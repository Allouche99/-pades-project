

import subprocess
import argparse
import os
import re
import sys
import tempfile
from io import BytesIO
from pathlib import Path
from typing import BinaryIO
from pathlib import Path
from asn1crypto import cms
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.sign.signers import PdfSignatureMetadata, SimpleSigner
from pyhanko.sign.timestamps import HTTPTimeStamper, TimeStamper

DEFAULT_KEY_FILE = Path(
    os.environ.get("PADES_KEY_PATH", "private_key.pem")
)
DEFAULT_CERTIFICATE_FILE = Path(
    os.environ.get("PADES_CERTIFICATE_PATH", "certificate.pem")
)
TSA_URLS = (
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com/rfc3161",
)
TSA_TIMEOUT = 5
NUMBERED_NAME_PATTERN = re.compile(r"^(.*?)(?: \(\d+\))?$")


class SigningError(RuntimeError):
    """Base class for expected signing failures."""


class InputFileError(SigningError):
    pass


class OutputFileError(SigningError):
    pass


class TimestampError(SigningError):
    pass


class FallbackTimeStamper(TimeStamper):
    def __init__(self, tsas: tuple[HTTPTimeStamper, ...]):
        super().__init__()
        if not tsas:
            raise TimestampError("No TSA is configured")
        self.tsas = tsas

    async def async_timestamp(self, message_digest, md_algorithm):
        last_error = None

        for tsa in self.tsas:
            try:
                token = await tsa.async_timestamp(
                    message_digest,
                    md_algorithm
                )
                return token

            except Exception as error:
                last_error = error

        raise TimestampError("All TSAs failed") from last_error


def build_timestamper() -> FallbackTimeStamper:
    """Create the TSA fallback chain used for PAdES-T signatures."""
    return FallbackTimeStamper(
        tuple(HTTPTimeStamper(url, timeout=TSA_TIMEOUT) for url in TSA_URLS)
    )


def _all_field_names(reader: PdfFileReader) -> set[str]:
    """Collect field names, including non-signature AcroForm fields."""
    names = set()
    acro_form = reader.root.get('/AcroForm')
    if acro_form is None:
        return names
    if hasattr(acro_form, 'get_object'):
        acro_form = acro_form.get_object()

    def visit(field):
        field = field.get_object() if hasattr(field, 'get_object') else field
        field_name = field.get('/T')
        if field_name is not None:
            names.add(str(field_name))
        for child in field.get('/Kids', []):
            visit(child)

    for field in acro_form.get('/Fields', []):
        visit(field)
    return names


def next_field_name(input_file: BinaryIO) -> str:
    """Return a signature field name that does not collide with existing ones."""
    reader = PdfFileReader(input_file)
    existing_names = _all_field_names(reader)
    index = 1
    while f"Signature{index}" in existing_names:
        index += 1
    return f"Signature{index}"


def default_output_path(input_path: str | Path) -> Path:
    """Build a non-conflicting output path beside the input PDF."""
    input_path = Path(input_path)
    base_name = NUMBERED_NAME_PATTERN.match(input_path.stem).group(1)

    if "signed" not in base_name.casefold():
        base_name = f"{base_name}_signed"
        number = 0
    else:
        number = 1

    while True:
        suffix = "" if number == 0 else f" ({number})"
        candidate = input_path.with_name(f"{base_name}{suffix}{input_path.suffix}")
        if not candidate.exists():
            return candidate
        number += 1


def _sign_pdf_bytes(
    pdf_bytes: bytes,
    first_name: str,
    last_name: str,
    eIDAS_auth: bool = False,
    eIDAS_iden: bool = False,
    company_name: str = "",
    field_name: str | None = None,
    key_path: Path = DEFAULT_KEY_FILE,
    certificate_path: Path = DEFAULT_CERTIFICATE_FILE,
) -> bytes:
    """Create and validate one PAdES-T signature in memory."""
    if not isinstance(pdf_bytes, bytes) or not pdf_bytes:
        raise InputFileError("The backend must provide non-empty PDF bytes")
    if not key_path.is_file():
        raise InputFileError(f"Private key not found: {key_path}")
    if not certificate_path.is_file():
        raise InputFileError(f"Certificate not found: {certificate_path}")

    del eIDAS_auth, eIDAS_iden, company_name
    try:
        input_stream = BytesIO(pdf_bytes)
        reader = PdfFileReader(input_stream)
        existing_field_names = _all_field_names(reader)
        if field_name is None:
            field_name = next_field_name(input_stream)
        elif field_name in existing_field_names:
            raise OutputFileError(
                f"Signature field already exists: {field_name}"
            )
        input_stream.seek(0)
    except SigningError:
        raise
    except Exception as error:
        raise InputFileError("Invalid or unreadable PDF") from error

    try:
        signer = SimpleSigner.load(
            key_file=str(key_path),
            cert_file=str(certificate_path),
            key_passphrase=None,
        )
    except Exception as error:
        raise SigningError(
            "Invalid or incompatible private key and certificate"
        ) from error

    metadata = PdfSignatureMetadata(
        field_name=field_name,
        md_algorithm="sha256",
        subfilter=SigSeedSubFilter.PADES,
        name=f"{first_name} {last_name}".strip(),
    )
    output_stream = BytesIO()
    try:
        writer = IncrementalPdfFileWriter(input_stream)
        signers.sign_pdf(
            writer,
            signature_meta=metadata,
            signer=signer,
            timestamper=build_timestamper(),
            output=output_stream,
        )

        signed_bytes = output_stream.getvalue()
        with BytesIO(signed_bytes) as signed_stream:
            signed_reader = PdfFileReader(signed_stream)
            signatures = signed_reader.embedded_signatures
            if not signatures:
                raise SigningError("The signature was not created")
            cms_content = cms.ContentInfo.load(
                bytes(signatures[-1].pkcs7_content)
            )
            signer_info = cms_content["content"]["signer_infos"][0]
            has_timestamp = any(
                attribute["type"].native == "signature_time_stamp_token"
                for attribute in signer_info["unsigned_attrs"]
            )
            if not has_timestamp:
                raise TimestampError(
                    "The CMS does not contain a signature_time_stamp_token"
                )
        return signed_bytes
    except TimestampError:
        raise
    except Exception as error:
        raise SigningError("PAdES-T signing failed") from error


def sign_pdf(
    pdf_bytes: bytes,
    first_name: str,
    last_name: str,
    eIDAS_auth: bool = False,
    eIDAS_iden: bool = False,
    company_name: str = "",
) -> bytes:
    """Sign backend-provided PDF bytes and return validated PDF bytes."""
    return _sign_pdf_bytes(
        pdf_bytes,
        first_name,
        last_name,
        eIDAS_auth,
        eIDAS_iden,
        company_name,
    )


def _sign_pdf_file(
    input_path: Path,
    output_path: Path,
    key_path: Path,
    certificate_path: Path,
    field_name: str | None = None,
) -> Path:
    """Adapt the file-based CLI to the bytes-based signing API."""
    if not input_path.is_file():
        raise InputFileError(f"PDF file not found: {input_path}")
    if input_path.resolve() == output_path.resolve():
        raise OutputFileError(
            "The output file must be different from the input file"
        )
    if output_path.parent != Path('.') and not output_path.parent.is_dir():
        raise OutputFileError(f"Output directory does not exist: {output_path.parent}")
    if output_path.exists():
        raise OutputFileError(f"Output file already exists: {output_path}")

    signed_bytes = _sign_pdf_bytes(
        input_path.read_bytes(),
        "",
        "",
        field_name=field_name,
        key_path=key_path,
        certificate_path=certificate_path,
    )
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".tmp",
            prefix=f".{output_path.name}.",
            dir=output_path.parent,
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(signed_bytes)
            temporary_file.flush()
        try:
            os.link(temporary_path, output_path)
        except FileExistsError as error:
            raise OutputFileError(
                f"Output file already exists: {output_path}"
            ) from error
        temporary_path.unlink()
        return output_path
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Adds a PAdES-T electronic signature to a PDF."
    )
    parser.add_argument("input", type=Path, help="Original or already-signed PDF")
    parser.add_argument(
        "--output",
        type=Path,
        help="Output PDF (default: <input>_signed.pdf)",
    )
    parser.add_argument(
        "--key",
        type=Path,
        default=DEFAULT_KEY_FILE,
        help="Private key file (default: private_key.pem)",
    )
    parser.add_argument(
        "--certificate",
        type=Path,
        default=DEFAULT_CERTIFICATE_FILE,
        help="Signer's certificate (default: certificate.pem)",
    )
    parser.add_argument(
        "--field-name",
        help="Signature field name (auto-generated by default)",
    )
    return parser.parse_args()

import subprocess
from pathlib import Path


def generate_certificate(
    organization: str,
    common_name: str = "Demo Signer",
    days: int = 365,
) -> None:
    key_path = Path("private_key.pem")
    certificate_path = Path("certificate.pem")

    # 1. Générer la clé privée RSA 2048 bits
    subprocess.run(
        [
            "openssl",
            "genrsa",
            "-out",
            str(key_path),
            "2048",
        ],
        check=True,
    )

    # 2. Générer le certificat auto-signé
    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-key",
            str(key_path),
            "-out",
            str(certificate_path),
            "-days",
            str(days),
            "-sha256",
            "-subj",
            f"/C=FR/O={organization}/CN={common_name}",
        ],
        check=True,
    )
def main() -> int:
    args = parse_args()
    try:
        signed_path = _sign_pdf_file(
            input_path=args.input,
            output_path=(
                default_output_path(args.input)
                if args.output is None
                else args.output
            ),
            key_path=args.key,
            certificate_path=args.certificate,
            field_name=args.field_name,
        )
    except SigningError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    print(f"PDF successfully signed: {signed_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())