
import argparse
import re
from pathlib import Path
from typing import BinaryIO

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.sign.signers import PdfSignatureMetadata, SimpleSigner
from pyhanko.sign.timestamps import HTTPTimeStamper, TimeStamper

DEFAULT_KEY_FILE = Path("private_key.pem")
DEFAULT_CERTIFICATE_FILE = Path("certificate.pem")
TSA_URLS = (
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com/rfc3161",
)
NUMBERED_NAME_PATTERN = re.compile(r"^(.*?)(?: \(\d+\))?$")


class FallbackTimeStamper(TimeStamper):
    def __init__(self, tsas: tuple[HTTPTimeStamper, ...]):
        super().__init__()
        self.tsas = tsas

    async def async_timestamp(self, message_digest, md_algorithm):
        last_error = None

        for tsa in self.tsas:
            try:
                print(f"Essai TSA : {tsa.url}")

                token = await tsa.async_timestamp(
                    message_digest,
                    md_algorithm
                )

                print(f"TSA OK : {tsa.url}")
                return token

            except Exception as e:
                print(f"TSA échouée : {tsa.url} -> {e}")
                last_error = e

        raise RuntimeError("Toutes les TSA ont échoué") from last_error


def build_timestamper() -> FallbackTimeStamper:
    """Create the TSA fallback chain used for PAdES-T signatures."""
    return FallbackTimeStamper(tuple(HTTPTimeStamper(url) for url in TSA_URLS))


def next_field_name(input_file: BinaryIO) -> str:
    """Return a signature field name that does not collide with existing ones."""
    reader = PdfFileReader(input_file)
    existing_count = len(reader.embedded_signatures)
    return f"Signature{existing_count + 1}"


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


def sign_pdf(
    input_path: str | Path,
    key_path: str | Path,
    certificate_path: str | Path,
    output_path: str | Path | None = None,
    field_name: str | None = None,
) -> Path:
    """Append one PAdES-T signature to a PDF, preserving previous signatures."""
    input_path = Path(input_path)
    output_path = (
        default_output_path(input_path)
        if output_path is None
        else Path(output_path)
    )

    if input_path.resolve() == output_path.resolve():
        raise ValueError("Le fichier de sortie doit être différent du fichier d'entrée")

    signer = SimpleSigner.load(
        key_file=str(key_path),
        cert_file=str(certificate_path),
        key_passphrase=None,
    )

    with input_path.open("rb") as input_file:
        if field_name is None:
            field_name = next_field_name(input_file)
            input_file.seek(0)

        writer = IncrementalPdfFileWriter(input_file)
        metadata = PdfSignatureMetadata(
            field_name=field_name,
            subfilter=SigSeedSubFilter.PADES,
        )

        with output_path.open("wb") as output_file:
            signers.sign_pdf(
                writer,
                signature_meta=metadata,
                signer=signer,
                timestamper=build_timestamper(),
                output=output_file,
            )

    return output_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ajoute une signature électronique PAdES-T à un PDF."
    )
    parser.add_argument("input", type=Path, help="PDF original ou déjà signé")
    parser.add_argument(
        "--output",
        type=Path,
        help="PDF de sortie (par défaut : <entrée>_signed.pdf)",
    )
    parser.add_argument(
        "--key",
        type=Path,
        default=DEFAULT_KEY_FILE,
        help="Fichier de clé privée (défaut : private_key.pem)",
    )
    parser.add_argument(
        "--certificate",
        type=Path,
        default=DEFAULT_CERTIFICATE_FILE,
        help="Certificat du signataire (défaut : certificate.pem)",
    )
    parser.add_argument(
        "--field-name",
        help="Nom du champ de signature (généré automatiquement par défaut)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    signed_path = sign_pdf(
        input_path=args.input,
        key_path=args.key,
        certificate_path=args.certificate,
        output_path=args.output,
        field_name=args.field_name,
    )
    print(f"PDF signé avec succès : {signed_path}")


if __name__ == "__main__":
    main()

