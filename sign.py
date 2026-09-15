
import asyncio

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.sign.signers import PdfSignatureMetadata, SimpleSigner
from pyhanko.sign.timestamps import HTTPTimeStamper, TimeStamper


class FallbackTimeStamper(TimeStamper):
    def __init__(self, tsas):
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


# Certificat + clé privée
signer = SimpleSigner.load(
    key_file="private_key.pem",
    cert_file="certificate.pem",
    key_passphrase=None,
)


# TSA 1
tsa1 = HTTPTimeStamper(
    "http://timestamp.digicert.com"
)

# TSA 2
tsa2 = HTTPTimeStamper(
    "http://timestamp.sectigo.com/rfc3161"
)

# TSA avec fallback
tsa = FallbackTimeStamper([
    tsa1,
    tsa2,
])


# PDF à signer
with open("document_test.pdf", "rb") as input_file:
    writer = IncrementalPdfFileWriter(input_file)

    metadata = PdfSignatureMetadata(
        field_name="Signature1",
        subfilter=SigSeedSubFilter.PADES,
    )

    # Signature PAdES-T
    with open("document_signed.pdf", "wb") as output_file:
        signers.sign_pdf(
            writer,
            signature_meta=metadata,
            signer=signer,
            timestamper=tsa,
            output=output_file,
        )


print("PDF signé avec succès")

