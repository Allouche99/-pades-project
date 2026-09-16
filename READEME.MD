# PAdES-T PDF Signing

Prototype for adding **PAdES-T electronic signatures** to PDF documents using [pyHanko](https://pyhanko.readthedocs.io/).

Developed as part of the **La Suite Numérique × 42 challenge**.

## 🎯 Objective

The goal of this project is to transform a standard PDF into a **PAdES-T signed PDF**.

PAdES-T combines:

* **PAdES** — PDF Advanced Electronic Signatures
* **Cryptographic signature**
* **RFC 3161 trusted timestamp**

The timestamp provides evidence that the signed data existed at a specific point in time.

---

## 🏗️ Architecture

```text
                 PDF
                  │
                  ▼
          ┌───────────────┐
          │    pyHanko    │
          └───────┬───────┘
                  │
                  ▼
        PAdES cryptographic
             signature
                  │
                  ▼
            SHA-256 hash
                  │
                  ▼
          RFC 3161 request
                  │
                  ▼
          ┌───────────────┐
          │      TSA      │
          │ Time Stamping │
          │   Authority   │
          └───────┬───────┘
                  │
                  ▼
         Timestamp Token
                  │
                  ▼
            PAdES-T PDF
```

---

## 🔐 What is PAdES-T?

**PAdES** is a standard for advanced electronic signatures embedded in PDF documents.

**PAdES-T** adds a trusted timestamp to the signature.

The resulting PDF contains:

```text
PDF
 └── PAdES signature
      ├── Cryptographic signature
      ├── Certificate
      └── RFC 3161 timestamp token
```

The timestamp token is embedded in the CMS signature as a `signature_time_stamp_token`.

---

## ⏱️ RFC 3161 Timestamping

The project uses RFC 3161-compatible **Time Stamping Authorities (TSA)**.

The current prototype uses:

1. DigiCert
2. Sectigo as fallback

```text
DigiCert TSA
     │
     ├── success ──► timestamp token
     │
     └── failure
            │
            ▼
      Sectigo TSA
            │
            ├── success ──► timestamp token
            │
            └── failure ──► error
```

This makes the timestamping step more resilient to temporary TSA failures.

---

## 🔄 TSA Fallback

A custom `FallbackTimeStamper` is implemented on top of pyHanko's `TimeStamper`.

```python
class FallbackTimeStamper(TimeStamper):
    def __init__(self, tsas):
        super().__init__()
        self.tsas = tsas

    async def async_timestamp(self, message_digest, md_algorithm):
        last_error = None

        for tsa in self.tsas:
            try:
                return await tsa.async_timestamp(
                    message_digest,
                    md_algorithm
                )
            except Exception as e:
                print(f"TSA failed: {tsa.url} -> {e}")
                last_error = e

        raise RuntimeError("All TSAs failed") from last_error
```

---

## 🧰 Technologies

| Technology                      | Role                                                  |
| ------------------------------- | ----------------------------------------------------- |
| Python                          | Implementation language                               |
| pyHanko                         | PDF signatures and PAdES                              |
| OpenSSL / cryptographic backend | Cryptographic operations through pyHanko dependencies |
| RFC 3161                        | Trusted timestamp protocol                            |
| DigiCert TSA                    | Primary timestamp authority                           |
| Sectigo TSA                     | Fallback timestamp authority                          |

---

## 📁 Project Structure

```text
pades-project/
│
├── sign.py
├── document_test.pdf
├── private_key.pem
├── certificate.pem
├── document_signed.pdf
└── READEME.MD
```

> `private_key.pem`, `certificate.pem` and generated signed documents are currently used for local testing only and should not be committed if they contain real credentials or sensitive material.

---

## 🚀 Installation

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Install pyHanko:

```bash
pip install pyHanko
```

---

## ▶️ Run the prototype

Make sure the key and certificate files are available:

```text
private_key.pem
certificate.pem
```

Then run:

```bash
python sign.py document_test.pdf
```

The resulting signed document will be:

```text
document_test_signed.pdf
```

The input PDF is passed as an argument and can already contain one or more
PAdES signatures. Each execution appends a new signature while preserving the
previous ones:

```bash
python sign.py document_test_signed.pdf
```

The output is created in the same directory as the input, with `_signed`
appended to a new document name. If the input already contains `signed`, the
same name is kept and `(1)`, `(2)`, etc. are added to avoid duplicate names.
An explicit output path can still be provided with `--output`.

Custom key and certificate paths can be supplied when needed:

```bash
python sign.py input.pdf --output output.pdf \
    --key path/to/private_key.pem \
    --certificate path/to/certificate.pem
```

The signature field name is generated automatically. Use `--field-name` only
when a specific field name is required.

### Output naming

When no output path is provided, the result is written next to the input PDF:

```text
document.pdf             -> document_signed.pdf
document_signed.pdf      -> document_signed (1).pdf
document_signed (1).pdf  -> document_signed (2).pdf
```

The automatic name avoids overwriting an existing file. To choose a specific
path, use `--output`.

---

## ✅ Verification

The generated PDF was verified by inspecting its embedded CMS signature.

The resulting signature contains:

```text
signature_time_stamp_token
```

This confirms that an RFC 3161 timestamp token is embedded in the signature.

Example verification:

```python
from asn1crypto import cms
from pyhanko.pdf_utils.reader import PdfFileReader

with open("document_test_signed.pdf", "rb") as file:
    pdf = PdfFileReader(file)
    signature = pdf.embedded_signatures[0]
    content_info = cms.ContentInfo.load(bytes(signature.pkcs7_content))
    signer_info = content_info["content"]["signer_infos"][0]
    print([
        (attribute["type"].native, len(attribute["values"]))
        for attribute in signer_info["unsigned_attrs"]
    ])
```

Expected output:

```text
[('signature_time_stamp_token', 1)]
```

---

## 🔌 Backend Integration

The current repository is a **working prototype**.

The backend can call the reusable `sign_pdf` function directly. The function
returns the path of the generated PDF and preserves existing signatures:

```python
from sign import sign_pdf

signed_path = sign_pdf(
    input_path="/tmp/document.pdf",
    key_path="/secrets/private_key.pem",
    certificate_path="/secrets/certificate.pem",
)
```

The private key must remain in a server-side secret manager or protected
volume. It must never be sent by the client in the PDF request.

The target integration with the backend is:

```text
Backend
   │
   │ PDF + cryptographic signature
   ▼
PAdES module
   │
   │ PAdES + RFC 3161 timestamp
   ▼
Signed PAdES-T PDF
   │
   ▼
Backend
   │
   ├── File storage
   └── Signature metadata in database
```

The exact input format of the cryptographic signature still needs to be defined with the backend team.

Possible formats include:

* raw signature bytes
* Base64-encoded signature
* CMS / PKCS#7 signature

The integration API will therefore be finalized once the backend signature format is defined.

---

## 🗄️ Suggested Signature Metadata

The backend can store metadata such as:

```text
document_id
signature_id
signature_format = PAdES-T
hash_algorithm = SHA-256
tsa_url
timestamp_time
signer_certificate
signature_status
created_at
```

The signed PDF itself should remain the primary signed artifact.

---

## ⚠️ Current Status

### Implemented

* [x] PDF signing with pyHanko
* [x] PAdES signature
* [x] SHA-256 based signing workflow
* [x] RFC 3161 timestamping
* [x] TSA integration
* [x] Multiple TSA fallback
* [x] Verification of embedded timestamp token
* [x] Generation of a PAdES-T PDF

### To integrate

* [ ] Define backend signature format
* [ ] Replace local test key/certificate with the project's signing mechanism
* [ ] Connect the module to the backend API
* [ ] Define database metadata model
* [ ] Add automated tests
* [ ] Add production-grade TSA configuration and monitoring

---

## 📚 Standards & Concepts

* **PAdES** — Advanced electronic signatures for PDF
* **CMS / CAdES** — Cryptographic container used by the PDF signature
* **RFC 3161** — Internet X.509 Public Key Infrastructure Time-Stamp Protocol
* **TSA** — Time Stamping Authority
* **SHA-256** — Cryptographic hash algorithm

---

## 👥 Context

This project was developed during the **La Suite Numérique × 42 hackathon** as a prototype for adding trusted timestamping to PDF electronic signatures.

