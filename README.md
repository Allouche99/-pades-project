# Signature PAdES-T avec pyHanko

Prototype de signature PAdES-T pour PDF avec Python et pyHanko 0.37.0.
La signature est acceptée uniquement si le CMS contient un token RFC 3161
dans l'attribut `signature_time_stamp_token`.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Utilisation backend

Le backend configure les chemins de la clé et du certificat :

```bash
export PADES_KEY_PATH=/chemin/securise/private_key.pem
export PADES_CERTIFICATE_PATH=/chemin/securise/certificate.pem
```

Puis il appelle directement :

```python
from sign import sign_pdf

signed_pdf_bytes = sign_pdf(
    pdf_bytes=pdf_bytes,
    first_name=first_name,
    last_name=last_name,
    eIDAS_auth=eIDAS_auth,
    eIDAS_iden=eIDAS_iden,
    company_name=company_name,
)
```

La fonction retourne le PDF signé en `bytes`. Les fichiers PEM restent côté
serveur et ne doivent jamais être envoyés au frontend, commités ou enregistrés
dans les logs.

## Utilisation CLI

Pour un essai local :

```bash
python sign.py document.pdf --output document_signed.pdf
```

La CLI essaie DigiCert puis Sectigo, avec un timeout de 5 secondes. Elle
refuse de produire une signature sans timestamp RFC 3161 et conserve les
signatures précédentes grâce à `IncrementalPdfFileWriter`.

## Documentation de démo

Voir [DEMO_BACKEND.md](DEMO_BACKEND.md) pour :

- générer `private_key.pem` et `certificate.pem` avec OpenSSL ;
- vérifier qu'ils correspondent ;
- configurer les variables d'environnement ;
- alimenter `sign_pdf()` depuis le backend ;
- vérifier `signature_time_stamp_token`.

## Limites

La présence de `signature_time_stamp_token` confirme que le token RFC 3161 est
embarqué dans le CMS. Elle ne prouve pas seule la validation cryptographique
complète du token ni la confiance dans la chaîne du certificat TSA. Les
certificats auto-signés de démonstration ne sont pas des certificats eIDAS
qualifiés.
