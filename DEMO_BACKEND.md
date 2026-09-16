# Guide de démonstration et d'intégration backend

Ce guide explique comment préparer une démonstration locale et appeler la
fonction PAdES-T depuis le backend.

## 1. Installer le projet

Depuis le dossier du projet :

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Python 3.10 ou plus récent est recommandé.

## 2. Générer les fichiers PEM de démonstration

Ces fichiers sont uniquement destinés au hackathon. Ils ne constituent pas
un certificat eIDAS qualifié.

```bash
openssl genrsa -out private_key.pem 2048

openssl req -new -x509 \
    -key private_key.pem \
    -out certificate.pem \
    -days 365 \
    -sha256 \
    -subj "/C=FR/O=Hackathon/CN=Demo Signer"
```

Vérifier que la clé et le certificat correspondent :

```bash
openssl x509 -noout -modulus -in certificate.pem | openssl sha256
openssl rsa -noout -modulus -in private_key.pem | openssl sha256
```

Les deux empreintes affichées doivent être identiques.

La clé privée ne doit jamais être envoyée au frontend, commitée dans Git ou
écrite dans les logs.

## 3. Configurer les chemins

En local, les fichiers peuvent rester dans le dossier du projet :

```bash
export PADES_KEY_PATH="$PWD/private_key.pem"
export PADES_CERTIFICATE_PATH="$PWD/certificate.pem"
```

En production, utiliser des chemins fournis par un gestionnaire de secrets.
Les variables doivent être définies avant `import sign`, car le code lit ces
chemins au chargement du module.

## 4. Appeler la fonction depuis le backend

Le backend fournit le PDF en mémoire et récupère le PDF signé en mémoire :

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

Paramètres :

- `pdf_bytes` : contenu du PDF à signer, de type `bytes` ;
- `first_name` et `last_name` : informations du signataire ;
- `eIDAS_auth` et `eIDAS_iden` : informations métier reçues du backend ;
- `company_name` : organisation éventuelle.

La fonction retourne `bytes`. Elle lève une exception si le PDF est invalide,
si la clé ou le certificat sont absents, si la signature échoue ou si aucune
TSA ne fournit de token RFC 3161.

Le backend doit considérer l'appel comme réussi uniquement si la fonction
retourne normalement. En cas d'exception, il ne doit pas envoyer ni stocker
de PDF comme signé.

Exemple de réponse HTTP côté backend :

```python
return Response(
    signed_pdf_bytes,
    content_type="application/pdf",
    headers={"Content-Disposition": "attachment; filename=signed.pdf"},
)
```

Le framework HTTP peut être différent ; l'important est de retourner les
bytes avec le type MIME `application/pdf`.

## 5. Tester avec un script local

Créer un PDF d'entrée, par exemple `document.pdf`, puis lancer :

```bash
python - <<'PY'
from pathlib import Path
from sign import sign_pdf

signed_pdf = sign_pdf(
    pdf_bytes=Path("document.pdf").read_bytes(),
    first_name="Jean",
    last_name="Dupont",
    eIDAS_auth=True,
    eIDAS_iden=True,
    company_name="Entreprise Exemple",
)
Path("document_signed.pdf").write_bytes(signed_pdf)
print("document_signed.pdf créé")
PY
```

Le fichier `document_signed.pdf` peut ensuite être ouvert dans un lecteur PDF.

## 6. Vérifier le timestamp RFC 3161

```bash
python - <<'PY'
from asn1crypto import cms
from pyhanko.pdf_utils.reader import PdfFileReader

with open("document_signed.pdf", "rb") as stream:
    reader = PdfFileReader(stream)
    signature = reader.embedded_signatures[-1]
    content_info = cms.ContentInfo.load(bytes(signature.pkcs7_content))
    attrs = content_info["content"]["signer_infos"][0]["unsigned_attrs"]
    print([attr["type"].native for attr in attrs])
PY
```

Le résultat doit contenir :

```text
signature_time_stamp_token
```

Cela confirme la présence du token dans le CMS. Cela ne valide pas à lui seul
la chaîne de confiance complète du certificat TSA.

## 7. Test CLI optionnel

La CLI accepte encore un chemin de PDF pour les essais locaux :

```bash
python sign.py document.pdf --output document_cli_signed.pdf
```

Le backend doit appeler `sign_pdf()` directement, et non lancer cette commande.

## 8. Fonctionnement TSA

Le programme essaie d'abord DigiCert, puis Sectigo si DigiCert échoue. Chaque
requête a un timeout de 5 secondes. Si les deux TSA échouent, aucun PDF signé
n'est retourné.

Le PDF n'est considéré comme réussi qu'après :

1. création de la signature cryptographique ;
2. obtention d'un token RFC 3161 ;
3. relecture du PDF ;
4. vérification de `signature_time_stamp_token`.

Les URLs TSA sont publiques et adaptées à une démonstration. Une mise en
production doit définir une politique de confiance TSA et une gestion
sécurisée des clés.

## Checklist avant envoi

- envoyer `sign.py`, `requirements.txt`, `README.md` et ce guide ;
- ne pas envoyer `private_key.pem` ni un certificat de démonstration ;
- configurer les deux variables d'environnement sur le serveur backend ;
- installer `pyHanko==0.37.0` avec `requirements.txt` ;
- appeler `sign_pdf()` directement avec `pdf_bytes` ;
- traiter toute exception comme un échec de signature ;
- tester avec un PDF non sensible et vérifier `signature_time_stamp_token`.
