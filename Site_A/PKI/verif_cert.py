from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Charger le certificat reçu dans la variable "data" et créer un objet "x509.Certificate"
data = "certif.crt"
cert = x509.load_pem_x509_certificate(data, default_backend())

# Vérifier la date d'expiration du certificat
if cert.not_valid_after < datetime.datetime.utcnow():
    raise ValueError("Le certificat a expiré.")

# Vérifier la chaîne de confiance
store_ctx = x509.StoreContext(store, cert)
try:
    store_ctx.verify_certificate()
except Exception as e:
    raise ValueError("La chaîne de confiance du certificat n'est pas valide.") from e

# Vérifier que le nom de domaine correspond
if cert.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value != "192.168.1.100":
    raise ValueError("Le nom de domaine dans le certificat ne correspond pas.")

# Vérifier la signature du certificat en utilisant la clé publique de l'AC émettrice
issuer_pubkey = cert.issuer.public_key()
try:
    issuer_pubkey.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )
except Exception as e:
    raise ValueError("La signature du certificat n'est pas valide.") from e
