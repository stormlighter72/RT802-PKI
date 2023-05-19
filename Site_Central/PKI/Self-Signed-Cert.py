############################################################################
## Programme de génération d'un certificat auto-signé pour le serveur PKI ##
##                           Site Central                                 ##
############################################################################

# Importation des modules
from OpenSSL import crypto

# Génération d'un certificat racine auto-signé
def generate_root_cert(ip_address):
    # Création d'une varible "k" pour stocker la clé privée
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # Configuration du certificat
    # Norme X509
    cert = crypto.X509()
    # Ajout des Informations dans la partie 'Sujet' du certificat
    cert.get_subject().C = "FR"
    cert.get_subject().ST = "Ile de France"
    cert.get_subject().L = "Paris"
    cert.get_subject().O = "PKI"
    cert.get_subject().OU = "PKI"
    cert.get_subject().CN = "Root CA"
    cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60) # adapté YYYYMMDDhhmmssZ
    # Ajout des Informations (les mêmes que dans 'Sujet') dans la partie 'Sujet' du certificat
    cert.set_issuer(cert.get_subject())
    #Ajout de la clef public généré plus tôt
    cert.set_pubkey(k)
    
    # Ajout de l'adresse IP comme SubjectAltName
    cert.add_extensions([crypto.X509Extension(b"subjectAltName", False, f"IP:{ip_address}".encode())])
    
    # Configuration de l'extension pour que notre certificat soit reconnu comme celui d'un Root CA
    cert.add_extensions([crypto.X509Extension(b"basicConstraints", True, f"CA:TRUE".encode())])
    
    # On signe le certificat avec le clef privée généré plus haut
    cert.sign(k, "sha256")

    # Exportation du certificat et de la clé privée dans les fichiers "root_cert.crt" et "root_key.crt"
    certfile = "root_cert.crt"
    keyfile = "/etc/ssl/private/root_key.crt"

    with open(certfile, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(keyfile, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

    print("Certificat autosigné généré avec succès!")

# Appel de la fonction pour générer le certificat autosigné
generate_root_cert("192.168.1.100")
