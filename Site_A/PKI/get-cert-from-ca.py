#####################################################################
## Programme de récupération d'un certificat auprès du serveur PKI ##
##                          Site A                                 ##
#####################################################################

# Importation des modules
import socket
import ssl
from OpenSSL import crypto

# Création de la socket client
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Configuration du contexte SSL/TLS
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
# Ajout du certificat du central dans les trusted certs
context.load_verify_locations("/usr/share/ca-certificates/PKI/root_cert.crt")

# Connexion au serveur PKI d'adresse IP 192.168.1.100 et sur le port 32700
with context.wrap_socket(sock, server_hostname="192.168.1.100") as conn:
    conn.connect(("192.168.1.100", 32700))

    # Génération d'une paire de clés RSA (2048 bits)
    # Stockage de la clé privée dans la variable "key"
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # Récupération de la clé publique, et stockage dans la variable "pub_key"
    pub_key = crypto.dump_publickey(crypto.FILETYPE_PEM, key)
    
    # Enregistrement de la clé privée dans le fichier "/etc/ssl/private/site_a_key.crt"
    keyfile = "/etc/ssl/private/site_a_key.crt"
    with open(keyfile, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    # Envoi de la clé publique au serveur
    conn.sendall(pub_key)

    # Réception du certificat
    cert_site_a = b''
    while True:
        data = conn.recv(4096)
        if not data:
            break
        cert_site_a += data
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_site_a)
    
    # Enregistrement du certificat dans le dossier Cert/    
    with open("Cert/site_a.crt", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    # Confirmation que le certificat à bien été reçu
    print("Certificat bien reçu !")
