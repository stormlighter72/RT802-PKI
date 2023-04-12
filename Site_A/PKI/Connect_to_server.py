# Importation des modules nécessaires
import socket
import ssl
from OpenSSL import crypto

# Génération d'une paire de clés RSA
key = crypto.PKey()
key.generate_key(crypto.TYPE_RSA, 2048)
# Sérialisation de la clé publique RSA
pub_key = key.publickey().export_key()

# Chargement du certificat du serveur
# certfile = "/usr/share/ca-certificates/PKI/root_cert.crt"

# Création du socket client et connexion au serveur
# sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
# context.load_verify_locations(cafile=certfile)
# conn = context.wrap_socket(sock, server_hostname="192.168.1.100")
# conn.connect(("192.168.1.100", 32700))

# Envoi de la clé publique au site central
certfile = "/usr/share/ca-certificates/PKI/root_cert.crt"
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_verify_locations(certfile)
with socket.create_connection(("192.168.1.100", 32700)) as sock:
    with context.wrap_socket(sock, server_hostname="site-central") as ssock:
        ssock.sendall(pub_key)

        # Réception du certificat
        cert_data = ssock.recv(1024)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
        print("Certificate received:\n{}".format(crypto.dump_certificate(crypto.FILETYPE_TEXT, cert).decode()))


# Envoi de la requête au serveur
# request = b"Hello, world!"
# conn.sendall(request)

# Réception de la réponse du serveur
# response = conn.recv(1024)
# print(response)

# Fermeture de la connexion
# conn.shutdown(socket.SHUT_RDWR)
# conn.close()
