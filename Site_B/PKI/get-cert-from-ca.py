import socket
import ssl
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Définition des paramètres de connexion
SERVER_ADDRESS = "192.168.1.100"
SERVER_PORT = 32700

# Génération de la paire de clés RSA et extraction de la clé publique
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub_key = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)

# Connexion au serveur PKI
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

with socket.create_connection((SERVER_ADDRESS, SERVER_PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=SERVER_ADDRESS) as ssock:
        # Envoi de la clé publique au serveur
        ssock.sendall(pub_key)
        # Réception du certificat du serveur
        data = ssock.recv(1024)
        with open("Cert/site_b.crt", "wb") as cert_file:
            cert_file.write(data)
        #print(data.decode())
