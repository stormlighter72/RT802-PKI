import socket
import ssl
from OpenSSL import crypto

# Création de la socket client
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Configuration du contexte SSL/TLS
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

# Connexion au serveur
with context.wrap_socket(sock, server_hostname="192.168.1.100") as conn:
    conn.connect(("192.168.1.100", 32700))

    # Génération de la paire de clés
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # Envoi de la clé publique au serveur
    pubkey_pem = crypto.dump_publickey(crypto.FILETYPE_PEM, key)
    conn.sendall(pubkey_pem)

    # Réception du certificat
    cert_pem = b''
    while True:
        data = conn.recv(4096)
        if not data:
            break
        cert_pem += data
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

    # Vérification du certificat
    store = crypto.X509Store()
    store.add_cert(cert)
    store_ctx = crypto.X509StoreContext(store, cert)
    store_ctx.verify_certificate()

    # Affichage du certificat
    print(crypto.dump_certificate(crypto.FILETYPE_TEXT, cert).decode())
