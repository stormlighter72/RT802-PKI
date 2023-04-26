import socket
import ssl

# Configuration du socket
serveur_pki = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serveur_pki.bind(('0.0.0.0', 32700))
serveur_pki.listen(5)

while True:
    # Attente de nouvelles connexions entrantes
    conn, addr = serveur_pki.accept()

    # Création d'un contexte SSL pour une communication sécurisée
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="root_cert.crt", keyfile="/etc/ssl/private/root_key.crt")

    # Création d'une socket SSL
    conn_ssl = context.wrap_socket(conn, server_side=True)

    # Attente de la demande de certificat du client
    demande = conn_ssl.recv(1024)

    # Génération du certificat pour le client
    certificat_client = "ceci est le certificat pour le client {}".format(addr[0])

    # Envoi du certificat au client
    conn_ssl.send(certificat_client.encode())

    # Fermeture de la connexion SSL
    conn_ssl.close()

# Fermeture de la socket du serveur
serveur_pki.close()
