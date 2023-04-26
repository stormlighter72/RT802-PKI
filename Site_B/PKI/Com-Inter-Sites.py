import socket
import ssl

# Configuration du socket
client_b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_b.bind(('0.0.0.0', 32700))
client_b.listen(5)

# Création d'un contexte SSL pour une communication sécurisée
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_cert_chain(certfile="/PKI/Cert/site_b.crt", keyfile="/etc/ssl/private/site_b_key.crt")
context.check_hostname = False

while True:
    # Attente de nouvelles connexions entrantes
    conn, addr = client_b.accept()

    # Création d'une socket SSL
    conn_ssl = context.wrap_socket(conn, server_side=True)

    # Réception du message du client A
    message = conn_ssl.recv(1024)

    # Envoi de la réponse au client A
    reponse = "Bonjour client A, je suis client B!".encode()
    conn_ssl.send(reponse)

    # Fermeture de la connexion SSL
    conn_ssl.close()

# Fermeture de la socket du client B
client_b.close()
