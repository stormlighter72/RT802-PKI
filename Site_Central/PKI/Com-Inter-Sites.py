import ssl
import socket

# Adresse et port d'écoute du site central
central_host = '192.168.1.100'
central_port = 32700

# Chemin du certificat du site central
certfile = "/PKI/root_cert.crt"
# Chemin de la clé privée correspondante au certificat
keyfile = "/etc/ssl/private/root_key.crt"

# Chemin du certificat du site A
certfile_site_a = '/usr/share/ca-certificates/Cert-Sites/site_a.crt'
# Chemin du certificat du site B
certfile_site_b = '/usr/share/ca-certificates/Cert-Sites/site_b.crt'

# Création d'un contexte SSL pour le serveur central
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

# Configuration pour vérifier le certificat des clients
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
context.load_verify_locations(certfile)
context.load_verify_locations(certfile_site_a)
context.load_verify_locations(certfile_site_b)

# Chargement du certificat et de la clé privée du serveur central
context.load_cert_chain(certfile=certfile, keyfile=keyfile)

# Création du socket d'écoute
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((central_host, central_port))
server.listen(1)
server_ssl_context = context.wrap_socket(server, server_side=True)
print("Serveur Actif !")

while True:
    # Attente d'une connexion
    conn, addr = server_ssl_context.accept()
    try:
        # Réception du site de destination
        destination = conn.recv(1024).decode()

        # Réception du contenu du message
        message = conn.recv(4096)

        # Traitement des données reçues
        # print('Message à destination du site', destination, ':', message.decode())

        # Vérification de la destination et envoi du message
        if destination == 'A':
            print('Message à destination du site A :', message.decode())
            # Création d'un contexte SSL pour le site A
            context_site_a = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context_site_a.verify_mode = ssl.CERT_REQUIRED
            context_site_a.load_verify_locations(certfile_site_a)

            # Connexion au site A
            with socket.create_connection(('192.168.1.101', 32700)) as dest_sock:
                with context_site_a.wrap_socket(dest_sock, server_hostname='192.168.1.101') as ssock:
                    # Envoi du message chiffré au site A
                    ssock.sendall(message.encode())

                    # Réception de la réponse du site A
                    response = ssock.recv(4096)

                    # Envoi de la réponse chiffrée au client
                    conn.sendall(response)

        elif destination == 'B':
            print('Message à destination du site B :', message.decode())
            # Création d'un contexte SSL pour le site B
            context_site_b = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context_site_a.verify_mode = ssl.CERT_REQUIRED
            context_site_b.load_verify_locations(certfile_site_b)

            # Connexion au site B
            with socket.create_connection(('192.168.1.102', 32700)) as dest_sock:
                with context_site_b.wrap_socket(dest_sock, server_hostname='192.168.1.102') as ssock:
                    # Envoi du message chiffré au site B
                    ssock.sendall(message)

                    # Réception de la réponse du site B
                    response = ssock.recv(4096)

                    # Envoi de la réponse chiffrée au client
                    conn.sendall(response)

        else:
            print('Destination inconnue :', destination)

    finally:
        # Fermeture de la connexion
        conn.close()
