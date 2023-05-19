#####################################################################
##              Programme de communication inter-site              ##
##                             Site B                              ##
#####################################################################

# Importation des modules
import ssl
import socket
import threading

# Définition de l'adresse IP et du port d'écoute du site B
site_b_host = '192.168.1.102'
site_b_port = 32700

# Chemin vers le certificat du site central
certfile_central = '/usr/share/ca-certificates/PKI/root_cert.crt'
# Chemin vers le certificat du site B
certfile_site_b = '/PKI/Cert/site_b.crt'
# Chemin vers la clef privée du site B
keyfile_site_b = '/etc/ssl/private/site_b_key.crt'

# Création d'un contexte SSL pour le site B
context_site_b = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context_site_b.check_hostname = False
context_site_b.verify_mode = ssl.CERT_NONE

# Fonction pour la réception des messages
def receive_messages():
    while True:
        context_site_b = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context_site_b.load_cert_chain(certfile=certfile_site_b, keyfile=keyfile_site_b)
        response_conn, _ = response_server.accept()
        message = response_conn.recv(4096)
        print('Message (site B) :', message.decode(errors='ignore'))
        response_conn.close()

# Écoute des connexions entrantes
response_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
response_server.bind((site_b_host, site_b_port))
response_server.listen(1)

print('Serveur B en attente de connexions...')

# Démarrage du serveur en arrière-plan pour recevoir les messages
receive_thread = threading.Thread(target=receive_messages)
receive_thread.start()

# Attente de l'appui sur la touche "Entrée"
input('Appuyez sur Entrée pour continuer...')

# Demande de la destination et du message
destination = input('Site Destination (A ou B) : ').encode()
message = input('Message à envoyer : ').encode()

# Connexion au site central
with socket.create_connection(('192.168.1.100', 32700)) as sock:
    # Ajout du certificat du serveur central dans les trusted certs
    context_site_b.load_verify_locations(certfile_central)

    with context_site_b.wrap_socket(sock, server_hostname='192.168.1.100') as ssock:
        # Envoi du site de destination
        ssock.sendall(destination)

        # Envoi du message 
        ssock.sendall(message)

        # Réception des données
        response = ssock.recv(4096)

        # Traitement des données reçues
        print('Réponse du site central (site B) :', response.decode())
