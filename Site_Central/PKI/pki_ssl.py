# v1 du 23/03/2023
import socket
import ssl
import pickle
import os

# Générer une paire de clés privée/publique
#key = ssl.create_default_keypair()
key = ssl.create_default_context(ssl.Purpose.SERVER_AUTH).generate_keypair()

# Charger le certificat racine autosigné
if os.path.exists('root_cert.pem'):
    with open('root_cert.pem', 'rb') as f:
        cert_data = f.read()
    root_cert = ssl.PEM_cert_to_X509_cert(cert_data)
else:
    # Créer un certificat autosigné à partir de la clé publique
    root_cert = ssl.DER_cert_to_PEM_cert(key[1]).encode()
    with open('root_cert.pem', 'wb') as f:
        f.write(root_cert)

# Créer un socket TCP/IP
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Associer le socket à un port
server_address = ('localhost', 10000)
server_socket.bind(server_address)

# Écouter les connexions entrantes
server_socket.listen(1)

# Accepter les connexions entrantes et traiter les demandes
while True:
    # Accepter une connexion
    client_socket, client_address = server_socket.accept()

    # Créer un contexte SSL
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile='root_cert.pem', keyfile=key[0])

    # Wrapper la socket client avec SSL
    ssl_socket = ssl_context.wrap_socket(client_socket, server_side=True)

    # Récupérer la demande du client
    request_data = ssl_socket.recv(1024)

    # Traiter la demande
    request = pickle.loads(request_data)
    if request['action'] == 'get_signed_cert':
        # Générer un certificat signé pour le client
        signed_cert = ssl.DER_cert_to_PEM_cert(key[1]).encode()
        response = {'result': 'success', 'signed_cert': signed_cert}
    else:
        response = {'result': 'error', 'message': 'Invalid request'}

    # Envoyer la réponse au client
    response_data = pickle.dumps(response)
    ssl_socket.sendall(response_data)

    # Fermer la connexion SSL
    ssl_socket.shutdown(socket.SHUT_RDWR)
    ssl_socket.close()
