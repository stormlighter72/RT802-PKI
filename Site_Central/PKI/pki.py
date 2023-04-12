# Serveur central (PKI)
# Mise en place d'un serveur PKI permettant de générer un certificat racine auto-signé, puis fournir des certificats signés pour chaque nœuds client qui le demande. 
# Il utilise des sockets pour communiquer avec les clients, et des threads pour gérer les connexions simultanées.

# Importation des modules
import socket
import ssl
import threading
from OpenSSL import crypto
import os

class PKIServer: 
    # Définition du serveur PKI
    def __init__(self, host, port): # Initialise les attributs de la classe
        self.host = host # Attribut "host" : Stockage de l'@IP du serveur
        self.port = port # Attribut "port" : Stockage du port du serveur

    # Mise en place de la socket du serveur et acceptation des connexions entrantes. 
    # Création d'une socket / liaison à l'@IP et au port / passage en mode "écoute" pour les connexions entrantes / affichage des informations. 
    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen()

        print(f"PKI server is running on {self.host}:{self.port}")

    # A l'arrivée d'une connexion, elle est enveloppée dans un objet SSL (Secure Sockets Layer) : wrap_socket avec server_side=True
    # puis génération des certificats et clé racine en utilisant _generate_root_cert.
        while True:
            client_socket, client_address = server_socket.accept()
            client_socket = ssl.wrap_socket(client_socket, server_side=True, certfile=self.root_cert, keyfile=self.root_key, ssl_version=ssl.PROTOCOL_TLS)

            threading.Thread(target=self.handle_client, args=(client_socket,)).start() # boucle infinie pour écouter les connexions entrantes

    # Gestion des requêtes client : Lorsqu'une requête est reçue, elle est décryptée et son contenu est stocké dans la variable "request". 
    # Si la requête est de type "get_root_cert" : le certificat racine est renvoyé au client. Enfin, fermeture de la socket (déconnexion).
    def handle_client(self, client_socket):
        request = client_socket.recv(1024).decode()
        if request == "get_root_cert":
            client_socket.send(self.root_cert.encode())
        client_socket.close()
        
# Execution du programme : Instancie un objet "PKIServer" écoutant sur l'adresse IP "0.0.0.0" avec le port 8000, puis lancement du serveur.
if __name__ == "__main__":
#if __name__ == "__init__":
    server = PKIServer("0.0.0.0", 32700)
    server.start()
