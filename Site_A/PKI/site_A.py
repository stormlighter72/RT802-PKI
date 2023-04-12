# Noeud A (Client)
# Mise en place d'un noeud "client" permettant de générer une paire de clé / échanger des certificats (envoi et reception du serveur PKI) 
# / chiffrement et déchiffrement de messages (via l'utilisation d'une clé symétrique partagée).

# Importation des modules
import socket
import ssl
import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization

# Définition de la classe avec 3 paramètres : nom du noeud, adresse IP et port du serveur PKI.
class Node:
    def __init__(self, name, pki_host, pki_port):
        self.name = name
        self.pki_host = pki_host
        self.pki_port = pki_port
        self.private_key = None
        self.public_key = None
        self.certificate = None
        self.shared_key = None
    
    def generate_key_pair(self): # Génération d'une paire de clés privée/publique (RSA 2048)
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    # Envoi de la clé publique au serveur PKI pour obtenir un certificat signé
    # utilisation d'un socket pour la connexion au serveur PKI et l'envoi de la clé publique.
    # La clé publique est au format PEM (Privacy Enhanced Mail) et est envoyée sous forme de chaîne de caractères. 
    # Le serveur PKI (après avoir vérifié la clé publique) renvoi un certificat signé.
    def send_public_key_to_pki(self):
        context = ssl.create_default_context()

        with socket.create_connection((self.pki_host, self.pki_port)) as sock:
            with context.wrap_socket(sock, server_hostname=self.pki_host) as ssock:
                request = {
                    "action": "send_public_key",
                    "public_key": self.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode(),
                    "name": self.name
                }
                ssock.sendall(json.dumps(request).encode())
                response = ssock.recv(1024).decode()
                response = json.loads(response)
                self.certificate = response["certificate"]

    # Reception du certificat signé par la PKI
    # utilise également un socket pour recevoir le certificat signé de la PKI. 
    # Le certificat est au format JSON et contient la clé publique du nœud, la signature de la PKI et la date d'expiration.
    def receive_certificate_from_pki(self):

        with socket.create_connection((self.pki_host, self.pki_port)) as sock:
            with context.wrap_socket(sock, server_hostname=self.pki_host) as ssock:
                request = {
                    "action": "get_certificate",
                    "name": self.name
                }
                ssock.sendall(json.dumps(request).encode())
                response = ssock.recv(1024).decode()
                response = json.loads(response)
                self.certificate = response["certificate"]


    def create_ssl_context(self):
    # # Crée et retourne un contexte SSL configuré pour utiliser TLSv1.2 
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_REQUIRED  # <--- ajouter cette ligne
        #ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.load_cert_chain(certfile=self.certificate_path, keyfile=self.private_key_path)
        ssl_context.load_verify_locations(cafile=self.ca_certificate_path)
        return ssl_context

    # Chiffrement du message en utilisant la clé symétrique partagée (bibliothèque "cryptography" / partagée entre les nœuds lors de l'établissement de la connexion)
    # Deux arguments : 
    # - "recipient" : tuple contenant l'adresse IP et le port du destinataire
    # - "message" : contenu du message à envoyer
    # Chiffrement du message à l'aide de la clé partagée, en utilisant le mode de chiffrement AES en mode GCM (Galois/Counter Mode). 
    # Le résultat est ensuite stocké dans la variable "cipher_text", tandis que le tag de vérification d'intégrité est stocké dans la variable "tag".
    # Création d'une nouvelle connexion TCP/IP avec le destinataire (bibliothèque socket). 
    # Le message chiffré, le tag de vérification d'intégrité et le nom de l'expéditeur (noeud) sont encodés en JSON puis envoyés au destinataire à l'aide de la la fonction "sendall()".
    def send_message(self, recipient, message):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.shared_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        context = ssl.create_default_context()

        with socket.create_connection((recipient, 8000)) as sock:
            with context.wrap_socket(sock, server_hostname=recipient) as ssock:
                request = {
                    "action": "send_message",
                    "message": {
                        "sender": self.name,
                        "data": encrypted_data.hex(),
                        "iv": iv.hex()
                    }
                }
                ssock.sendall(json.dumps(request).encode())

    # Réception des messages chiffrés, puis déchiffrement du contenu (en utilisant la clé symétrique partagée). 
    # Utilisation d'une boucle "while" pour écouter de façon continue les données entrantes sur le programme/conteneur. 
    # A réception d'une donnée : décodage au format JSON et vérification du contenu d'un message chiffré. 
    # Si message chiffré : déchiffrement du message en utilisant la clé symétrique partagée et affichage du message déchiffré à l'utilisateur. 
    # Si les données reçues ne contiennent pas de message chiffré : affichage d'un message d'erreur.
    def receive_message(self):
        while True:
            data = self.connection.recv(1024)
            if not data:
                break

            json_data = data.decode()
            data_dict = json.loads(json_data)

            if "encrypted_message" in data_dict:
                encrypted_message = data_dict["encrypted_message"].encode()

                cipher = AES.new(self.shared_key, AES.MODE_GCM, nonce=encrypted_message[:16])
                plaintext = cipher.decrypt_and_verify(encrypted_message[16:], encrypted_message[16:32])

                print(f"[{self.name}] Message reçu de {data_dict['sender']}: {plaintext.decode()}")
            else:
                print(f"[{self.name}] Message invalide : {data_dict}")
                
    # Execution du programme : Instancie un objet "Node" et appel les fonctions "generate_key_pair", "send_public_key_to_pki" et "receive_certificate_from_pki" pour générer une paire de clés privée/publique, 
    # envoyer la clé publique au serveur PKI pour obtenir un certificat signé, et recevoir le certificat signé de la PKI. 
    # Ensuite, création d'un socket et écoute des connexions entrantes. 
    # Lorsqu'une connexion est établie : appel de la fonction "exchange_key" pour échanger les clés symétriques avec le noeud distant, puis création d'un "thread" pour gérer la réception des messages entrants (via la fonction "receive_message").
    def run(self):
        self.generate_key_pair()
        self.send_public_key_to_pki()
        self.receive_certificate_from_pki()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen()

        print(f"[{self.name}] Node en écoute sur {self.host}:{self.port}")

        while True:
            self.connection, client_address = self.socket.accept()
            print(f"[{self.name}] Nouvelle connexion de {client_address}")
            
            self.exchange_key()
            
            threading.Thread(target=self.receive_message).start()


########################
#### NOTES / ESSAIS ####
########################

########################

# Execution du programme : Instancie un objet "Node" avec les paramètres nom, ip et port du serveur.
if __name__ == '__main__':
    node = Node('Client_A', '192.168.1.100', 32700)
    #node = Node('192.168.1.101', '192.168.1.100', 32700)
    node.run()

########################

# Execution avec : python3 site_A.py
# Envoi message vers un autre noeud/client : commande "send" suivie du nom du destinataire et du message 
# Exemple : send Site_B msg vers site B
# Affichage des messages reçus : Utilisation de la commande "recv" sans paramètres
# Exemple : recv
