import socket
import ssl

# Configuration du socket
client_a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_a.connect(('192.168.1.100', 32700))

# Création d'un contexte SSL pour une communication sécurisée
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_cert_chain(certfile="/PKI/Cert/site_a.crt", keyfile="/etc/ssl/private/site_a_key.crt")

# Ajout du certificat auto-signé du serveur à la liste des certificats de confiance
context.load_verify_locations(cafile="/usr/share/ca-certificates/PKI/root_cert.crt")
context.check_hostname = False
# context.verify_mode = ssl.CERT_NONE

# Création d'une socket SSL
client_a = context.wrap_socket(client_a, server_hostname='Site A')

# Demande de certificat sécurisé TLS au serveur central PKI
client_a.send(b"Bonjour PKI pouvez-vous me fournir un certificat securise TLS pour une communication avec client B")

# Réception du certificat du serveur
certificat = client_a.recv(1024)

# Création d'un contexte SSL pour la communication avec client B
context_b = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context_b.load_cert_chain(certfile="/PKI/Cert/site_a.crt", keyfile="/etc/ssl/private/site_a_key.crt")

# Ajout du certificat auto-signé du serveur à la liste des certificats de confiance
context_b.load_verify_locations(cafile="/usr/share/ca-certificates/PKI/root_cert.crt")
context_b.check_hostname = False
# context.verify_mode = ssl.CERT_NONE

# Création d'une socket SSL pour la communication avec client B
client_b = context_b.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname='Site B')
client_b.connect(('192.168.1.102', 32700))

# Envoi du message sécurisé TLS à client B
client_b.send(b"Bonjour client B, comment allez-vous ?")

# Réception de la réponse sécurisée TLS de client B
reponse = client_b.recv(1024)
print(reponse)

# Fermeture de la connexion SSL avec client B
client_b.close()

# Fermeture de la connexion SSL avec le serveur central PKI
client_a.close()
