import socket
import ssl
import json
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
# pip3 install pycrypto

# Adresse IP et port du serveur PKI
PKI_IP = '192.168.1.100'
PKI_PORT = 32700

# Adresse IP et port de Node A
NODE_A_IP = '192.168.1.101'
NODE_A_PORT = 8001

# Adresse IP et port de Node B
NODE_B_IP = '192.168.1.102'
NODE_B_PORT = 8002

# Générer une paire de clés RSA pour Node A
start = time.perf_counter()
key = RSA.generate(2048)
print(f"Generated keys in {time.perf_counter() - start:.2f}s")

# Envoyer la clé publique de Node A au serveur PKI pour obtenir un certificat signé
context = ssl.create_default_context()
with socket.create_connection((PKI_IP, PKI_PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=PKI_IP) as ssock:
        message = {'node': 'A', 'public_key': public_key.decode('utf-8')}
        ssock.sendall(json.dumps(message).encode('utf-8'))
        response = ssock.recv(1024)
        cert = response.decode('utf-8')
        print(f"Certificat de Node A : {cert}")

# Vérifier que le certificat de Node B est signé par la PKI
with socket.create_connection((NODE_B_IP, NODE_B_PORT)) as sock:
    with ssl.wrap_socket(sock, cert_reqs=ssl.CERT_REQUIRED, ca_certs='ca.pem') as ssock:
        ssock.sendall(b'Certificate')
        cert = ssock.recv(1024)
        cert = cert.decode('utf-8')
        print(f"Certificat de Node B : {cert}")
        cert = ssl.DER_cert_to_PEM_cert(cert.encode('utf-8'))
        cert = cert.encode('utf-8')
        cert = ssl.PEM_cert_to_DER_cert(cert)
        cert = ssl.DER_cert_to_PEM_cert(cert)
        cert = cert.decode('utf-8')
        if cert != cert_B:
            print("Erreur : le certificat de Node B n'est pas signé par la PKI")

# Générer une clé secrète AES pour communiquer avec Node B
# secret = b'Très secret !' # à remplacer par une clé générée aléatoirement
secret = os.urandom(16) # génère une clé secrète de 16 octets
cipher = AES.new(secret, AES.MODE_EAX)

# Envoyer une demande de certificat à Node B
with socket.create_connection((NODE_B_IP, NODE_B_PORT)) as sock:
    with ssl.wrap_socket(sock, cert_reqs=ssl.CERT_REQUIRED, ca_certs='ca.pem') as ssock:
        message = {'node': 'A', 'cert': cert.decode('utf-8')}
        ssock.sendall(json.dumps(message).encode('utf-8'))
        response = ssock.recv(1024)
        cert = response.decode('utf-8')
        print(f"Certificat de Node B : {cert}")
        cert = ssl.DER_cert_to_PEM_cert(cert.encode('utf-8'))
        cert = cert.encode('utf-8')
        cert = ssl.PEM_cert_to_DER_cert(cert)
        cert = ssl.DER_cert_to_PEM_cert(cert)
        cert = cert.decode('utf-8')
        if cert != cert_B:
            print("Erreur : le certificat de Node B n'est pas signé par la PKI")

# Envoyer une demande de clé symétrique à Node B
with socket.create_connection((NODE_B_IP, NODE_B_PORT)) as sock:
    with ssl.wrap_socket(sock, cert_reqs=ssl.CERT_REQUIRED, ca_certs='ca.pem') as ssock:
        ciphertext, tag = cipher.encrypt_and_digest(secret)
        message = {'node': 'A', 'ciphertext': ciphertext.hex(), 'tag': tag.hex()}
        ssock.sendall(json.dumps(message).encode('utf-8'))
        response = ssock.recv(1024)
        ciphertext_B = response.decode('utf-8')
        print(f"Message de Node B : {ciphertext_B}")
        ciphertext_B = bytes.fromhex(ciphertext_B)
        plaintext_B = cipher.decrypt(ciphertext_B)
        print(f"Clé symétrique partagée avec Node B : {plaintext_B.decode('utf-8')}")

# Envoyer un message chiffré à Node B
with socket.create_connection((NODE_B_IP, NODE_B_PORT)) as sock:
    with ssl.wrap_socket(sock, cert_reqs=ssl.CERT_REQUIRED, ca_certs='ca.pem') as ssock:
        message = {'node': 'A', 'ciphertext': cipher.encrypt(b"Hello, Node B!").hex()}
        ssock.sendall(json.dumps(message).encode('utf-8'))
        response = ssock.recv(1024)
        ciphertext_B = response.decode('utf-8')
        print(f"Message chiffré de Node B : {ciphertext_B}")
        ciphertext_B = bytes.fromhex(ciphertext_B)
        plaintext_B = cipher.decrypt(ciphertext_B)
        print(f"Message déchiffré de Node B : {plaintext_B.decode('utf-8')}")

# Écouter les messages entrants de Node B
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind((NODE_A_IP, NODE_A_PORT))
    sock.listen()
    conn, addr = sock.accept()
with conn:
    with ssl.wrap_socket(conn, certfile='cert_A.pem', keyfile='key_A.pem', server_side=True) as sconn:
        print(f"Connexion de Node B : {addr}")
        data = sconn.recv(1024)
        ciphertext_B = data.decode('utf-8')
        print(f"Message chiffré de Node B : {ciphertext_B}")
        ciphertext_B = bytes.fromhex(ciphertext_B)
        plaintext_B = cipher.decrypt(ciphertext_B)
        print(f"Message déchiffré de Node B : {plaintext_B.decode('utf-8')}")
        message = {'node': 'A', 'ciphertext': cipher.encrypt(b"Hello, Node B!").hex()}
        sconn.sendall(json.dumps(message).encode('utf-8'))
