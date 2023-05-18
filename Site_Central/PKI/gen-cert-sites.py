# Importation des modules nécessaires
import socket
import ssl
from OpenSSL import crypto

# Définition du serveur PKI
class PKIServer:
    def __init__(self, host, port, certfile, keyfile):
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile

    def start(self):
        # Création du socket serveur et liage à l'adresse IP et au port spécifiés
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(5)

        # Boucle d'écoute des connexions entrantes
        while True:
            # Acceptation de la connexion
            conn, addr = sock.accept()
            
            if addr[0] == '192.168.1.101':
                print("Site A s'est connecté !")
            elif addr[0] == '192.168.1.102':
                print("Site B s'est connecté !")
            
            # Encapsulation de la socket dans un contexte SSL/TLS
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
            conn = context.wrap_socket(conn, server_side=True)
            # Traitement de la requête et envoi de la réponse
            data = conn.recv(1024)
            # Récupération de la clé publique du site A
            public_key = crypto.load_publickey(crypto.FILETYPE_PEM, data)
            # Création du certificat X509
            cert = crypto.X509()
            if addr[0] == '192.168.1.101':
                cert.get_subject().CN = "Site A"
            elif addr[0] == '192.168.1.102':
                cert.get_subject().CN = "Site B"
            else:
                cert.get_subject().CN = "unknown"
            # cert.get_subject().CN = "Root CA"
            #Issuer = crypto.X509Name()
            Issuer = crypto.X509Name(crypto.X509().get_subject())
            Issuer.CN = 'Root CA'
            Issuer.OU = "PKI"
            Issuer.O = "PKI"
            Issuer.L = "Paris"
            Issuer.ST = "Ile de France"
            Issuer.C = "FR"
            cert.set_issuer(Issuer)
            # cert.set_issuer().ST = "Ile de France"
            # cert.set_issuer().L = "Paris"
            # cert.set_issuer().O = "PKI"
            # cert.set_issuer().OU = "PKI"
            # cert.set_issuer().CN = "Root CA"
            cert.set_pubkey(public_key)
            cert.set_serial_number(1000)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(315360000)
            # cert.set_issuer(crypto.X509Name('CN=Root CA'))
            # cert.set_subject(crypto.X509Name('CN=Site A'))
            cert.sign(crypto.load_privatekey(crypto.FILETYPE_PEM, open(keyfile).read()), 'sha256')
            # Envoi du certificat X509 au site A
            conn.sendall(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

            if addr[0] == '192.168.1.101':
                certfile_name = "site_a.crt"
            elif addr[0] == '192.168.1.102':
                certfile_name = "site_b.crt"
            else:
                certfile_name = "unknown.crt"
            
            with open(f"Cert-Sites/{certfile_name}", 'wb') as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            # Fermeture de la connexion
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
            if addr[0] == '192.168.1.101':
                print("Certificat envoyé à Site A !")
            elif addr[0] == '192.168.1.102':
                print("Certificat envoyé à Site B !")

# Chargement du certificat et de la clé privée
certfile = "/PKI/root_cert.crt"
keyfile = "/etc/ssl/private/root_key.crt"

# Instanciation du serveur PKI et démarrage du serveur
server = PKIServer("0.0.0.0", 32700, certfile, keyfile)
# while True:
#     # Accepter une connexion entrante
#     client, adresse_client = server.accept()
#     print("Connexion entrante de", adresse_client[0])



server.start()




# else:
#     certfile_name = "unknown.crt"