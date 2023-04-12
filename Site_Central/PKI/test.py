import socket
import ssl
from OpenSSL import crypto

class PKIServer:
    def __init__(self, host, port, certfile, keyfile):
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(5)

        while True:
            conn, addr = sock.accept()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
            conn = context.wrap_socket(conn, server_side=True)
            data = conn.recv(1024)
            if not data:
                continue
            pubkey = crypto.load_publickey(crypto.FILETYPE_PEM, data)
            cert = crypto.X509()
            cert.set_pubkey(pubkey)
            # Récupération de la clé public pour signer le certificat
            with open(self.keyfile, 'r') as f:
                key_data = f.read()
            pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key_data)
            cert.sign(pkey, "sha256")
            cert_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
            conn.sendall(cert_data)
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()

certfile = "/PKI/root_cert.crt"
keyfile = "/etc/ssl/private/root_key.crt"

server = PKIServer("0.0.0.0", 32700, certfile, keyfile)
server.start()
