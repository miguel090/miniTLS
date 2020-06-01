# Import socket module
import socket
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, ARC4, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randrange
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import DSS
from Crypto.Util.Padding import pad, unpad
import struct
from OpenSSL import crypto

from asn1crypto.keys import DSAParams
from os import system
import os
import subprocess

IV_SIZE = 16
NONCE_SIZE = 8
CHARSET = 'utf-8'
PACKET_SIZE = 4096
CIPHER = "AES-CTR-NoPadding"
# Ciphers: AES-CTR-NoPadding, RC4, AES-CBC-NoPadding, AES-CBC-PKCS5Padding, AES-CFB8-NoPadding, AES-CFB8-PKCS5Padding, AES-CFB-NoPadding


class Key:
    def __init__(self):
        # Code got in slack by student with up201005324
        # system("openssl dsaparam -outform DER -in parameters.pem -out parameters.der")
        with open("parameters.der", "rb") as f:
            certs = f.read()
        f.close()
        params = DSAParams.load(certs)
        self.p = int(params['p'])
        self.q = int(params['q'])
        self.g = int(params['g'])


class Client:
    def __init__(self, soc):
        self.socket = soc

        key = Key()
        self.client_secret = randrange(0, key.q - 1)
        self.shared_prime = key.p
        self.shared_base = key.g
        self.client_DHside = pow(
            self.shared_base, self.client_secret, self.shared_prime)

        # Everything is set after establishing session key
        self.server_DHside = 0
        self.sessionKey = 0
        self.enc_key = 0
        self.auth_key = 0
        self.clientnr = 0

        self.encCipher = 0
        self.decCipher = 0
        self.ehmac = 0
        self.dhmac = 0

        self.nonce_iv = 0
        self.nrseq = 0

    def establish_session_key(self):
        # print("client_DHside: " + str(self.client_DHside))
        self.send_message(str(self.client_DHside).encode(CHARSET))

        self.generate_and_send_nonce_iv()

        server_DHside_signature_clientnr = self.receive_message()
        # print("server_DHside: " + str(server_DHside_signature_clientnr))
        server_DHside, encrypted_json, certs = get_server_DHside_encrypted_json_and_certs(
            server_DHside_signature_clientnr)
        sessionKey = pow(server_DHside, self.client_secret, self.shared_prime)
        self.sessionKey = str(sessionKey).encode(CHARSET)

        self.set_keys()

        signed_hash_json = self.dec_data(encrypted_json)
        self.clientnr, signed_hash = get_clientnr_and_hash_from_json(
            signed_hash_json)
        # print(signed_hash)
        hashed_values, validity = self.verify_hash(signed_hash, server_DHside)
        if validity == False:
            return False

        if(not self.checkCertificates(certs)):
            print("The certificate chain could not be validated")
            return False

        signed_hash = self.sign_DHvalues(hashed_values)
        message_to_send = self.enc_data(signed_hash)
        message_to_send = b64encode(message_to_send).decode(CHARSET)
        data_to_send = json.dumps(
            {'encrypted_signed': message_to_send, 'certs': self.importCertificates()})

        # print("data to send" + data_to_send)
        self.send_message(data_to_send.encode(CHARSET))
        # print(client.sessionKey)

        return True

    def generate_and_send_nonce_iv(self):
        if(CIPHER == "AES-CTR-NoPadding" or CIPHER == "RC4"):
            self.nonce_iv = get_random_bytes(NONCE_SIZE)
        elif(CIPHER == "AES-CBC-NoPadding" or CIPHER == "AES-CBC-PKCS5Padding" or CIPHER == "AES-CFB8-NoPadding" or CIPHER == "AES-CFB8-PKCS5Padding" or CIPHER == "AES-CFB-NoPadding"):
            self.nonce_iv = get_random_bytes(IV_SIZE)

        self.send_message(self.nonce_iv)
        print("Sended nonce_iv " + str(self.nonce_iv) +
              " of length " + str(len(self.nonce_iv)))

    def set_keys(self):
        self.enc_key = SHA256.new(data=self.sessionKey + b'1').digest()
        self.auth_key = SHA256.new(data=self.sessionKey + b'2').digest()

        if(CIPHER == "AES-CTR-NoPadding"):
            self.encCipher = AES.new(
                self.enc_key, AES.MODE_CTR, nonce=self.nonce_iv)
            self.decCipher = AES.new(
                self.enc_key, AES.MODE_CTR, nonce=self.nonce_iv)

        elif(CIPHER == "RC4"):
            self.encCipher = ARC4.new(self.enc_key, nonce=self.nonce_iv)
            self.decCipher = ARC4.new(self.enc_key, nonce=self.nonce_iv)

        elif(CIPHER == "AES-CBC-NoPadding" or CIPHER == "AES-CBC-PKCS5Padding"):
            self.encCipher = AES.new(
                self.enc_key, AES.MODE_CBC, iv=self.nonce_iv)
            self.decCipher = AES.new(
                self.enc_key, AES.MODE_CBC, iv=self.nonce_iv)

        elif(CIPHER == "AES-CFB8-NoPadding" or CIPHER == "AES-CFB8-PKCS5Padding"):
            self.encCipher = AES.new(
                self.enc_key, AES.MODE_CFB, iv=self.nonce_iv, segment_size=8)
            self.decCipher = AES.new(
                self.enc_key, AES.MODE_CFB, iv=self.nonce_iv, segment_size=8)

        # PyCryptoDome não permite segment_size = 1 para CFB-1
        elif(CIPHER == "AES-CFB-NoPadding"):
            self.encCipher = AES.new(
                self.enc_key, AES.MODE_CFB, iv=self.nonce_iv, segment_size=8)
            self.decCipher = AES.new(
                self.enc_key, AES.MODE_CFB, iv=self.nonce_iv, segment_size=8)

        self.ehmac = HMAC.new(self.auth_key, digestmod=SHA256)
        self.dhmac = HMAC.new(self.auth_key, digestmod=SHA256)

    def importCertificates(self):
        f = open('AC.pem')
        zero = f.read()
        f.close()

        f = open('grupoFM.pem')
        one = f.read()
        f.close()

        f = open('client.cer')
        two = f.read()
        f.close()

        return json.dumps({"0": zero, "1": one, "2": two})

    def checkCertificates(self, certs):
        certs = json.loads(certs)
        depth = len(certs.keys())

        leaf = crypto.load_certificate(
            crypto.FILETYPE_PEM, certs[str(depth-1)])

        intermediates = []
        for i in range(1, depth-1):
            intermediates.append(crypto.load_certificate(
                crypto.FILETYPE_PEM, certs[str(i)]))

        bad_store = crypto.X509Store()
        # add the AC root
        f = open('AC.pem')
        acCert = f.read()
        f.close()

        bad_store.add_cert(crypto.load_certificate(
            crypto.FILETYPE_PEM, acCert))
        for intermediate in intermediates:
            bad_store.add_cert(intermediate)
        bad_store_ctx = crypto.X509StoreContext(bad_store, leaf)

        try:
            bad_store_ctx.verify_certificate()
            print("== CHAIN IS VALID ==")
        except Exception as e:
            print("== CHAIN FAILED VALIDATION ==")
            return False

        return True

    def sign_DHvalues(self, hashed_values):
        f = open('client.key')
        key = RSA.import_key(f.read())
        f.close()

        signed_hash = pow(hashed_values, key.d, key.n)

        return str(signed_hash).encode(CHARSET)

    def verify_hash(self, signed_hash, server_DHside):
        verify_values = json.dumps(
            {'gy': str(server_DHside), 'gx': str(self.client_DHside)})
        # verify_values = str(server_DHside) + str(self.client_DHside)
        hash_to_verify = SHA256.new(verify_values.encode(CHARSET))
        hash_to_verify = int.from_bytes(
            hash_to_verify.digest(), byteorder='big')

        #print('hashed values: ' + hash_to_verify.hexdigest())
        # print('signed value: ' + str(signed_hash))
        f = open('server.cer')
        key = RSA.import_key(f.read())
        f.close()

        hashFromSignature = pow(int(signed_hash), key.e, key.n)

        if(hash_to_verify == hashFromSignature):
            print("Verified signature")
            return hash_to_verify, True
        else:
            print("The message signature couldn't be validated")
            return hash_to_verify, False

    def enc_data(self, message):
        if(CIPHER == "AES-CTR-NoPadding" or CIPHER == "RC4" or CIPHER == "AES-CFB8-NoPadding" or CIPHER == "AES-CFB-NoPadding"):
            return self.encCipher.encrypt(message)
        elif(CIPHER == "AES-CBC-NoPadding"):
            return self.encCipher.encrypt(pad(message, 16))
        elif(CIPHER == "AES-CBC-PKCS5Padding" or CIPHER == "AES-CFB8-PKCS5Padding"):
            return self.encCipher.encrypt(pad(message, 16))

    def dec_data(self, ciphertext):
        if(CIPHER == "AES-CTR-NoPadding" or CIPHER == "RC4" or CIPHER == "AES-CFB8-NoPadding" or CIPHER == "AES-CFB-NoPadding"):
            return self.decCipher.decrypt(ciphertext)
        elif(CIPHER == "AES-CBC-NoPadding"):
            return unpad(self.decCipher.decrypt(ciphertext), 16)
        elif(CIPHER == "AES-CBC-PKCS5Padding" or CIPHER == "AES-CFB8-PKCS5Padding"):
            return unpad(self.decCipher.decrypt(ciphertext), 16)

    def make_auth(self, ciphertext):
        # Add sequence number to ciphertext
        ciphertext = ciphertext + bytes(self.nrseq)
        self.ehmac.update(ciphertext)
        return self.ehmac.digest()

    def verify_auth(self, ciphertext, mac):
        # Add sequence number to ciphertext
        ciphertext = ciphertext + bytes(self.nrseq)
        self.dhmac.update(ciphertext)
        try:
            # Need to transform from hexadecimal bytes to hexadecimal string
            self.dhmac.hexverify(mac.hex())
            print('MAC is good.')
        except ValueError as e:
            print('MAC with error.')
            return False

        return True

    def encrypt_and_compose_json_message(self, message):
        message = message.encode(CHARSET)
        ciphertext = self.enc_data(message)
        mac = self.make_auth(message)

        # Create json file
        return make_json(ciphertext, mac)

    def decrypt_and_decompose_json_message(self, message):
        try:
            ciphertext, mac = parse_json(message)
            # Decode the json received
            message = self.dec_data(ciphertext)
            # print(message)
        except ValueError | KeyError as e:
            print('Error in decryption')
            raise e

        # Validate mac
        if self.verify_auth(message, mac) == False:
            print("Security error. Closing connection")
            raise ValueError

        return message

    def send_message(self, message):
        # print("Send struct: " + '=I' + str(len(message)) + 's')
        packet = struct.pack('=I' + str(len(message)) + 's',
                             len(message), message)
        self.socket.sendall(packet)

    def receive_message(self):
        unpacker = struct.Struct('=I')
        data = self.socket.recv(unpacker.size)
        if(data == b''):
            print("Received empty message")
            return b''
        n_bytes = unpacker.unpack(data)[0]
        # print("Received n_bytes: " + str(n_bytes))

        unpacker = struct.Struct('=' + str(n_bytes) + 's')
        data = self.socket.recv(unpacker.size)
        message = unpacker.unpack(data)[0]
        # print("Received message: " + str(message))
        print("Received message")
        return message


def get_clientnr_and_hash_from_json(signed_hash_json):
    rcv_json = json.loads(signed_hash_json)
    return rcv_json['clientnr'], b64decode(rcv_json['signature'])


def get_server_DHside_encrypted_json_and_certs(server_DHside_signature_clientnr):
    rcv_json = json.loads(server_DHside_signature_clientnr)
    return int(rcv_json['gy']), b64decode(rcv_json['encrypted_signed']), rcv_json['certs']


def make_json(ciphertext_bytes, mac):
    # b64 encode becuz of weird characters
    ciphertext = b64encode(ciphertext_bytes).decode(CHARSET)
    mac = b64encode(mac).decode(CHARSET)

    return json.dumps({'ciphertext': ciphertext, 'mac': mac})


def parse_json(data_rcv):
    rcv_json = json.loads(data_rcv)

    ciphertext = b64decode(rcv_json['ciphertext'])
    mac = b64decode(rcv_json['mac'])

    return ciphertext, mac


def Main():
    # Local host IP '127.0.0.1'
    host = '127.0.0.1'
    # Define the port on which you want to connect
    port = 9999

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to server on local computer
    s.connect((host, port))

    client = Client(s)
    if client.establish_session_key() == False:
        print("There was an error estabilishing the key")
        # s.sendall("Couldnt establish shared key".encode(CHARSET))
        return

    #print('Received the following session key: ' + str(client.sessionKey) + '\n')
    message = client.receive_message()
    print('Received the following greeting message: ' + str(message) + '\n')
    # Reset keys so values coincide again
    # client.set_keys()
    while True:
        try:
            message = input('Message to send: ')
        except EOFError as e:
            print("Type 'quit' or 'exit' to exit the program gracefully.")
            continue

        if message == '':
            print("Type 'quit' or 'exit' to exit the program gracefully.")
            continue
        elif message == 'quit' or message == 'exit':
            break

        message = client.encrypt_and_compose_json_message(message)
        # print(message)
        client.send_message(message.encode(CHARSET))

        message = client.receive_message()
        if message == b'':
            print('Server disconnected Exiting...')
            break
        message = client.decrypt_and_decompose_json_message(message)

        # Print the received message
        print('Received from the server: ' +
              message.decode(CHARSET) + '\n')
        client.nrseq = client.nrseq + 1

    # Close the connection
    s.close()


if __name__ == '__main__':
    Main()
