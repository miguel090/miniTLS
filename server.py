#!/usr/bin/env python

import socket
import threading
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, ARC4, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random.random import randrange
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import DSS
import struct

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


class ClientThread(threading.Thread):

    def __init__(self, ip, port, client_nr, clientsocket):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.client_nr = client_nr

        self.csocket = clientsocket

        key = Key()
        self.server_secret = randrange(0, key.q - 1)
        self.shared_prime = key.p
        self.shared_base = key.g
        self.server_DHside = pow(
            self.shared_base, self.server_secret, self.shared_prime)

        # Everything is set after establishing session key
        self.sessionKey = 0
        self.enc_key = 0
        self.auth_key = 0

        self.enc = 0
        self.dec = 0
        self.ehmac = 0
        self.dhmac = 0

        self.nonce_iv = 0
        self.nrseq = 0

        print("[+] New thread started for " + ip + ":" + str(port))

    def establish_session_key(self):
        # print('server_public_key: ' + str(self.server_DHside))

        client_DHside = self.receive_message()
        # print('client_public_key: ' + str(client_DHside))

        self.nonce_iv = self.receive_message()
        # print("Received nonce_iv" + str(self.nonce_iv) + "\n")

        client_DHside = int(client_DHside.decode(CHARSET))
        sessionKey = pow(client_DHside, self.server_secret, self.shared_prime)
        self.sessionKey = str(sessionKey).encode(CHARSET)
        self.set_keys()

        # encrypted_signed_json is a json with the client nr and the signature of the hash of gy and gx
        # It is encrypted with session key and b64 encoded
        encrypted_signed_json, hashed_values = self.sign_client_and_DHsides(
            client_DHside)

        data_to_send = json.dumps(
            {'gy': str(self.server_DHside), 'certs': self.importCertificates(), 'encrypted_signed': encrypted_signed_json})

        # print("data to send" + data_to_send)
        self.send_message(data_to_send.encode(CHARSET))

        data = self.receive_message()

        rcv_json = json.loads(data)
        confirmation_data_encrypted = b64decode(rcv_json['encrypted_signed'])
        certs = rcv_json['certs']

        confirmation_data = self.get_confirmation_data(
            confirmation_data_encrypted)

        if(self.checkCertificates(certs)):
            print("The certificate chain could not be validated")
            return False

        # The signature contains the hashed values so it verifies if the values are correct
        return self.verify_signature(confirmation_data, hashed_values)

    def set_keys(self):
        self.enc_key = SHA256.new(data=self.sessionKey + b'1').digest()
        self.auth_key = SHA256.new(data=self.sessionKey + b'2').digest()

        if(CIPHER == "AES-CTR-NoPadding"):
            self.enc = AES.new(self.enc_key, AES.MODE_CTR, nonce=self.nonce_iv)
            self.dec = AES.new(self.enc_key, AES.MODE_CTR, nonce=self.nonce_iv)

        elif(CIPHER == "RC4"):
            self.enc = ARC4.new(self.enc_key, nonce=self.nonce_iv)
            self.dec = ARC4.new(self.enc_key, nonce=self.nonce_iv)

        elif(CIPHER == "AES-CBC-NoPadding" or CIPHER == "AES-CBC-PKCS5Padding"):
            self.enc = AES.new(self.enc_key, AES.MODE_CBC, iv=self.nonce_iv)
            self.dec = AES.new(self.enc_key, AES.MODE_CBC, iv=self.nonce_iv)

        elif(CIPHER == "AES-CFB8-NoPadding" or CIPHER == "AES-CFB8-PKCS5Padding"):
            self.enc = AES.new(self.enc_key, AES.MODE_CFB,
                               iv=self.nonce_iv, segment_size=8)
            self.dec = AES.new(self.enc_key, AES.MODE_CFB,
                               iv=self.nonce_iv, segment_size=8)

        # PyCryptoDome não permite segment_size = 1 para CFB-1
        elif(CIPHER == "AES-CFB-NoPadding"):
            self.enc = AES.new(self.enc_key, AES.MODE_CFB,
                               iv=self.nonce_iv, segment_size=8)
            self.dec = AES.new(self.enc_key, AES.MODE_CFB,
                               iv=self.nonce_iv, segment_size=8)

        self.ehmac = HMAC.new(self.auth_key, digestmod=SHA256)
        self.dhmac = HMAC.new(self.auth_key, digestmod=SHA256)

    def importCertificates(self):
        f = open('AC.pem')
        zero = f.read()
        f.close()

        f = open('grupoFM.pem')
        one = f.read()
        f.close()

        f = open('server.cer')
        two = f.read()
        f.close()

        return json.dumps({"0": zero, "1": one, "2": two})

    def checkCertificates(self, certs):
        depth = len(certs)
        command = ["java", "ValidateCertPath"]

        for i in range(0, depth):
            f = open(str(i) + '_server_tmp.cer', 'wt')
            f.write(certs[str(i)])
            f.close()
            command.append(str(i) + '_server_tmp.cer')

        ret = subprocess.run(command).returncode

        for i in range(0, depth):
            os.remove(str(i) + '_server_tmp.cer')

        if(ret == 0):
            return True
        else:
            return False

    def get_confirmation_data(self, confirmation_data_encrypted):
        ciphertext = b64decode(confirmation_data_encrypted)
        # Returns in bytes format
        return self.dec_data(ciphertext)

    def sign_client_and_DHsides(self, client_DHside):
        # Make json with both values to send
        signing_items = json.dumps(
            {'gy': str(self.server_DHside), 'gx': str(client_DHside)})

        hash_to_sign = SHA256.new(signing_items.encode(CHARSET))
        hash_to_sign = int.from_bytes(hash_to_sign.digest(), byteorder='big')

        f = open('server.key')
        key = RSA.import_key(f.read())
        f.close()

        signature = pow(hash_to_sign, key.d, key.n)
        # print('hashed_values: ' + hash_to_sign.hexdigest())
        # print('signed value: ' + str(signature))
        signature = b64encode(str(signature).encode(CHARSET)).decode(CHARSET)
        signed_json = json.dumps(
            {'signature': signature, 'clientnr': str(self.client_nr)})

        encrypted_signed_json = self.enc_data(signed_json.encode(CHARSET))

        encrypted_signed_json = b64encode(
            encrypted_signed_json).decode(CHARSET)
        return encrypted_signed_json, hash_to_sign

    def verify_signature(self, data_signed, data_to_test):
        f = open('client.cer')
        key = RSA.import_key(f.read())
        f.close()

        hashFromSignature = pow(int(data_signed), key.e, key.n)

        if(data_to_test == hashFromSignature):
            print("Verified signature")
            return True
        else:
            print("The message signature couldn't be validated")
            return False

    def enc_data(self, message):
        if(CIPHER == "AES-CTR-NoPadding" or CIPHER == "RC4" or CIPHER == "AES-CFB8-NoPadding" or CIPHER == "AES-CFB-NoPadding"):
            return self.enc.encrypt(message)
        elif(CIPHER == "AES-CBC-NoPadding"):
            return self.enc.encrypt(pad(message, 16))
        elif(CIPHER == "AES-CBC-PKCS5Padding" or CIPHER == "AES-CFB8-PKCS5Padding"):
            return self.enc.encrypt(pad(message, 16))

    def dec_data(self, ciphertext):
        if(CIPHER == "AES-CTR-NoPadding" or CIPHER == "RC4" or CIPHER == "AES-CFB8-NoPadding" or CIPHER == "AES-CFB-NoPadding"):
            return self.dec.decrypt(ciphertext)
        elif(CIPHER == "AES-CBC-NoPadding"):
            return unpad(self.dec.decrypt(ciphertext), 16)
        elif(CIPHER == "AES-CBC-PKCS5Padding" or CIPHER == "AES-CFB8-PKCS5Padding"):
            return unpad(self.dec.decrypt(ciphertext), 16)

    def make_auth(self, ciphertext):
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

    def make_json(self, ciphertext_bytes, mac):
        # b64 encode becuz of weird characters
        ciphertext = b64encode(ciphertext_bytes).decode(CHARSET)
        mac = b64encode(mac).decode(CHARSET)

        return json.dumps({'ciphertext': ciphertext, 'mac': mac})

    def parse_json(self, data_rcv):
        rcv_json = json.loads(data_rcv)

        ciphertext = b64decode(rcv_json['ciphertext'])
        mac = b64decode(rcv_json['mac'])

        return ciphertext, mac

    def encrypt_and_compose_json_message(self, message):
        message = message.encode(CHARSET)
        ciphertext = self.enc_data(message)
        mac = self.make_auth(message)

        # Create json file
        return self.make_json(ciphertext, mac)

    def decrypt_and_decompose_json_message(self, message):
        try:
            ciphertext, mac = self.parse_json(message)
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
        # print("Send message: " + str(message))
        packet = struct.pack('=I' + str(len(message)) + 's',
                             len(message), message)
        self.csocket.sendall(packet)

    def receive_message(self):
        unpacker = struct.Struct('=I')
        data = self.csocket.recv(unpacker.size)
        if(data == b''):
            print("Received empty message")
            return b''
        n_bytes = unpacker.unpack(data)[0]
        print("Received n_bytes: " + str(n_bytes))

        unpacker = struct.Struct('=' + str(n_bytes) + 's')
        data = self.csocket.recv(unpacker.size)
        message = unpacker.unpack(data)[0]
        print("Received message: " + str(message))
        return message

    def run(self):
        print("Connection from " + self.ip + ":" + str(self.port))

        if self.establish_session_key() == False:
            print("There was an error estabilishing the key")
            self.send_message(
                "Couldn't establish shared key")
            return

        #print("Session key for " + self.ip + ":" + str(self.port) + ": " + str(self.sessionKey))
        # self.set_keys()
        stri = "Welcome to the server"
        send = stri.encode('ascii')
        self.send_message(send)

        data = "dummydata"

        while len(data):
            message = self.receive_message()
            if message == b'':
                break
            message = self.decrypt_and_decompose_json_message(message)
            #print("Received the following data: " + str(data))

            # Print the received message
            print('Received from the client ' + str(self.client_nr) + ': ' +
                  str(message.decode(CHARSET)) + '\n')

            message = self.encrypt_and_compose_json_message(str(message))
            self.send_message(message.encode(CHARSET))
            self.nrseq = self.nrseq + 1

        print("Client at " + self.ip + " disconnected...")


def Main():
    host = "127.0.0.1"
    port = 9999

    tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    tcpsock.bind((host, port))
    print("Listening for incoming connections...\n")
    client_nr = 0
    while True:
        tcpsock.listen(4)
        (clientsock, (ip, port)) = tcpsock.accept()

        # Pass clientsock to the ClientThread thread object being created
        newthread = ClientThread(ip, port, client_nr, clientsock)
        newthread.start()

        client_nr += 1


if __name__ == '__main__':
    Main()
