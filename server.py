#!/usr/bin/env python

import socket
import threading
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

KEY = b'0123456789'
NONCE = b'abcdef'
IV = b'0123456789abcdef'
CHARSET = 'utf-8'
CIPHER = "AES-CTR-NoPadding"
# Ciphers: AES-CTR-NoPadding, RC4, AES-CBC-NoPadding, AES-CBC-PKCS5Padding, AES-CFB8-NoPadding, AES-CFB8-PKCS5Padding, AES-CFB-NoPadding


class ClientThread(threading.Thread):

    def __init__(self, ip, port, clientsocket):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.csocket = clientsocket
        self.charset = CHARSET
        self.nonce = NONCE
        self.nrseq = 0

        self.enc_key = SHA256.new(data=KEY).digest()

        if(CIPHER == "AES-CTR-NoPadding"):
            self.enc = AES.new(self.enc_key, AES.MODE_CTR, nonce=self.nonce)
            self.dec = AES.new(self.enc_key, AES.MODE_CTR, nonce=self.nonce)

        elif(CIPHER == "RC4"):
            self.enc = ARC4.new(self.enc_key, nonce=self.nonce)
            self.dec = ARC4.new(self.enc_key, nonce=self.nonce)

        elif(CIPHER == "AES-CBC-NoPadding" or CIPHER == "AES-CBC-PKCS5Padding"):
            self.enc = AES.new(self.enc_key, AES.MODE_CBC, iv=IV)
            self.dec = AES.new(self.enc_key, AES.MODE_CBC, iv=IV)

        elif(CIPHER == "AES-CFB8-NoPadding" or CIPHER == "AES-CFB8-PKCS5Padding"):
            self.enc = AES.new(self.enc_key, AES.MODE_CFB,
                               iv=IV, segment_size=8)
            self.dec = AES.new(self.enc_key, AES.MODE_CFB,
                               iv=IV, segment_size=8)

        # PyCryptoDome não permite segment_size = 1 para CFB-1
        elif(CIPHER == "AES-CFB-NoPadding"):
            self.enc = AES.new(self.enc_key, AES.MODE_CFB,
                               iv=IV, segment_size=8)
            self.dec = AES.new(self.enc_key, AES.MODE_CFB,
                               iv=IV, segment_size=8)

        print("[+] New thread started for " + ip + ":" + str(port))

    def encData(self, message):
        if(CIPHER == "AES-CTR-NoPadding" or CIPHER == "RC4" or CIPHER == "AES-CFB8-NoPadding" or CIPHER == "AES-CFB-NoPadding"):
            return self.enc.encrypt(message)
        elif(CIPHER == "AES-CBC-NoPadding"):
            return self.enc.encrypt(pad(message, 16))
        elif(CIPHER == "AES-CBC-PKCS5Padding" or CIPHER == "AES-CFB8-PKCS5Padding"):
            return self.enc.encrypt(pad(message, 16))

    def decData(self, ciphertext):
        if(CIPHER == "AES-CTR-NoPadding" or CIPHER == "RC4" or CIPHER == "AES-CFB8-NoPadding" or CIPHER == "AES-CFB-NoPadding"):
            return self.dec.decrypt(ciphertext)
        elif(CIPHER == "AES-CBC-NoPadding"):
            return unpad(self.dec.decrypt(ciphertext), 16)
        elif(CIPHER == "AES-CBC-PKCS5Padding" or CIPHER == "AES-CFB8-PKCS5Padding"):
            return unpad(self.dec.decrypt(ciphertext), 16)

    def make_json(self, ciphertext_bytes, nonce):
        # b64 encode becuz of weird characters
        ciphertext = b64encode(ciphertext_bytes).decode(self.charset)
        nonce = b64encode(nonce).decode(self.charset)

        return json.dumps({'nonce': nonce, 'ciphertext': ciphertext})

    def parse_json(self, data_rcv):
        rcv_json = json.loads(data_rcv)

        ciphertext = b64decode(rcv_json['ciphertext'])
        nonce = b64decode(rcv_json['nonce'])

        return ciphertext, nonce

    def run(self):
        print("Connection from " + self.ip + ":" + str(self.port))

        stri = "Welcome to the server"
        send = stri.encode('ascii')
        self.csocket.send(send)

        data = "dummydata"

        while len(data):
            data = self.csocket.recv(2048)
            print("Received the following data: " + str(data))

            if data == b'':
                break

            try:
                ciphertext, nonce = self.parse_json(data)
                # Decode the json received
                message = self.decData(ciphertext)
            except ValueError | KeyError as e:
                print('Error in decryption')

            # Print the received message
            print('Received from the client: ' +
                  str(message.decode(self.charset)) + '\n')

            self.csocket.send(data)
            self.nrseq = self.nrseq + 1

        print("Client at " + self.ip + " disconnected...")


host = "127.0.0.1"
port = 9999

tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

tcpsock.bind((host, port))
print("Listening for incoming connections...\n")

while True:
    tcpsock.listen(4)
    (clientsock, (ip, port)) = tcpsock.accept()

    # pass clientsock to the ClientThread thread object being created
    newthread = ClientThread(ip, port, clientsock)
    newthread.start()
