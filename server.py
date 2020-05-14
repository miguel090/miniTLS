#!/usr/bin/env python

import socket
import threading
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

KEY = b'abcdef'
NONCE = b'1234'
CHARSET = 'utf-8'


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

        self.enc = AES.new(self.enc_key, AES.MODE_CTR, nonce=self.nonce)
        self.dec = AES.new(self.enc_key, AES.MODE_CTR, nonce=self.nonce)

        print("[+] New thread started for " + ip + ":" + str(port))

    def encData(self, message):
        return self.enc.encrypt(message)

    def decData(self, ciphertext):
        return self.dec.decrypt(ciphertext)

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
