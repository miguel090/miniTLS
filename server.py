#!/usr/bin/env python

import socket
import threading
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256


class ClientThread(threading.Thread):

    def __init__(self, ip, port, clientsocket):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.csocket = clientsocket
        self.charset = 'utf-8'
        self.nonce = b'1234'

        self.sessionKey = get_random_bytes(32)
        self.enc_key = SHA256.new(data=self.sessionKey + b'1').digest()
        self.auth_key = SHA256.new(data=self.sessionKey + b'2').digest()

        self.enc = AES.new(self.enc_key, AES.MODE_CTR, nonce=self.nonce)
        self.dec = AES.new(self.enc_key, AES.MODE_CTR, nonce=self.nonce)
        self.ehmac = HMAC.new(self.auth_key, digestmod=SHA256)
        self.dhmac = HMAC.new(self.auth_key, digestmod=SHA256)

        print("[+] New thread started for " + ip + ":" + str(port))
    
    def encData(self, message):
        return self.enc.encrypt(message)


    def decData(self, ciphertext):
        return self.dec.decrypt(ciphertext)


    def make_auth(self, mac, ciphertext):
        self.ehmac.update(ciphertext)
        return self.ehmac.digest()


    def verify_auth(self, ciphertext, mac):
        self.dhmac.update(ciphertext)
        try:
            # need to transform from hexadecimal bytes to hexadecimal string
            self.dhmac.hexverify(mac.hex())
            print('MAC is good.')
        except ValueError as e:
            print('MAC with error.')
            return 1

        return 0

    def make_json(self, ciphertext_bytes, nonce, mac):
        # b64 encode becuz of weird characters
        ciphertext = b64encode(ciphertext_bytes).decode(self.charset)
        nonce = b64encode(nonce).decode(self.charset)
        mac = b64encode(mac).decode(self.charset)

        return json.dumps({'nonce': nonce, 'ciphertext': ciphertext, 'mac': mac})

    def parse_json(self, data_rcv):
        rcv_json = json.loads(data_rcv)

        ciphertext = b64decode(rcv_json['ciphertext'])
        nonce = b64decode(rcv_json['nonce'])
        mac = b64decode(rcv_json['mac'])

        return ciphertext, nonce, mac

    def run(self):
        print("Connection from " + self.ip + ":" + str(self.port))

        print("Session key for " + self.ip + ":" +
              str(self.port) + ": " + str(self.sessionKey))
        self.csocket.send(self.sessionKey)

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
                ciphertext, nonce, mac = self.parse_json(data)
                # Decode the json received
                message = self.decData(ciphertext)
            except ValueError | KeyError as e:
                print('Error in decryption')

            # Validate mac
            if self.verify_auth(message, mac) != 0:
                print("Security error. Closing connection")
                break

            # Print the received message
            print('Received from the client: ' +
                  str(message.decode(self.charset)) + '\n')

            self.csocket.send(data)

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
