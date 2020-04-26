#!/usr/bin/env python

import socket
import threading
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random.random import randrange
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

from asn1crypto.keys import DSAParams
from os import system

charset = 'utf-8'


class Key:
    def __init__(self):
        # code got in slack by student with name up201005324
        system("openssl dsaparam -outform DER -in parameters1.pem -out parameters1.der")
        with open("parameters1.der", "rb") as f:
            certs = f.read()
        params = DSAParams.load(certs)
        self.p = int(params['p'])
        self.q = int(params['q'])
        self.g = int(params['g'])
        f.close()


class ClientThread(threading.Thread):

    def __init__(self, ip, port, client_nr, clientsocket):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.client_nr = client_nr
        client_nr += 1

        self.csocket = clientsocket
        self.charset = 'utf-8'
        self.nonce = b'1234'
        self.nrseq = 0

        key = Key()
        self.server_secret = randrange(0, key.q - 1)
        self.shared_prime = key.p
        self.shared_base = key.g
        self.server_DHside = pow(self.shared_base, self.server_secret, self.shared_prime)

        # everything is set after establishing session key
        self.sessionKey = 0
        self.enc_key = 0
        self.auth_key = 0

        self.enc = 0
        self.dec = 0
        self.ehmac = 0
        self.dhmac = 0

        print("[+] New thread started for " + ip + ":" + str(port))

    def establish_session_key(self):
        # print('server_public_key: ' + str(self.server_public_key))
        client_DHside = self.csocket.recv(4096)
        # print('client_public_key: ' + str(client_public_key))
        client_DHside = int(client_DHside.decode(self.charset))
        sessionKey = pow(client_DHside, self.server_secret, self.shared_prime)
        self.sessionKey = str(sessionKey).encode(self.charset)
        self.set_keys()

        # encrypted_signed_json is a json with the client nr and the signature of the hash of gy and gx
        # it is encrypted with session key and b64 encoded
        encrypted_signed_json, hashed_values = self.sign_client_and_DHsides(client_DHside)

        data_to_send = json.dumps({'gy': str(self.server_DHside), 'encrypted_signed': encrypted_signed_json})

        self.csocket.send(data_to_send.encode('utf-8'))

        confirmation_data_encrypted = self.csocket.recv(4096)
        confirmation_data = self.get_confirmation_data(confirmation_data_encrypted)
        #The signature contains the hashed values so it verifies if the values are correct
        if self.verify_signature(confirmation_data, hashed_values) == False:
            return False
        return True


    def get_confirmation_data(self, confirmation_data_encrypted):
        ciphertext = b64decode(confirmation_data_encrypted)
        # returns in bytes format
        return self.dec_data(ciphertext)

    def sign_client_and_DHsides(self, client_DHside):
        # make json with both values to send
        signing_items = json.dumps({'gy': str(self.server_DHside), 'gx': str(client_DHside)})
        hash_to_sign = SHA256.new(signing_items.encode(self.charset))

        f = open('server_private_key.pem')
        key = ECC.import_key(f.read())

        signer = DSS.new(key, 'fips-186-3')
        signature = signer.sign(hash_to_sign)
        #print('hashed_values: ' + hash_to_sign.hexdigest())
        #print('signed value: ' + str(signature))
        signature = b64encode(signature).decode(self.charset)
        signed_json = json.dumps({'signature': signature, 'clientnr': str(self.client_nr)})

        encrypted_signed_json = self.enc_data(signed_json.encode(self.charset))

        encrypted_signed_json = b64encode(encrypted_signed_json).decode(charset)
        return encrypted_signed_json, hash_to_sign

    def verify_signature(self, data_signed, data_to_test):
        key = ECC.import_key(open(str(self.client_nr) + '_public_key.pem').read())
        verifier = DSS.new(key, 'fips-186-3')
        try:
            test = verifier.verify(data_to_test, data_signed)
            print("verified signature")
            return True
        except ValueError:
            print("The message signature couldnt be validated")
            return False

    def set_keys(self):

        self.enc_key = SHA256.new(data=self.sessionKey + b'1').digest()
        self.auth_key = SHA256.new(data=self.sessionKey + b'2').digest()

        self.enc = AES.new(self.enc_key, AES.MODE_CTR, nonce=self.nonce)
        self.dec = AES.new(self.enc_key, AES.MODE_CTR, nonce=self.nonce)
        self.ehmac = HMAC.new(self.auth_key, digestmod=SHA256)
        self.dhmac = HMAC.new(self.auth_key, digestmod=SHA256)

    def enc_data(self, message):
        # message must be bytes
        return self.enc.encrypt(message)

    def dec_data(self, ciphertext):
        return self.dec.decrypt(ciphertext)

    def make_auth(self, mac, ciphertext):
        ciphertext = ciphertext + bytes(self.nrseq)
        self.ehmac.update(ciphertext)
        return self.ehmac.digest()

    def verify_auth(self, ciphertext, mac):
        # add sequence number to ciphertext
        ciphertext = ciphertext + bytes(self.nrseq)
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
        if self.establish_session_key() == False:
            print("There was an error estabilishing the key")
            self.csocket.send("Couldnt establish shared key").encode(self.charset)
            return

        #print("Session key for " + self.ip + ":" + str(self.port) + ": " + str(self.sessionKey))
        self.set_keys()
        stri = "Welcome to the server"
        send = stri.encode('ascii')
        self.csocket.send(send)

        data = "dummydata"

        while len(data):
            data = self.csocket.recv(2048)
            #print("Received the following data: " + str(data))

            if data == b'':
                break

            try:

                ciphertext, nonce, mac = self.parse_json(data)
                # Decode the json received
                message = self.dec_data(ciphertext)

            except ValueError | KeyError as e:
                print('Error in decryption')

            # Validate mac
            if self.verify_auth(message, mac) != 0:
                print("Security error. Closing connection")
                break

            # Print the received message
            print('Received from the client ' + str(self.client_nr) + ': ' +
                  str(message.decode(self.charset)) + '\n')

            self.csocket.send(data)
            self.nrseq = self.nrseq + 1

        print("Client at " + self.ip + " disconnected...")


def create_asymetric_key_files():
    key = ECC.generate(curve='P-256')

    f = open('server_private_key.pem', 'wt')
    f.write(key.export_key(format='PEM'))
    f.close()

    f = open('server_public_key.pem', 'wt')
    f.write(key.export_key(format='PEM'))
    f.close()


def Main():
    create_asymetric_key_files()

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

        # pass clientsock to the ClientThread thread object being created
        newthread = ClientThread(ip, port, client_nr, clientsock)
        newthread.start()
        client_nr += 1


if __name__ == '__main__':
    Main()
