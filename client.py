
# Import socket module
import socket
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


class Client:
    def __init__(self, nonce):
        self.nonce = nonce
        self.enc_key = SHA256.new(data=KEY).digest()

        if(CIPHER == "AES-CTR-NoPadding"):
            self.encCipher = AES.new(
                self.enc_key, AES.MODE_CTR, nonce=self.nonce)
            self.decCipher = AES.new(
                self.enc_key, AES.MODE_CTR, nonce=self.nonce)

        elif(CIPHER == "RC4"):
            self.encCipher = ARC4.new(self.enc_key, nonce=self.nonce)
            self.decCipher = ARC4.new(self.enc_key, nonce=self.nonce)

        elif(CIPHER == "AES-CBC-NoPadding" or CIPHER == "AES-CBC-PKCS5Padding"):
            self.encCipher = AES.new(
                self.enc_key, AES.MODE_CBC, iv=IV)
            self.decCipher = AES.new(
                self.enc_key, AES.MODE_CBC, iv=IV)

        elif(CIPHER == "AES-CFB8-NoPadding" or CIPHER == "AES-CFB8-PKCS5Padding"):
            self.encCipher = AES.new(
                self.enc_key, AES.MODE_CFB, iv=IV, segment_size=8)
            self.decCipher = AES.new(
                self.enc_key, AES.MODE_CFB, iv=IV, segment_size=8)

        # PyCryptoDome não permite segment_size = 1 para CFB-1
        elif(CIPHER == "AES-CFB-NoPadding"):
            self.encCipher = AES.new(
                self.enc_key, AES.MODE_CFB, iv=IV, segment_size=8)
            self.decCipher = AES.new(
                self.enc_key, AES.MODE_CFB, iv=IV, segment_size=8)

        self.nrseq = 0


def encData(client, message):
    if(CIPHER == "AES-CTR-NoPadding" or CIPHER == "RC4" or CIPHER == "AES-CFB8-NoPadding" or CIPHER == "AES-CFB-NoPadding"):
        return client.encCipher.encrypt(message)
    elif(CIPHER == "AES-CBC-NoPadding"):
        return client.encCipher.encrypt(pad(message, 16))
    elif(CIPHER == "AES-CBC-PKCS5Padding" or CIPHER == "AES-CFB8-PKCS5Padding"):
        return client.encCipher.encrypt(pad(message, 16))


def decData(client, ciphertext):
    if(CIPHER == "AES-CTR-NoPadding" or CIPHER == "RC4" or CIPHER == "AES-CFB8-NoPadding" or CIPHER == "AES-CFB-NoPadding"):
        return client.decCipher.decrypt(ciphertext)
    elif(CIPHER == "AES-CBC-NoPadding"):
        return unpad(client.decCipher.decrypt(ciphertext), 16)
    elif(CIPHER == "AES-CBC-PKCS5Padding" or CIPHER == "AES-CFB8-PKCS5Padding"):
        return unpad(client.decCipher.decrypt(ciphertext), 16)


def make_json(client, ciphertext_bytes):
    # b64 encode becuz of weird characters
    ciphertext = b64encode(ciphertext_bytes).decode(CHARSET)
    nonce = b64encode(client.nonce).decode(CHARSET)

    return json.dumps({'nonce': nonce, 'ciphertext': ciphertext})


def parse_json(data_rcv):
    rcv_json = json.loads(data_rcv)

    ciphertext = b64decode(rcv_json['ciphertext'])
    nonce = b64decode(rcv_json['nonce'])

    return ciphertext, nonce


def Main():
    # Local host IP '127.0.0.1'
    host = '127.0.0.1'
    # Define the port on which you want to connect
    port = 9999

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to server on local computer
    s.connect((host, port))
    client = Client(NONCE)
    message = s.recv(2048)
    print('Received the following greeting message: ' + str(message) + '\n')

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

        message = message.encode(CHARSET)
        ciphertext = encData(client, message)

        # Create json file
        result = make_json(client, ciphertext)

        # Message sent to server
        s.send(result.encode(CHARSET))

        # Message received from server
        data_rcv = s.recv(2048)
        try:
            ciphertext, client.nonce = parse_json(data_rcv)
            # Decode the json received
            message = decData(client, ciphertext)
        except ValueError | KeyError as e:
            print('Error in decryption')

        # Print the received message
        print('Received from the server: ' +
              str(message.decode(CHARSET)) + '\n')
        client.nrseq = client.nrseq + 1

    # Close the connection
    s.close()


if __name__ == '__main__':
    Main()
