
# Import socket module
import socket
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, ARC4
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

KEY = b'abcdef'
NONCE = b'1234'
CHARSET = 'utf-8'


class Client:
    def __init__(self, nonce):
        self.nonce = nonce
        self.enc_key = SHA256.new(data=KEY).digest()

        self.encCipher = AES.new(self.enc_key, AES.MODE_CTR, nonce=nonce)
        self.decCipher = AES.new(self.enc_key, AES.MODE_CTR, nonce=nonce)

        self.nrseq = 0


def encData(client, message):
    return client.encCipher.encrypt(message)


def decData(client, ciphertext):
    return client.decCipher.decrypt(ciphertext)


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
