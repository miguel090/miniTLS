
# Import socket module
import socket
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, ARC4
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256


charset = 'utf-8'

class Client:
    def __init__(self):
        self.nonce = b'1234'
        self.sessionKey = 0
        self.enc_key = 0
        self.auth_key = 0

        self.client_secret =15
        self.shared_prime = 23
        self.shared_base=5
        self.client_public_key= pow(self.shared_base, self.client_secret, self.shared_prime)

        self.encCipher = 0
        self.decCipher = 0
        self.ehmac = 0
        self.dhmac = 0

        self.nrseq = 0

def estabilish_session_key(s, client):
    print("client_public_key: " + str(bytes([client.client_public_key])))
    s.send(bytes([client.client_public_key]))

    server_public_key = s.recv(100)
    print("server_public_key: " + str(server_public_key))
    server_public_key = int.from_bytes(server_public_key, byteorder='big')

    client.sessionKey = pow(server_public_key, client.client_secret, client.shared_prime)
    print(client.sessionKey)
    client.sessionKey= bytes([client.sessionKey])

    set_keys(client)


def set_keys(client):
    client.enc_key = SHA256.new(data=client.sessionKey + b'1').digest()
    client.auth_key = SHA256.new(data=client.sessionKey + b'2').digest()

    client.encCipher = AES.new(client.enc_key, AES.MODE_CTR, nonce=client.nonce)
    client.decCipher = AES.new(client.enc_key, AES.MODE_CTR, nonce=client.nonce)
    client.ehmac = HMAC.new(client.auth_key, digestmod=SHA256)
    client.dhmac = HMAC.new(client.auth_key, digestmod=SHA256)

def encData(client, message):
    return client.encCipher.encrypt(message)


def decData(client, ciphertext):
    return client.decCipher.decrypt(ciphertext)


def make_auth(client, ciphertext):
    #add sequence number to ciphertext
    ciphertext = ciphertext + bytes(client.nrseq)
    client.ehmac.update(ciphertext)
    return client.ehmac.digest()


def verify_auth(client, ciphertext, mac):
    #add sequence number to ciphertext
    ciphertext = ciphertext + bytes(client.nrseq)
    client.dhmac.update(ciphertext)
    try:
        # need to transform from hexadecimal bytes to hexadecimal string
        client.dhmac.hexverify(mac.hex())
        print('MAC is good.')
    except ValueError as e:
        print('MAC with error.')
        return 1

    return 0


def make_json(client, ciphertext_bytes, mac):
    # b64 encode becuz of weird characters
    ciphertext = b64encode(ciphertext_bytes).decode(charset)
    nonce = b64encode(client.nonce).decode(charset)
    mac = b64encode(mac).decode(charset)

    return json.dumps({'nonce': nonce, 'ciphertext': ciphertext, 'mac': mac})


def parse_json(data_rcv):
    rcv_json = json.loads(data_rcv)

    ciphertext = b64decode(rcv_json['ciphertext'])
    nonce = b64decode(rcv_json['nonce'])
    mac = b64decode(rcv_json['mac'])

    return ciphertext, nonce, mac


def Main():
    # Local host IP '127.0.0.1'
    host = '127.0.0.1'
    # Define the port on which you want to connect
    port = 9999

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to server on local computer
    s.connect((host, port))

    client = Client()
    estabilish_session_key(s, client)
    print('Received the following session key: ' + str(client.sessionKey) + '\n')
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

        message = message.encode(charset)
        ciphertext = encData(client, message)

        mac = make_auth(client, message)

        # Create json file
        result = make_json(client, ciphertext, mac)

        # Message sent to server
        s.send(result.encode(charset))

        # Message received from server
        data_rcv = s.recv(2048)
        try:
            ciphertext, client.nonce, mac = parse_json(data_rcv)
            # Decode the json received
            message = decData(client, ciphertext)
        except ValueError | KeyError as e:
            print('Error in decryption')

        # Validate mac
        if verify_auth(client, message, mac) != 0:
            print("Security error. Closing connection")
            break

        # Print the received message
        print('Received from the server: ' +
              str(message.decode(charset)) + '\n')
        client.nrseq = client.nrseq + 1

    # Close the connection
    s.close()


if __name__ == '__main__':
    Main()
