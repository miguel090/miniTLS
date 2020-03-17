
# Import socket module
import socket
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, ARC4
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

charset = 'utf-8'


def encData(cipher, message):
    return cipher.encrypt(message)


def decData(cipher, ciphertext):
    return cipher.decrypt(ciphertext)


def make_auth(hmac, ciphertext):
    hmac.update(ciphertext)
    return hmac.digest()


def verify_auth(hmac, ciphertext, mac):
    hmac.update(ciphertext)
    try:
        # need to transform from hexadecimal bytes to hexadecimal string
        hmac.hexverify(mac.hex())
        print('MAC is good.')
    except ValueError as e:
        print('MAC with error.')
        return 1

    return 0


def make_json(ciphertext_bytes, nonce, mac):
    # b64 encode becuz of weird characters
    ciphertext = b64encode(ciphertext_bytes).decode(charset)
    nonce = b64encode(nonce).decode(charset)
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
    sessionKey = s.recv(32)
    print('Received the following session key: ' + str(sessionKey) + '\n')

    enc_key = SHA256.new(data=sessionKey + b'1').digest()
    auth_key = SHA256.new(data=sessionKey + b'2').digest()

    encCipher = AES.new(enc_key, AES.MODE_CTR, nonce=b'1234')
    decCipher = AES.new(enc_key, AES.MODE_CTR, nonce=b'1234')
    ehmac = HMAC.new(auth_key, digestmod=SHA256)
    dhmac = HMAC.new(auth_key, digestmod=SHA256)

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
        ciphertext = encData(encCipher, message)

        mac = make_auth(ehmac, message)

        # Create json file
        result = make_json(ciphertext, encCipher.nonce, mac)

        # Message sent to server
        s.send(result.encode(charset))

        # Message received from server
        data_rcv = s.recv(2048)
        try:
            ciphertext, nonce, mac = parse_json(data_rcv)
            # Decode the json received
            message = decData(decCipher, ciphertext)
        except ValueError | KeyError as e:
            print('Error in decryption')

        # Validate mac
        if verify_auth(dhmac, message, mac) != 0:
            print("Security error. Closing connection")
            break

        # Print the received message
        print('Received from the server: ' +
              str(message.decode(charset)) + '\n')

    # Close the connection
    s.close()


if __name__ == '__main__':
    Main()
