# Import socket module
import socket
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, ARC4
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
        system("openssl dsaparam -outform DER -in parameters2.pem -out parameters2.der")
        with open("parameters2.der", "rb") as f:
            certs = f.read()
        params = DSAParams.load(certs)
        self.p = int(params['p'])
        self.q = int(params['q'])
        self.g = int(params['g'])
        f.close()


class Client:
    def __init__(self):
        self.nonce = b'1234'

        key = Key()
        self.client_secret = randrange(0, key.q - 1)
        self.shared_prime = key.p
        self.shared_base = key.g
        self.client_DHside = pow(self.shared_base, self.client_secret, self.shared_prime)

        # everything is set after establishing session key
        self.sessionKey = 0
        self.enc_key = 0
        self.auth_key = 0
        self.clientnr = 0

        self.encCipher = 0
        self.decCipher = 0
        self.ehmac = 0
        self.dhmac = 0

        self.nrseq = 0


def establish_session_key(s, client):
    # print("client_DHside: " + str(client.client_DHside))
    s.send(str(client.client_DHside).encode(charset))

    server_DHside_signature_clientnr = s.recv(4096)
    # print("server_DHside: " + str(server_DHside))
    server_DHside, encrypted_json = get_server_DHside_and_encrypted_json(server_DHside_signature_clientnr)
    sessionKey = pow(server_DHside, client.client_secret, client.shared_prime)
    client.sessionKey = str(sessionKey).encode(charset)
    set_keys(client)

    signed_hash_json = dec_data(client, encrypted_json).decode(charset)
    client.clientnr, signed_hash = get_clientnr_and_hash_from_json(signed_hash_json)
    #print(signed_hash)
    hashed_values, validity = verify_hash(client, signed_hash, server_DHside)
    if validity == False:
        return False
    create_asymetric_key_files(client.clientnr)

    signed_hash = sign_DHvalues(client, hashed_values)
    message_to_send = enc_data(client, signed_hash)
    message_to_send = b64encode(message_to_send)
    s.send(message_to_send)
    # print(client.sessionKey)
    return True


def sign_DHvalues(client, hashed_values):
    f = open(str(client.clientnr) + '_private_key.pem')
    key = ECC.import_key(f.read())

    signer = DSS.new(key, 'fips-186-3')
    signed_hash = signer.sign(hashed_values)

    return signed_hash


def verify_hash(client, signed_hash, server_DHside):
    verify_values = json.dumps({'gy': str(server_DHside), 'gx': str(client.client_DHside)})
    hash_to_verify = SHA256.new(verify_values.encode(charset))

    #print('hashed values: ' + hash_to_verify.hexdigest())
    #print('signed value: ' + str(signed_hash))
    f = open('server_public_key.pem')
    key = ECC.import_key(f.read())

    verifier = DSS.new(key, 'fips-186-3')
    try:
        verifier.verify(hash_to_verify, signed_hash)
        #print("verified signature")
        return hash_to_verify, True
    except ValueError:
        print("The message signature couldnt be validated")
        return hash_to_verify, False


def get_clientnr_and_hash_from_json(signed_hash_json):
    rcv_json = json.loads(signed_hash_json)
    return rcv_json['clientnr'], b64decode(rcv_json['signature'])


def get_server_DHside_and_encrypted_json(server_DHside_signature_clientnr):
    rcv_json = json.loads(server_DHside_signature_clientnr)
    return int(rcv_json['gy']), b64decode(rcv_json['encrypted_signed'])


def set_keys(client):
    client.enc_key = SHA256.new(data=client.sessionKey + b'1').digest()
    client.auth_key = SHA256.new(data=client.sessionKey + b'2').digest()

    client.encCipher = AES.new(client.enc_key, AES.MODE_CTR, nonce=client.nonce)
    client.decCipher = AES.new(client.enc_key, AES.MODE_CTR, nonce=client.nonce)
    client.ehmac = HMAC.new(client.auth_key, digestmod=SHA256)
    client.dhmac = HMAC.new(client.auth_key, digestmod=SHA256)


def enc_data(client, message):
    return client.encCipher.encrypt(message)


def dec_data(client, ciphertext):
    return client.decCipher.decrypt(ciphertext)

def make_auth(client, ciphertext):
    # add sequence number to ciphertext
    ciphertext = ciphertext + bytes(client.nrseq)
    client.ehmac.update(ciphertext)
    return client.ehmac.digest()


def verify_auth(client, ciphertext, mac):
    # add sequence number to ciphertext
    ciphertext = ciphertext + bytes(client.nrseq)
    client.dhmac.update(ciphertext)
    try:
        # need to transform from hexadecimal bytes to hexadecimal string
        client.dhmac.hexverify(mac.hex())
        #print('MAC is good.')
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
    if establish_session_key(s, client) == False:
        print("There was an error estabilishing the key")
        s.send("Couldnt establish shared key".encode(charset))
        return

    #print('Received the following session key: ' + str(client.sessionKey) + '\n')
    message = s.recv(2048)
    print('Received the following greeting message: ' + str(message) + '\n')
    #reset keys so values coincide again
    set_keys(client)
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
        ciphertext = enc_data(client, message)

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
            message = dec_data(client, ciphertext)
            #print(message)
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


def create_asymetric_key_files(client_nr):
    key = ECC.generate(curve='P-256')

    f = open(str(client_nr) + '_private_key.pem', 'wt')
    f.write(key.export_key(format='PEM'))
    f.close()

    f = open(str(client_nr) + '_public_key.pem', 'wt')
    f.write(key.export_key(format='PEM'))
    f.close()


if __name__ == '__main__':
    Main()
