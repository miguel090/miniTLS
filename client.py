
# Import socket module
import socket
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

def encData(message, enc_key):
    #create AES object and encrypt
    AESenc = AES.new(enc_key, AES.MODE_CTR)
    ciphertext = AESenc.encrypt(message)

    return ciphertext, AESenc.nonce

def decData(ciphertext, nonce, enc_key):
    AESdec = AES.new(enc_key, AES.MODE_CTR, nonce=nonce)
    return AESdec.decrypt(ciphertext)

def make_auth(ciphertext, auth_key):
    h = HMAC.new(auth_key, digestmod=SHA256)
    h.update(ciphertext)
    return h.digest()

def verify_auth(mac, msg, auth_key):
    h = HMAC.new(auth_key, digestmod=SHA256)
    h.update(msg)
    try:
        #need to transform from hexadecimal bytes to hexadecimal string
        h.hexverify(mac.hex())
        print('mac is good')
    except ValueError as e:
        print('major error')
    return

def make_json(ciphertext_bytes, nonce, mac):
    #b64 encode becuz of weird characters
    ciphertext = b64encode(ciphertext_bytes).decode('utf-8')
    nonce = b64encode(nonce).decode('utf-8')
    mac = b64encode(mac).decode('utf-8')
    return json.dumps({'nonce':nonce, 'ciphertext':ciphertext, 'mac':mac})

def parse_json(data_rcv):
    rcv_json = json.loads(data_rcv)
    ciphertext= b64decode(rcv_json['ciphertext'])
    nonce= b64decode(rcv_json['nonce'])
    mac = b64decode(rcv_json['mac'])
    return ciphertext, nonce, mac
    
def Main():
    # local host IP '127.0.0.1'
    host = '127.0.0.1'

    # Define the port on which you want to connect
    port = 9999

    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    # connect to server on local computer
    s.connect((host,port))
    data = s.recv(1024)
    print(data.decode('utf-8'))
    enc_key = b'aaaaatadinhadela'#get_random_bytes(32)
    auth_key= b'tadinhadelaaaaaa'#get_random_bytes(32)
    # message you send to server
    while True:

        message=input()
        if message=='' : continue
        message = message.encode('utf-8')
        #encrypt data with AES-CTR mode
        ciphertext, nonce = encData(message, enc_key)
        mac = make_auth(message, auth_key)
        #create json file
        result = make_json(ciphertext, nonce, mac)
        # message sent to server
        s.send(result.encode('utf-8'))

        # message received from server
        data_rcv = s.recv(1024)
        try:
            ciphertext ,nonce ,mac= parse_json(data_rcv)
            #decode the json received
            message = decData(ciphertext, nonce, enc_key)
        except ValueError | KeyError as e:
            print('error in decrtytion')

        #validate mac
        verify_auth(mac, message, auth_key)
        # print the received message
        print('Received from the server :',str(message.decode('utf-8')))

        if message != 'quit':
            continue
        else:
            break
    # close the connection
    s.close()

if __name__ == '__main__':
    Main()
