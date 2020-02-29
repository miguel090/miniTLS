
# Import socket module
import socket
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

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
    #key = get_random_bytes(32)

    # message you send to server
    while True:

        message=input()
        if message=='' : continue
        message = message.encode('utf-8')
        #create AES object and encrypt
        AESenc = AES.new(b'This is a key123', AES.MODE_CTR)
        ciphertext_bytes = AESenc.encrypt(message)
        ciphertext = b64encode(ciphertext_bytes).decode('utf-8')
        nonce = b64encode(AESenc.nonce).decode('utf-8')
        #create json file
        result = json.dumps({'nonce':nonce, 'ciphertext':ciphertext})
        # message sent to server
        s.send(result.encode('utf-8'))

        # messaga received from server
        data = s.recv(1024)
        rcv_json = json.loads(data)
        nonce= b64decode(rcv_json['nonce'])
        ciphertext= b64decode(rcv_json['ciphertext'])
        AESdec = AES.new(b'This is a key123', AES.MODE_CTR, nonce=nonce)
        message = AESdec.decrypt(ciphertext)

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
