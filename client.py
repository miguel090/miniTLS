
# Import socket module
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
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
    print(data.decode('ascii'))
    #key = get_random_bytes(32)
    #iv = get_random_bytes(16)
    # message you send to server
    while True:

        message=input()
        message = message.encode('ascii')
        if message=='' : continue
        #create AES object
        AESenc = AES.new(b'This is a key123', AES.MODE_CBC, b'This is an IV456')
        ciphertext = AESenc.encrypt(pad(message,16))
        print(ciphertext)
        # message sent to server
        s.send(ciphertext)

        data = s.recv(1024)
        AESdec = AES.new(b'This is a key123', AES.MODE_CBC, b'This is an IV456')
        message = unpad(AESdec.decrypt(data), 16)
        # messaga received from server


        # print the received message
        # here it would be a reverse of sent message
        print('Received from the server :',str(message.decode('ascii')))

        if message != 'quit':
            continue
        else:
            break
    # close the connection
    s.close()

if __name__ == '__main__':
    Main()
