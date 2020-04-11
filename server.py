#!/usr/bin/env python

import socket
import threading
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random.random import randrange
from Crypto.Hash import HMAC, SHA256

class Key:
    def __init__(self):
        self.p=673903887833553591611992317553943076492624442040299397496340559052122790218081892328387568714604018125875041083390606438662925710721182633447664365606242254112761994560581106879023501656831238170438855681080126881495920577132194837672155075947573127193499150645403600201067733394892442630047702867736851753803443708618531260710606909641165879490043439452835550747679886090652900552538360692720998577281680781912518797411462336094579249260902925191819964318816310215187575904741769134306309657469579380531052968797558998763015423812253540191632574409101760533068985393812623916102102883753256734594226297695457820178484438166814344107077166263594055925810351618810988984360251727602557285967694877917116562764227014930421352426715083768208206614085051639901147418819692068979189456377529219029841082433586324532943918728607886762329833702122646517536013058074485446308428453890804503893248820187467344627894091576935678675784975247034908431180955270103919050129592216647944224295182666285605292908760968784654217813967927185584307055747121789999034994974226230595332097995722202475949957184456670144855770718110366329072454079173187755439048413608796917813488761441918318575114911965333868577552561988102051977164188742465082813320859
        self.q= 64248947059182511824089548949218439125267141577560023720486122199750960835313
        self.g=541272959318098048064392370092354561852283494302818288435012464176468019260493532618107071785965274971652252737853457082883251899610920546491827905200120127723438625950663531255085317779858758285614930758770182003104417189465166750559232593672389754541657683126926089891070843746673578143574108125278657544619676129896981855319913460315802123419232941049977931771833331612489334817807704227330510917550950719439430286557336845311677701158183072331320143485206958356382068409501262344153857238285905597066922436515282612926075131146725951947975204390303223859753403653717925392154622948513386446899541541721566744919634659109823672719912560870983584546223111103336541698760709643464933239972861514219827969333732369848233325022614293911449904449969246725624546439618919138834509705385783386949321357060720319942313172319373524863871444407280214755064218900714005345882924348930240750013910091315361589546887725313399309124378326065706201011755828412106601224660844730895925090530556915588239751309656723652972471715876083875917859714575393557644410109818748732394379226910621218602510027210203058335804091575391961708816651140526711459023050593977013122896904471987752438242176104394201151729631670024604038744882947556633090477310679

class ClientThread(threading.Thread):

    def __init__(self, ip, port, clientsocket):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.csocket = clientsocket
        self.charset = 'utf-8'
        self.nonce = b'1234'
        self.nrseq = 0

        key=Key()
        self.server_secret = randrange(0,key.q-1)
        self.shared_prime = key.p
        self.shared_base= key.g
        self.server_public_key= pow(self.shared_base, self.server_secret, self.shared_prime)

        self.sessionKey = 0
        self.enc_key = 0
        self.auth_key = 0

        self.enc = 0
        self.dec = 0
        self.ehmac = 0
        self.dhmac = 0

        print("[+] New thread started for " + ip + ":" + str(port))

    def estabilish_session_key(self):
        #print('server_public_key: ' + str(self.server_public_key))
        client_public_key=self.csocket.recv(4096)
        #print('client_public_key: ' + str(client_public_key))
        client_public_key=int(client_public_key.decode('utf-8'))

        self.csocket.send(str(self.server_public_key).encode('utf-8'))
        self.sessionKey= pow(client_public_key, self.server_secret, self.shared_prime)
        #print(self.sessionKey)
        self.sessionKey=str(self.sessionKey).encode('utf-8')
        self.set_keys()

    def set_keys(self):
        self.enc_key = SHA256.new(data=self.sessionKey + b'1').digest()
        self.auth_key = SHA256.new(data=self.sessionKey + b'2').digest()

        self.enc = AES.new(self.enc_key, AES.MODE_CTR, nonce=self.nonce)
        self.dec = AES.new(self.enc_key, AES.MODE_CTR, nonce=self.nonce)
        self.ehmac = HMAC.new(self.auth_key, digestmod=SHA256)
        self.dhmac = HMAC.new(self.auth_key, digestmod=SHA256)

    def encData(self, message):
        return self.enc.encrypt(message)


    def decData(self, ciphertext):
        return self.dec.decrypt(ciphertext)


    def make_auth(self, mac, ciphertext):
        self.ehmac.update(ciphertext)
        return self.ehmac.digest()


    def verify_auth(self, ciphertext, mac):
        #add sequence number to ciphertext
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
        self.estabilish_session_key()
        print("Session key for " + self.ip + ":" +
              str(self.port) + ": " + str(self.sessionKey))

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
            self.nrseq = self.nrseq + 1

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
