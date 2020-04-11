
# Import socket module
import socket
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, ARC4
from Crypto.Random.random import randrange
from Crypto.Hash import HMAC, SHA256


charset = 'utf-8'
class Key:
    def __init__(self):
        self.p=673903887833553591611992317553943076492624442040299397496340559052122790218081892328387568714604018125875041083390606438662925710721182633447664365606242254112761994560581106879023501656831238170438855681080126881495920577132194837672155075947573127193499150645403600201067733394892442630047702867736851753803443708618531260710606909641165879490043439452835550747679886090652900552538360692720998577281680781912518797411462336094579249260902925191819964318816310215187575904741769134306309657469579380531052968797558998763015423812253540191632574409101760533068985393812623916102102883753256734594226297695457820178484438166814344107077166263594055925810351618810988984360251727602557285967694877917116562764227014930421352426715083768208206614085051639901147418819692068979189456377529219029841082433586324532943918728607886762329833702122646517536013058074485446308428453890804503893248820187467344627894091576935678675784975247034908431180955270103919050129592216647944224295182666285605292908760968784654217813967927185584307055747121789999034994974226230595332097995722202475949957184456670144855770718110366329072454079173187755439048413608796917813488761441918318575114911965333868577552561988102051977164188742465082813320859
        self.q= 64248947059182511824089548949218439125267141577560023720486122199750960835313
        self.g=541272959318098048064392370092354561852283494302818288435012464176468019260493532618107071785965274971652252737853457082883251899610920546491827905200120127723438625950663531255085317779858758285614930758770182003104417189465166750559232593672389754541657683126926089891070843746673578143574108125278657544619676129896981855319913460315802123419232941049977931771833331612489334817807704227330510917550950719439430286557336845311677701158183072331320143485206958356382068409501262344153857238285905597066922436515282612926075131146725951947975204390303223859753403653717925392154622948513386446899541541721566744919634659109823672719912560870983584546223111103336541698760709643464933239972861514219827969333732369848233325022614293911449904449969246725624546439618919138834509705385783386949321357060720319942313172319373524863871444407280214755064218900714005345882924348930240750013910091315361589546887725313399309124378326065706201011755828412106601224660844730895925090530556915588239751309656723652972471715876083875917859714575393557644410109818748732394379226910621218602510027210203058335804091575391961708816651140526711459023050593977013122896904471987752438242176104394201151729631670024604038744882947556633090477310679

class Client:
    def __init__(self):
        self.nonce = b'1234'
        self.sessionKey = 0
        self.enc_key = 0
        self.auth_key = 0

        key = Key()
        self.client_secret = randrange(0,key.q-1)
        self.shared_prime = key.p
        self.shared_base=key.g
        self.client_public_key= pow(self.shared_base, self.client_secret, self.shared_prime)

        self.encCipher = 0
        self.decCipher = 0
        self.ehmac = 0
        self.dhmac = 0

        self.nrseq = 0

def estabilish_session_key(s, client):
    #print("client_public_key: " + str(client.client_public_key))
    s.send(str(client.client_public_key).encode(charset))

    server_public_key = s.recv(4096)
    #print("server_public_key: " + str(server_public_key))
    server_public_key = int(server_public_key.decode(charset))

    client.sessionKey = pow(server_public_key, client.client_secret, client.shared_prime)
    #print(client.sessionKey)
    client.sessionKey= str(client.sessionKey).encode(charset)

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
