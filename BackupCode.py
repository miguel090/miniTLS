class Oracle:
    def __init__(self, cipher, key, mode='', nonce=b'', padding=''):
        if (cipher == AES):
            self.cipher = AES.new(key, mode, nonce)
        elif (cipher == ARC4):
            self.cipher = ARC4.new(key)

        self.key = key
        self.mode = mode
        self.nonce = nonce
        self.padding = padding

    def encrypt(self, message):
        return self.cipher.encrypt(message)

    def decrypt(self, message):
        return self.cipher.decrypt(message)


class MessageAuthentication:
    def __init__(self, key, digestmod):
        self.key = key
        self.digestmod = digestmod
        self.hmac = HMAC.new(key, digestmod=digestmod)

    def authenticate(self, ciphertext):
        self.hmac.update(ciphertext)
        return self.hmac.digest()

    def verify(self, mac, ciphertext):
        self.hmac.update(ciphertext)
        try:
            # need to transform from hexadecimal bytes to hexadecimal string
            self.hmac.hexverify(mac.hex())
            print('MAC is good.')
        except ValueError as e:
            print('MAC with error.')
            return 1

        return 0
