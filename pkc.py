from Crypto.PublicKey import *
from random import randint
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import json
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes

class Diffie_Hellman:
    def __init__(self, p=None, g=None):
        self.p = p
        self.g = g
        # don't set vals of key or x and y yet
        self.key = None
        self.secret_x = None
        self.public_received = None
        self.public_sent = None
        # used for MITM attack
        self.intercepted_a = None 
        self.intercepted_b = None 
        self.key_a = None
        self.key_b = None

    """ sends p and g to user and initializes their values """
    def send_p_g(self, user):
        user.p = self.p
        user.g = self.g

    def set_x(self):
        self.secret_x = randint(1, self.p - 1)

    """ sends g^x mod p to user """
    def send_public(self, user):
        self.public_sent = pow(self.g, self.secret_x, self.p)
        user.public_received = self.public_sent

    """ MITM Attack, will store what they intercepted into intercepted_x """
    def send_modified(self, user, x):
        if x == 'a':
            self.intercepted_a = self.public_received
        else:
            self.intercepted_b = self.public_received
        self.public_sent = pow(self.g, self.secret_x, self.p) # uses own x
        user.public_received = self.public_sent
        
    """ creates the shared key """
    def get_key(self):
        s = pow(self.public_received, self.secret_x, self.p)
        sha = SHA256.new(bytes(str(s), 'utf-8'))
        self.key = sha.digest()
        self.key = self.key[:16]
    
    """ MITM Attack to get key between each x user """
    def MITM_get_key(self, x):
        if x == 'a':
            s = pow(self.intercepted_a, self.secret_x, self.p)
            sha = SHA256.new(bytes(str(s), 'utf-8'))
            self.key_a = sha.digest()
            self.key_a = self.key_a[:16]
        else:
            s = pow(self.intercepted_b, self.secret_x, self.p)
            sha = SHA256.new(bytes(str(s), 'utf-8'))
            self.key_b = sha.digest()
            self.key_b = self.key_b[:16]

def main():
    p = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6\
9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0\
13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70\
98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0\
A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708\
DF1FB2BC2E4A4371"
    p = int(p, 16)
    g = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F\
D6406CFF14266D31266FEA1E5C41564B777E690F5504F213\
160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1\
909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A\
D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24\
855E6EEB22B3B2E5"
    g = g.strip(" ")
    g = int(g, 16)

    alice = Diffie_Hellman(p, g)
    bob = Diffie_Hellman()
    mallory = Diffie_Hellman()
    #alice.send_p_g(bob)
    
    # MITM
    alice.send_p_g(mallory)
    mallory.send_p_g(bob)
    #

    alice.set_x()
    #alice.send_public(bob)

    # MITM
    alice.send_public(mallory)
    mallory.set_x()
    mallory.send_modified(bob, "a") # intercepted a, send modified to bob
    #

    bob.set_x()
    #bob.send_public(alice)

    # MITM
    bob.send_public(mallory)
    mallory.send_modified(alice, "b") # intercepted b, send modified to alice
    mallory.MITM_get_key("a") # sets mallory's a key to match alice's key
    mallory.MITM_get_key("b") # sets mallory's b key to match bob's key
    #

    alice.get_key()
    bob.get_key()
    print(alice.key)
    print(mallory.key_a)
    print(bob.key)
    print(mallory.key_b)

    mA = b"Hi Bob!"
    mB = b"Hi Alice!"

    ctA = createCipherText(mA, alice.key)
    ctB = createCipherText(mB, bob.key)

    #decryptCipherText(bob.key, ctA)
    #decryptCipherText(alice.key, ctB)

    # MITM
    ptA = decryptCipherText(mallory.key_a, ctA) # decrypt alice's message for bob
    ptB = decryptCipherText(mallory.key_b, ctB) # dc bob's message for alice
    ctForBob = createCipherText(ptA, mallory.key_b) # ec alice's msg for bob w/ mallory's key that matches bob's
    ctForAlice = createCipherText(ptB, mallory.key_a) #  ec bob's msg for alice w/ mallory's key that matches alice's
    #

    decryptCipherText(bob.key, ctForBob)
    decryptCipherText(alice.key, ctForAlice)

def createCipherText(bytes_msg, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(bytes_msg, AES.block_size))

    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})
    #print(result)
    return result

def decryptCipherText(key, json_input):
    try:
        b64 = json.loads(json_input)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        print("The message was: ", pt)
        return pt
    except (ValueError, KeyError):
        print("Incorrect decryption")

if __name__ == "__main__":
    main()