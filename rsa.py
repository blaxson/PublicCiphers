from Crypto.Util.number import *
from random import randint
from Crypto.Hash import SHA256
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class Person:
    def __init__(self, public_key=None, private_key=None, others_pk=None):
        self.public_key = public_key
        self.private_key = private_key
        self.others_public_key = others_pk
        self.s = None
        self.c = None
        self.sym_key = None
        self.cipher = None
        self.message = None

    def send_public_key(self, user):
        user.others_public_key = self.public_key
        
    def send_encrypted_s(self, user):
        self.s = randint(1, self.others_public_key[1] - 1)
        c = pow(self.s, self.others_public_key[0], self.others_public_key[1])
        user.c = c
        
    def recv_decrypted_s(self):
        s = pow(self.c, self.private_key[0], self.private_key[1])
        self.s = s

    def generateSymKey(self):
        sha = SHA256.new(bytes(str(self.s), 'utf-8')) 
        key = sha.digest()
        self.sym_key = key[:16]

    """ F function that is used by attacker to manipulate cipher key, sends 
        1 to user as c because 1^d mod n = 1... modular exploit """
    def F(self, user):
        self.s = 1
        self.c = 1
        user.c = 1
    
    def send_message(self, user, m):
        cipher = AES.new(self.sym_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(m, AES.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'iv':iv, 'ciphertext':ct})
        #print(result)
        user.cipher = result
    
    def recv_message(self):
        try:
            b64 = json.loads(self.cipher)
            iv = b64decode(b64['iv'])
            ct = b64decode(b64['ciphertext'])
            cipher = AES.new(self.sym_key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            #print("The message was: ", pt)
            self.message = pt
        except (ValueError, KeyError):
            print("Incorrect decryption")


class RSA:
    def __init__(self):
        self.p = getPrime(512) # 512 bit prime number
        self.q = getPrime(512)
        self.p = 17
        self.q = 11
        self.n = self.p*self.q
        self.theta_n = (self.p-1)*(self.q-1)
        #self.e = getStrongPrime(512, self.theta_n) # 512 bit coprime number
        #e = 65537
        
        self.e = 7

        
        self.d = self.modular_inverse(self.e, self.n, self.theta_n)


        self.public_key = (self.e, self.n)
        self.private_key = (self.d, self.n)
        print(self.public_key)
        print(self.private_key)

    def modular_inverse(self, e, n, theta_n):
        for d in range(1, n + 1):
            if (e * d) % theta_n == 1:
                return d
        return None

    def encrypt(self, m):
        c = pow(m, self.e, self.n)
        return c
        
    def decrypt(self, c):
        m = pow(c, self.d, self.n)
        return m





def main():
    rsa = RSA()
    alice = Person(rsa.public_key, rsa.private_key)
    bob = Person()
    mallory = Person()
    alice.send_public_key(bob) # sends public key to bob
    alice.send_public_key(mallory)

    """
    bob.send_encrypted_s(alice)
    alice.recv_decrypted_s()
    """

    # MITM
    bob.send_encrypted_s(mallory)
    mallory.F(alice)
    alice.recv_decrypted_s()
    alice.generateSymKey()
    mallory.generateSymKey()
    alice.send_message(mallory, b'hi there bob')
    mallory.recv_message()
    print(mallory.message)

    

if __name__ == '__main__':
    main()