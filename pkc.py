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

    """ sends p and g to user and initializes their values """
    def send_p_g(self, user):
        user.p = self.p
        user.g = self.g

    """ sends g^x mod p to user """
    def send_public(self, user):
        self.secret_x = randint(1, self.p - 1)
        self.public_sent = (self.g ** self.secret_x) % self.p
        user.public_received = self.public_sent

    """ creates the shared key """
    def get_key(self):
        s = (self.public_received ** self.secret_x) % self.p
        sha = SHA256.new(bytes(str(s), 'utf-8'))
        self.key = sha.digest()
        self.key = self.key[:16]



def main():
    # p = "B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 \
    #      9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0 \
    #      13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70 \
    #      98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0 \
    #      A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708 \
    #      DF1FB2BC 2E4A4371"
    # p = int(p, 16)
    
    # g = "A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F \
    #      D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213 \
    #      160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1 \
    #      909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A \
    #      D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24 \
    #      855E6EEB 22B3B2E5"
    # g = int(g, 16)

    alice = Diffie_Hellman(37, 5)
    bob = Diffie_Hellman()
    alice.send_p_g(bob)
    alice.send_public(bob)
    bob.send_public(alice)
    alice.get_key()
    bob.get_key()
    print(alice.key)
    print(bob.key)

    mA = b"Hi Bob!"
    mB = b"Hi Alice!"

    ctA = createCipherText(mA, alice.key)
    ctB = createCipherText(mB, bob.key)

    decryptCipherText(bob.key, ctA)
    decryptCipherText(alice.key, ctB)

def createCipherText(bytes_msg, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(bytes_msg, AES.block_size))

    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})
    print(result)
    return result

def decryptCipherText(key, json_input):
    try:
        b64 = json.loads(json_input)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        print("The message was: ", pt)
    except (ValueError, KeyError):
        print("Incorrect decryption")

if __name__ == "__main__":
    main()