from .crack_4 import crack_4
from .crack_3 import crack_3

def crack(ciphertext, plaintext=None):
    if plaintext:
        return crack_3(plaintext=plaintext, ciphertext=ciphertext)
    else:
        return crack_4(ciphertext=ciphertext)
