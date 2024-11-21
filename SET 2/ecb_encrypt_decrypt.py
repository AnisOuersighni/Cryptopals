from Padding import padder,unpadder

from os import urandom

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()

# ECB is the almost the implementation for AES, input(key,Pn)  and output(Cn)  each one treated indepedantly and with update() and finalize() we make the treatement on the whole string/cipher

def ecb_encrypt_aes_128_block(msg, key):
    '''unpadded AES block encryption'''
    msg_padded = padder(msg)
    if len(key) not in (16, 24, 32):
        raise ValueError("Key length must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256.")
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(msg_padded) + encryptor.finalize()

def ecb_decrypt_aes_128_block(ctxt, key):
    if len(key) not in (16, 24, 32):
        raise ValueError("Key length must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256.")
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data =  decryptor.update(ctxt) + decryptor.finalize()
    return unpadder(decrypted_data)



# so with this function we need a message of **exactly** 128 bits (16 Bytes)
msg = urandom(32)
key = urandom(16)
ctxt = ecb_encrypt_aes_128_block(msg, key)
msg_2 = ecb_decrypt_aes_128_block(ctxt, key)



#print(msg,"\n")
#print(msg_padded,"\n")
#print(ctxt,"\n")
#print(msg_2,"\n")
#print(msg_padded == msg_2) #true