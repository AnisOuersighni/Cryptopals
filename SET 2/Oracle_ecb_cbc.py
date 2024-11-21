from ecb_encrypt_decrypt import ecb_decrypt_aes_128_block, ecb_encrypt_aes_128_block
from cbc_encrypt_decrypt import cbc_decrypt_aes_128,cbc_encrypt_aes_128
from detect_ecb import has_repeated_blocks

from random import choice,randint
from os import urandom

def Oracle_ecb_cbc(plaintext,mode=None):
    # Generate a random 128-bit key
    key = urandom(16)
    before = urandom(randint(5,10))
    after = urandom(randint(5,10))


    if isinstance(plaintext,str):
        plaintext = plaintext.encode('utf-8')
    elif isinstance(plaintext,hex):
        plaintext = bytes.fromhex(plaintext)
    elif not isinstance(plaintext,bytes):
        raise ValueError("plaintext must be a string, bytes or hex")
    
    plaintext = before + plaintext + after

    if mode ==None:
        mode=choice(["ECB","CBC"])

    if mode == "ECB":
        # Encrypt the plaintext using ECB mode
        ciphertext = ecb_encrypt_aes_128_block(plaintext, key)
        return ciphertext,mode
    elif mode =="CBC":
        # Encrypt the plaintext using CBC mode
        iv = urandom(16)
        ciphertext = cbc_encrypt_aes_128(plaintext, key, iv)
        return ciphertext,mode
    else:
        return "Invalid mode"

def testing_mode(ciphertext):
    # Check if the ciphertext has repeated blocks
    if has_repeated_blocks(ciphertext):
        print("-"*120)
        print("This is more likely to be ECB")
        print("-"*120)
        return "ECB"
    else:
        print("-"*120)
        print("No detected repeated pattern, most likely this is CBC")
        print("-"*120)
        return "CBC"



##################################################

# Testing the function
'''
plaintext = "ANIS"*16

mode = choice(["ECB","CBC"])
ciphertext,mode = Oracle_ecb_cbc(plaintext,mode)
guessed_mode = testing_mode(ciphertext)

print("IS THE GUESSED MODE SAME AS THE TRUE MODE => ", guessed_mode==mode)
'''
###################################################




'''
------------------------------------------------------------------------------------------------------------------------
No detected repeated pattern, most likely this is CBC
------------------------------------------------------------------------------------------------------------------------
IS THE GUESSED MODE SAME AS THE TRUE MODE =>  True


------------------------------------------------------------------------------------------------------------------------
This is more likely to be ECB
------------------------------------------------------------------------------------------------------------------------
IS THE GUESSED MODE SAME AS THE TRUE MODE =>  True
'''