from ecb_encrypt_decrypt import ecb_decrypt_aes_128_block,ecb_encrypt_aes_128_block
from Oracle_ecb_cbc import Oracle_ecb_cbc, testing_mode

import base64 
from os import urandom

# python -m IPython
# Simple
'''
AES-128-ECB(attacker-controlled || target-bytes, random-key)
'''

class ECB_Oracle:
    def __init__(self):
        self.key = urandom(16)
    
    def encrypt(self, plaintext):
        if isinstance(plaintext, str):  
            plaintext = plaintext.encode()  
        elif isinstance(plaintext, bytes):  
            pass  # Do nothing, already bytes
        else:
            try:  # Try to handle as a hex string
                plaintext = bytes.fromhex(plaintext)
            except ValueError:
                raise TypeError("plaintext must be a string, valid hex, or bytes")
        
        return  ecb_encrypt_aes_128_block(plaintext, self.key)


def find_unknown_string_size_from_cipher(oracle,unknown_string):
    
# Trivial is the to doe len(unknown_string) but for educational purpose we do it this way

    if isinstance(unknown_string,str):
        unknown_string = unknown_string.encode()

    unknown_string_len = 0

    unknown_string_cipher_len = len(oracle.encrypt(unknown_string))

    print(f"\n {'-'*50} \n unknown_string_cipher_len = {unknown_string_cipher_len} \n {'-'*50} ")

    for i in range(1,16):
        new_cipher_len = len(oracle.encrypt( b"A"*i + unknown_string ))   # This exploit to function we should have the possibility to get in hand the unknowing_string and used to prefix chars
        if new_cipher_len > unknown_string_cipher_len:
            
            padding = i-1
            unknown_string_len = unknown_string_cipher_len - padding
            print(f"\n {'-'*50} \n The number of appended lettres are  i = {padding} and thus unknown_string_len = {unknown_string_len}\n {'-'*50}")
#            block_size = new_cipher_len - unknown_string_cipher_len      # usefull in case we don't know the key of the oracle (thus the ciphers blocs size)
            break
    
    return unknown_string_len,padding







'''
Choosen String              Unknown String             Padding          
A A A                       S1 S2 S3 S4                 1 ---->             A  A  A  S1   first bloc
                                                                            S2 S3 S4 1    second bloc

                                                                            |
                                                                            | Encryption
                                                                            v
                                                                            x1 x2 x3 x4    first cipher bloc
                                                                            x5 x6 x7 x8

New Knowledge : A  A  A  S1  =>  x1  x2  x3  x4

we keep the bloc x1 x2 x3 x4  and try to bruteforce  the value of s1 that would give that bloc cipher

Once we Know S1, we decrement A  and we have A A S1 S2 => we brute force S2  and so on.

'''




def brute_force_one_byte_each_time_simple(oracle, unknown_string):
    
    if isinstance(unknown_string, str):
        unknown_string = unknown_string.encode()

    # Determine the length of the unknown string
    unknown_string_len, _ = find_unknown_string_size_from_cipher(oracle, unknown_string)

    block_size = 16  # AES block size
    discovered_bytes = b""  # Bytes we have discovered so far

    print("\nStarting brute-force decryption...\n")

    for i in range(unknown_string_len):  # For every byte in the unknown string
        
        # Calculate padding to align the unknown byte  -  
        # when len(discovered) = 0  => len(padding) = 15  leaving 1 byte to bruteforce 
        # when len(discovered) = 16  => len(padding) = 15  leaving 1 byte to bruteforce but we will pass to the next block
        padding_length = block_size - (len(discovered_bytes) % block_size) - 1       
        crafted_input = b"A" * padding_length

        # Encrypt the crafted input with the unknown string
        # crafted_input + unknown_string =   "A"*15 + unknown_string[0]+ unknown_string[1:]    
        #  => this will produce the full ciphertext related to the i-th byte to test
        # if i = 3 (4th byte of unknown_string)  => padding_length will be 15-3 = 12 ( assuming we discovered 3 bytes already) and thus
        # crafted_input + unknown_string = 
        # "A"*12 + unknown_string[0] + unknown_string[1] + unknown_string[2] + unknown_string[3] "to find" + unknown_string[4:]
        # in the rest of the function, we assume already that unknown_string[0] + unknown_string[1] + unknown_string[2] are in discovered_bytes so that comparaison would be correct
        crafted_cipher = oracle.encrypt(crafted_input + unknown_string) 


        # Identify the block containing the unknown byte
        # if len(discovered_bytes)>16 => target_bloc_index = 1  (next block) 
        # we will work on the corresponding block of crafter_cipher to compare
        target_block_index = (len(crafted_input) + len(discovered_bytes)) // block_size
        target_block = crafted_cipher[target_block_index * block_size:(target_block_index + 1) * block_size]

        # Brute-force the next byte
        for b in range(256):
            guess = crafted_input + discovered_bytes + bytes([b])  # len (crafted_input + discovered_bytes) will always be equal 15 leaving a place for a byte
            guess_cipher = oracle.encrypt(guess + unknown_string) # append only the remaining part of the unknown string starting from the current index being brute-forced

            # Match the guessed block with the target block
            guess_block = guess_cipher[target_block_index * block_size:(target_block_index + 1) * block_size]
            if guess_block == target_block:
                discovered_bytes += bytes([b])
                print(f"Discovered so far: {discovered_bytes}")
                break

    print(f"\nDecryption complete! \n {'-'*120} ")
    return discovered_bytes.decode(errors="ignore")


##############################################################################
# Testing the function 
'''
oracle= ECB_Oracle()

unknown_string = base64.b64decode("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK""")
#print(testing_mode(oracle.encrypt(urandom(50))))
#print(testing_mode(oracle.encrypt(b"A"*50)))
#l   = find_unknown_block_size(oracle,b"ANISANISANISAN")

unknown_string_cipher = oracle.encrypt(unknown_string)

#print(unknown_string_cipher)
l   = find_unknown_string_size_from_cipher(oracle,unknown_string)
print(f"len = {l} ")


secret = brute_force_one_byte_each_time(oracle, unknown_string)
print(secret)
'''
##############################################################################