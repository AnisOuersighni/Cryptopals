# Harder 
from ecb_encrypt_decrypt import ecb_encrypt_aes_128_block
from ECB_decryption_Byte_at_a_time12 import  find_unknown_string_size_from_cipher, brute_force_one_byte_each_time_simple
from cbc_encrypt_decrypt import split_bytes_in_blocks


import base64 
from os import urandom
from random import randint


# In Exercice 12 we are requested to get the target-bytes from this schema : Reminder, we have only access to encryption function not decryption of course.
# from the encryption function and controlled input we try to determine what could be the target-bytes plaintext.

'''
AES-128-ECB(attacker-controlled || target-bytes, random-key)
'''

# In this exercice we are required to get the target-bytes from this schema where we control only the middle part of the message
#  the random prefix should be generated once at the instanciation of the oracle, and stay the same accross all calls to the oracle.
'''
AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
'''

class Oracle:
    def __init__(self):
        self.random_prefix = urandom(randint(1,16))
        self.key = urandom(16)
        self.target_bytes1 = base64.b64decode("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK""")
        self.target_bytes2 = b"SC2 Community is rock'ing it. Go Ahead and Solve this, I know you are capables guys !"
#        print(f"generated prefix = {self.random_prefix} and \n len = {len(self.random_prefix)}")        


    def encrypt(self,message):
        return ecb_encrypt_aes_128_block( self.random_prefix + message + self.target_bytes1 + self.target_bytes2 , self.key )

oracle = Oracle()


def find_prefix_size(oracle):

    reference_ciphertext = oracle.encrypt(b"0"*16)
    reference_ciphertext_blocks = split_bytes_in_blocks(reference_ciphertext)  #  => this is a list of cipher blocks [ Cb1,Cb2,Cb3 ..]
    
    block_size = 16
    prefix_size = 16  # assumption if for loop quits

    for i in range(0,block_size):

        c_i = oracle.encrypt(b"0"*i + b"1")
        c_i_blocks = split_bytes_in_blocks(c_i)
        if c_i_blocks[0] == reference_ciphertext_blocks[0]:
            prefix_size = block_size - i 
            break
    
    return prefix_size
   
 

prefix_len = find_prefix_size(oracle)


print("-"*120)
print(f"prefix_guessed_len = {prefix_len}")



def brute_force_one_byte_each_time_hard(oracle,prefix_len):

    bloc_size = 16
    padding_capacity = (bloc_size - (prefix_len % bloc_size)) % bloc_size  

    discovered_bytes= b""
    
    len_reference_ciphertext = len(oracle.encrypt(b""))
    unknown_string_len_range = len_reference_ciphertext - prefix_len    # => at maximum the unknown string can be this length, and minimum this value - 15 (case when last byte of ciphertext start a new cipher bloc)

    print("\nStarting brute-force decryption...\n")

    for _ in range(1,unknown_string_len_range):
         # Correct padding calculation
        padding_length = bloc_size - (len(discovered_bytes) % bloc_size) - 1
        crafted_input = b"0" * (padding_capacity + padding_length)
        crafted_ciphertext = oracle.encrypt(crafted_input)

        
        # discovered bytes hiya ily kol matakber tnejm t3edyna nakhdmo aal bloc ily baado ( if len(discovered_bytes)> padding capacity nit3edew lil bloc ily baad)
        #target_block_index = (prefix_len + padding_length + len(discovered_bytes)) // bloc_size  
        target_block_index = (prefix_len + padding_capacity + len(discovered_bytes)) // bloc_size    # Notice that prefix_len + capacity bloc_size= 16 always
        target_cipher_bloc = crafted_ciphertext[target_block_index * bloc_size : (target_block_index + 1) * bloc_size]
        
        byte_found = False
        for j in range(255):
            guess = crafted_input + discovered_bytes + bytes([j])
            guess_ciphertext = oracle.encrypt(guess)
            target_guess_bloc = guess_ciphertext[target_block_index * bloc_size : (target_block_index + 1) * bloc_size]

            if target_guess_bloc ==  target_cipher_bloc:
                discovered_bytes += bytes([j])
                byte_found= True
                print(f"Discovered so far: {discovered_bytes}")
                break

        if not byte_found:
            print("No matching byte found! Stopping.")
            break

    return discovered_bytes




secret_string =brute_force_one_byte_each_time_hard(oracle,prefix_len)

print("-"*120)
print(f"secret_string = {secret_string.decode()}")
print("-"*120)




# Find_prefix_size : 


"""
    Reference =     P P P P P P P P 0 0 0 0 0 0 0 0 0 0
                    0 0 0 0 0 0 S S S S S S S S S S S S 
                    S S S S S S S 9 9 9 9 9 9 9 9 9 9 9


    Each time i start with inserting 1

        C1 =        P P P P P P P P 1 0 0 0 0 0 0 0     =>  Bc1
                    0 0 0 0 0 0 0 S S S S S S S S S 
                    S S S S S S S S 8 8 8 8 8 8 8 8 

    Then i add 0 before : 
        C2 =        P P P P P P P P 0 1 0 0 0 0 0 0 
                    0 0 0 0 0 0 0 0 S S S S S S S S 
                    S S S S S S S S S 7 7 7 7 7 7 7 

    until :  ( 7 zeros + 1)
        C8 =        P P P P P P P P 0 0 0 0 0 0 0 1
                    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
                    S S S S S S S S S S S S S S S S 
                    S 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 

    Finally  ( 8 zeros +  1 )

        C9 =        P P P P P P P P 0 0 0 0 0 0 0 0        =>  Same As Bc1  <=> Bc1 = Bc9  <=> len == 16 - 9 + 1
                    1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
                    0 S S S S S S S S S S S S S S S  
                    S S 1 1 1 1 1 1 1 1 1 1 1 1 1 1 
-------------------------------------------------------------------------------------

Case P = 16 :
        C1' =       P P P P P P P P P P P P P P P P        
                    1 S S S S S S S S S S S S S S S 
                    S S S S S S S S S S S S S S S S 
                    S 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1

    try until 15 zeros +1 
        C16' =      P P P P P P P P P P P P P P P P          
                    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1     => this line never was equal to the previous line 
                    S S S S S S S S S S S S S S S S 
                    S S S S S S S S S S S S S S S S 

"""


# brute_force_one_byte_each_time_hard(oracle,prefix_len)

'''

    Reference_ciphertext =  XXXX     SSSS    SSSS    SSSS
                            SSSS     SSSS    pppp    pppp
        
        p = pcks7
            
            Prefix length = 4
            S length = 20
    
    Padding capacity = 12 

---------------------------------------------------------
for i = 1 ( search for S1) :

padding_length = 15 
input = "0" * (15 + 12 ) = 27  = "0" *27

        crafted_ciphertext                XXXX    0000    0000    0000
                                          0000    0000    0000    000S  => here is the lettre to brute force
                                          SSSS    SSSS    SSSS    SSSS
                                          SSSP    pppp    pppp    pppp
    
target_block_index = (4+12+0)//16 = 1  => the 2nd block of crafted_ciphertext  :
                                          0000    0000    0000    000S          => here is the lettre to brute force

************************************
*   brute force the letter S1      *
    guess = "0" * 27  +  ""  + bytes([j])

    check if the 2nd block of guess match this line  0000    0000    0000    000S 
    and thus bytes([j]) == S

    <=> S is disovered we add it to our discovered_bytes string

--------------------------------------------------

for i = 2 ( search for S2) :

padding_length = 14 
input = "0" * (14 + 12 ) = 26  = "0" *26

        crafted_ciphertext                XXXX    0000    0000    0000
                                          0000    0000    0000    00SS  => the second S is the one to bruteforce
                                          SSSS    SSSS    SSSS    SSSS
                                          SSPP    pppp    pppp    pppp
    
target_block_index = (4+12+1)//16 = 1  => always work on the 2nd block of crafted_ciphertext  :
                                          0000    0000    0000    00SS          => here is the lettre to brute force

************************************
*   brute force the letter S2      *
    guess = "0" * 26  +  "S"  + bytes([j])

    check if the 2nd block of guess match this line  0000    0000    0000    00SS 
    and thus bytes([j]) == S  ( second one at the end)

    <=> S is disovered we add it to our discovered_bytes string


    
--------------------------------------------------

for i = 7 ( search for S17  after discovering bytes S1 - S16) :

padding_length = 15 
input = "0" * (15 + 12 ) = 27  = "0" *27

        crafted_ciphertext                XXXX    0000    0000    0000
                                          0000    0000    0000    000S  
                                          SSSS    SSSS    SSSS    SSSS  => The last lettre is the one to brute force 
                                          SSSP    pppp    pppp    pppp
    
target_block_index = (4+12+16)//16 = 2  => the 3rd block of crafted_ciphertext  :
                                          SSSS    SSSS    SSSS    SSSS          => all the 15 lettres in this bloc are known but the last isn't 

************************************
*   brute force the letter S17      *
    guess = "0" * 27  +  "S1" -> "S16"  + bytes([j])

    check if the 2nd block of guess match this line  SSSS    SSSS    SSSS    SSSS 
    and thus bytes([j]) == S   ( last one in the block)

    <=> S is disovered we add it to our discovered_bytes string


'''

        
    


