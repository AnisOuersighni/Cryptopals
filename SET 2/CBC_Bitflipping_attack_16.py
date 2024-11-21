from os import urandom
from ecb_encrypt_decrypt import ecb_decrypt_aes_128_block, ecb_encrypt_aes_128_block
from cbc_encrypt_decrypt import cbc_encrypt_aes_128, cbc_decrypt_aes_128
from cbc_encrypt_decrypt import split_bytes_in_blocks



def wrap_user_input(user_data):
    
    if isinstance(user_data,str):
        user_data = user_data.encode()
    if not isinstance(user_data,bytes):
        raise TypeError("user_data must be a string or bytes object")
    
    prefix = b"comment1=cooking%20MCs;userdata="
    suffix = b";comment2=%20like%20a%20pound%20of%20bacon"

    user_data_serialized = user_data.replace(b";",b"%3B").replace(b"=",b"%3D")

    return prefix + user_data_serialized + suffix


class Oracle:
    def __init__(self):
        self._key = urandom(16)
        self._IV = urandom(16)
    
    def encrypt(self, user_data):
        data = wrap_user_input(user_data)
        return cbc_encrypt_aes_128(data,self._IV,self._key)

    def decrypt(self,ciphertext):
        return cbc_decrypt_aes_128(ciphertext,self._IV,self._key)

def make_admin(oracle,bloc_size=16):


    a_block = b"A"* bloc_size
    ciphertext = oracle.encrypt(a_block * 2 )    # 2 blocs of prefix + 2 blocs of b"A"  + the rest of suffix 
    
    flipper = bytes([_b ^ _a for _b, _a in zip( a_block , b";admin=true;".rjust(bloc_size,b"A"))])  
    
    padder = flipper.rjust( bloc_size*3 , b"\x00" ).ljust( len(ciphertext) ,  b"\x00" )
    new_ciphertext = bytes([_c ^_p for _c,_p in zip(ciphertext,padder)])
    print(new_ciphertext)
    return new_ciphertext


def check_admin(oracle,ciphertext):

    if isinstance(ciphertext,str):
        ciphertext = ciphertext.encode()
    if not isinstance(ciphertext,bytes):
        raise TypeError("ciphertext must be a string or bytes object")

    plaintext = oracle.decrypt(ciphertext)

    if  b";admin=true;" in plaintext:
        return "Admin Role Granted"
    else:
        return "Nope, Sorry you aren't an Admin \nThus, No Privileges are Granted. \n Bye"


oracle = Oracle()
user_data = b"foo;admin=true;bar"
ciphertext1 = oracle.encrypt(user_data)
result = check_admin(oracle,ciphertext1)

print(result)
print('-'*50)
print(oracle.decrypt(ciphertext1))
print("-"*120)
print("test 2 :")

ciphertext = make_admin(oracle)
print(oracle.decrypt(ciphertext))
print(check_admin(oracle,ciphertext))


'''
Nope, Sorry you aren't an Admin 
Thus, No Privileges are Granted.
 Bye
--------------------------------------------------
b'comment1=cooking%20MCs;userdata=foo%3Badmin%3Dtrue%3Bbar;comment2=%20like%20a%20pound%20of%20bacon'
'''




'''
Logic: 

    
        prefix = b"comment1=cooking%20MCs;userdata="                        => len = 32  <=> 2 blocs of 16
        suffix = b";comment2=%20like%20a%20pound%20of%20bacon"              => len= 42
        b";admin=true;"                                                     => len = 12  <=> append AAAA to attend 16  with rjust append from right 
    
make admin : 

    Flipper =  AAAA AAAA AAAA AAAA   +  AAAA ;adm in=t rue;    = 0000 XXXX XXXX XXXX
    
    
    Padder =  0000 0000 0000 0000     0000 0000 0000 0000    
              0000 0000 0000 0000     0000 XXXX XXXX XXXX    =>  here is the ligne of userdata
              0000 0000 0000 0000     0000 0000 0000 0000
              0000 0000 0000 0000

ciphertext =  PPPP PPPP PPPP PPPP     PPPP PPPP PPPP PPPP    
              AAAA AAAA AAAA AAAA     AAAA AAAA AAAA AAAA    =>  here is the ligne of userdata
              SSSS SSSS SSSS SSSS     SSSS SSSS SSSS SSSS
              SSSS SSSS SSSS SSSS


New_cipher =  PPPP PPPP PPPP PPPP     PPPP PPPP PPPP PPPP    
              AAAA AAAA AAAA AAAA     AAAA ;adm in=t rue;    =>  the xor removed the AAAA AAAA AAAA from the ciphertext and only our wanted string is present now
              SSSS SSSS SSSS SSSS     SSSS SSSS SSSS SSSS
              SSSS SSSS SSSS SSSS

we send this for decytion and our oracle will find that admin is present ! 
'''









