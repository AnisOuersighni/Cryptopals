'''
Implement PKCS#7 padding
A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

"YELLOW SUBMARINE"
... padded to 20 bytes would be:

"YELLOW SUBMARINE\x04\x04\x04\x04"

'''


def padder(plaintext,blocsize=16):
    if isinstance(plaintext,str):
        plaintext = plaintext.encode()
    if len(plaintext) % blocsize !=0:
        pad = blocsize - (len(plaintext)%blocsize)
        pad = bytes([pad]*pad)
        plaintext += pad
    
    return plaintext

def unpadder(plaintext,blocksize=16):
    if isinstance(plaintext,str):
        plaintext = plaintext.encode()
    if isinstance(plaintext,bytes):
        if plaintext[-1] < blocksize :
            plaintext = plaintext[:-plaintext[-1]] 
    
    return plaintext


#plaintext = "YELLOW SUBMARI"

#print(padder(plaintext))
#print(unpadder(padder(plaintext)))