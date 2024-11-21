
def has_repeated_blocks(ctxt, blocksize=16):
    '''blocksize is in bytes'''
    if len(ctxt) % blocksize != 0:
        raise Exception('ciphertext length is not a multiple of block size')
    else:
        num_blocks = len(ctxt) // blocksize
        
    blocks = [ctxt[i*blocksize:(i+1)*blocksize] for i in range(num_blocks)]
    
    if len(set(blocks)) != num_blocks:
        return True
    else:
        return False

file=''''''

Lignes= file.strip().split()

ciphertexts=[ bytes.fromhex(ligne) for ligne in Lignes]

ecb_cipher = [ ciphertext for ciphertext in ciphertexts if has_repeated_blocks(ciphertext,16)]

for detected in ecb_cipher:
    print(detected.hex())
    print("-"*60)  
