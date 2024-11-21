

def pkcs7_checker(message,block_size=16):
    
    if isinstance(message,str):
        message = message.encode('utf-8')
    if not isinstance(message,bytes):
        return "Please provide a Bytes/Ascii string"
    
    if message[-1] < block_size:
        claim_padding = message[-1]
        #print(f"message[-1] = {message[-1]}")
        #print(f"message[-claim_padding ] = {message[-claim_padding ]}")
        #print(f"message[:- ( claim_padding + 1  ) ]  =  {message[- ( claim_padding + 1  ) ]}")
        #print(f"padding string = {message[-claim_padding: ]}")

        correct_claim_padding_string = b""
        for i in range(claim_padding):
            correct_claim_padding_string += bytes([message[-1]])
        
        #print(f" correct_claim_padding_string to compare with    =  { correct_claim_padding_string}")
        
        if ( message[- ( claim_padding + 1 ) ] != message[-1] ) and ( message[-claim_padding: ]  == correct_claim_padding_string)  :

            print("The string padding is correct")
            print("-"*120)
            plaintext = message[:-claim_padding  ]
            return plaintext
        else:
            return "The string padding is incorrect !"
    else:
        return message

message= "ICE ICE BABY\x05\x05\x05\x05\x05"
print(pkcs7_checker(message))  