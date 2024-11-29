import hashlib
import hmac 
import os

def hmac_sha512(key, message):
    #128 byte block size for SHA-512
    block = 128

    #ipad and opad constants
    i_pad = bytes([0x36] * block)
    o_pad = bytes([0x5c] * block) 

    if len(key) > block:
        #reduce key to 512 bits using SHA-512
        key = hashlib.sha512(key).digest()
    if len(key) < block:
        #pad key to reach 128 byte size
        key += bytes(block - len(key))

    #xor key with ipad and apply SHA-512
    key_xor_i_pad = bytes(k ^ i for k, i in zip(key, i_pad))
    h = hashlib.sha512(key_xor_i_pad + message).digest()

    #xor key with opad and apply SHA-512
    key_xor_o_pad = bytes(k ^ o for k, o in zip(key, o_pad))
    hmac = hashlib.sha512(key_xor_o_pad + h).digest()

    return hmac

#inputs
key = os.urandom(64)  
message = b"I am using this input string to test my own implementation of HMAC-SHA-512."

#Compute using own implementation 
hmac_result = int.from_bytes(hmac_sha512(key, message))
print("HMAC-SHA-512 personal implementation:", hmac_result)

#compute using library implementation
library_hmac_result = int.from_bytes(hmac.new(key, message, hashlib.sha512).digest())
print("Library HMAC-SHA-512 implementation:", library_hmac_result)
