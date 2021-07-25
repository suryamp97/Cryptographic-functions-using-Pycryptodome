#!/usr/bin/env python3
# coding: utf-8

# In[1]:


import json
from base64 import b64encode,b64decode
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA,DSA
from time import perf_counter
import os, sys
from Crypto.Signature import DSS
from Crypto.Hash import SHA256,SHA512,SHA3_256


# In[2]:


PT_1KB = 'Plain_Text_1KB.txt'
if not os.path.exists(PT_1KB):
    print('The file %s does not exist' % (PT_1KB))
    sys.exit()
    
PT_10MB = 'Plain_Text_10MB.txt'
if not os.path.exists(PT_10MB):
    print('The file %s does not exist' % (PT_10MB))
    sys.exit()
    
PT_1MB = 'Plain_Text_1MB.txt'
if not os.path.exists(PT_1MB):
    print('The file %s does not exist' % (PT_1MB))
    sys.exit()

fileobj = open(PT_1KB)
content_1KB = fileobj.read()

fileobj1 = open(PT_10MB)
content_10MB = fileobj1.read()

fileobj2 = open(PT_1MB)
content_1MB = fileobj2.read()

print("\n\n")


# In[3]:


print("(a) 128-bit key AES in CBC-Mode:\n")
# creating 128-bit key
t1 = perf_counter() 
key = get_random_bytes(16)
t2 = perf_counter() 
print('Key Generation Time: %.8f seconds\n' %(t2-t1))

def AES_128_CBC(message):

    
    # message input
    message = message
    
    # Encrypting our message
    t1e = perf_counter() 
    cipher = AES.new(key, AES.MODE_CBC)
    ct=cipher.encrypt(pad(message, AES.block_size))
    t2e = perf_counter() 
    size = sys.getsizeof(ct)
    print('\tEncryption Time: %.8f seconds' %(t2e-t1e))
    enc_per_byte = (t2e-t1e)/size
    
    iv = b64encode(cipher.iv).decode('utf-8')
    ciphertext = b64encode(ct).decode('utf-8')
    cipher_and_iv_json1 = json.dumps({'iv':iv, 'ciphertext':ciphertext})

    # Decrypting ciphertext 
    b64 = json.loads(cipher_and_iv_json1)
    iv = b64decode(b64['iv'])
    ciphertext = b64decode(b64['ciphertext'])
    
    t1d = perf_counter() 
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ciphertext)
    plaintext = unpad(pt, AES.block_size)  
    t2d = perf_counter()    
    size = sys.getsizeof(plaintext)
    print('\tDecryption Time: %.8f seconds' %(t2d-t1d))
    dec_per_byte = (t2d-t1d)/size
    
    print('\tEncryption Speed/byte: %.10f seconds' %(enc_per_byte))   
    print('\tDecryption Speed/byte: %.10f seconds' %(dec_per_byte))     

    if plaintext == message:
        print("ciphertext decrypt = original message --> Encryption Successful.")
    else:
        print("decrypt message and message do not match --> Enryption Failed.")

print("File1: ",PT_1KB,", FileSize: ",sys.getsizeof(content_1KB),"bytes")
AES_128_CBC(bytes(content_1KB, encoding='utf-8'))

print("\nFile2: ",PT_10MB,", FileSize: ",sys.getsizeof(content_10MB),"bytes")
AES_128_CBC(bytes(content_10MB, encoding='utf-8'))

print("\n\n")


# In[4]:


# AES 128-bit key CTR-MODE
print("(b) 128-bit key AES in CTR-Mode:\n")  

# creating 128-bit key
t1 = perf_counter() 
key = get_random_bytes(16)
t2 = perf_counter() 
print('Key Generation Time: %.8f seconds\n' %(t2-t1))

def AES_128_CTR(message):
    
    # message input
    message = message
    
    # Encrypting our message
    t1e = perf_counter() 
    cipher = AES.new(key, AES.MODE_CTR)
    ct = cipher.encrypt(message)
    t2e = perf_counter() 
    size = sys.getsizeof(ct)
    print('\tEncryption Time: %.8f seconds' %(t2e-t1e))
    enc_per_byte = (t2e-t1e)/size

    iv = b64encode(cipher.nonce).decode('utf-8')
    ciphertext = b64encode(ct).decode('utf-8')
    cipher_and_iv_json2 = json.dumps({'iv':iv, 'ciphertext':ciphertext})

    # Decrypting ciphertext 
    b64 = json.loads(cipher_and_iv_json2)
    iv = b64decode(b64['iv'])
    ciphertext = b64decode(b64['ciphertext'])
    
    t1d = perf_counter() 
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
    plaintext = cipher.decrypt(ciphertext)
    t2d = perf_counter() 
    size = sys.getsizeof(plaintext)
    print('\tDecryption Time: %.8f seconds' %(t2d-t1d))
    dec_per_byte = (t2d-t1d)/size

    print('\tEncryption Speed/byte: %.10f seconds' %(enc_per_byte)) 
    print('\tDecryption Speed/byte: %.10f seconds' %(dec_per_byte))   
        
    if plaintext == message:
        print("\nciphertext decrypt = original message --> Encryption Successful.")
    else:
        print("decrypt message and message do not match --> Enryption Failed.")
    
print("File1: ",PT_1KB,", FileSize: ",sys.getsizeof(content_1KB),"bytes")
AES_128_CTR(bytes(content_1KB, encoding='utf-8'))

print("\nFile2: ",PT_10MB,", FileSize: ",sys.getsizeof(content_10MB),"bytes")
AES_128_CTR(bytes(content_10MB, encoding='utf-8'))

print("\n\n")


# In[5]:


# AES 256-bit key CTR-MODE
print("(c) 256-bit key AES in CTR-Mode:\n")

# creating 256-bit key
t1 = perf_counter() 
key = get_random_bytes(32)
t2 = perf_counter() 
print('Key Generation Time: %.8f seconds\n' %(t2-t1))

def AES_256_CTR(message):
    
    # message input
    message = message
    
    # Encrypting our message   
    t1e = perf_counter() 
    cipher = AES.new(key, AES.MODE_CTR)
    ct = cipher.encrypt(message)
    t2e = perf_counter() 
    size = sys.getsizeof(ct)
    print('\tEncryption Time: %.8f seconds' %(t2e-t1e))
    enc_per_byte = (t2e-t1e)/size

    iv = b64encode(cipher.nonce).decode('utf-8')
    ciphertext = b64encode(ct).decode('utf-8')
    cipher_and_iv_json3 = json.dumps({'iv':iv, 'ciphertext':ciphertext})


    # Decrypting ciphertext 
    b64 = json.loads(cipher_and_iv_json3)
    iv = b64decode(b64['iv'])
    ciphertext = b64decode(b64['ciphertext'])
    
    t1d = perf_counter()
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
    plaintext = cipher.decrypt(ciphertext)
    t2d = perf_counter() 
    size = sys.getsizeof(plaintext)
    print('\tDecryption Time: %.8f seconds' %(t2d-t1d))
    dec_per_byte = (t2d-t1d)/size
  
    print('\tEncryption Speed/byte: %.10f seconds' %(enc_per_byte))   
    print('\tDecryption Speed/byte: %.10f seconds' %(dec_per_byte))   
        
    if plaintext == message:
        print("ciphertext decrypt = original message --> Encryption Successful.")
    else:
        print("decrypt message and message do not match --> Enryption Failed.")
        
print("File1: ",PT_1KB,", FileSize: ",sys.getsizeof(content_1KB),"bytes")
AES_256_CTR(bytes(content_1KB, encoding='utf-8'))

print("\nFile2: ",PT_10MB,", FileSize: ",sys.getsizeof(content_10MB),"bytes")
AES_256_CTR(bytes(content_10MB, encoding='utf-8'))

print("\n\n")


# In[6]:


print("(d) 2048-bit key RSA PKCS#1 OAEP:\n")  


# creating 2048-bit RSA key
t1 = perf_counter()
key = RSA.generate(2048)
t2 = perf_counter() 
print('Key Generation Time: %.6f seconds\n' %(t2-t1))
private_key = key
public_key = key.publickey()

def RSA_2048_OAEP(message):

    # message input
    size = len(message)
    chunk_size = 214
    itr = int(size/chunk_size)+1
    print("message length: ", size,"; chunk_size: ",chunk_size,"bytes/chunk; number of chunks: ", itr)
    m=message
    flag=0
    
    total_enc_time =0
    total_dec_time =0
    
    for i in range(itr):
        
        message = m[i*chunk_size:(i+1)*chunk_size]
        # Encrypting our message with public key
        t1 = perf_counter()
        cipher = PKCS1_OAEP.new(public_key)
        ciphertext = cipher.encrypt(message)
        t2 = perf_counter() 
        total_enc_time = total_enc_time + (t2-t1)

        # Decrypting our message with private key
        t1 = perf_counter()
        cipher = PKCS1_OAEP.new(private_key)
        plaintext = cipher.decrypt(ciphertext)
        t2 = perf_counter() 
        total_dec_time = total_dec_time + (t2-t1)

        if plaintext != message:
            flag=i+1
            
    if flag==0:
        print("All chunks checked. ciphertext decrypt = original message --> Encryption Successful.")
        print('\tEncryption Time: %.8f seconds' %(total_enc_time))  
        print('\tDecryption Time: %.8f seconds' %(total_dec_time))
        print('\tEncryption Speed/byte: %.10f seconds' %((total_enc_time)/size)) 
        print('\tDecryption Speed/byte: %.10f seconds' %((total_dec_time)/size))   
    else:
        print("decrypted message and original message do not match at message chunk: ",flag," --> Enryption Failed.")
       
       
print("File1: ",PT_1KB,", FileSize: ",sys.getsizeof(content_1KB),"bytes")
RSA_2048_OAEP(bytes(content_1KB, encoding='utf-8'))

print("\nFile2: ",PT_1MB,", FileSize: ",sys.getsizeof(content_1MB),"bytes")
RSA_2048_OAEP(bytes(content_1MB, encoding='utf-8'))

print("\n\n")


# In[7]:


# creating 3072-bit RSA key
print("(e) 3072-bit key RSA PKCS#1 OAEP:\n")  

t1 = perf_counter()
key = RSA.generate(3072)
t2 = perf_counter() 
print('Key Generation Time: %.6f seconds\n' %(t2-t1))
private_key = key
public_key = key.publickey()

def RSA_3072_OAEP(message):

    # message input
    size = len(message)
    chunk_size = 342
    itr = int((size/chunk_size))+1
    print("message length: ", size,"; chunk_size: ",chunk_size,"bytes/chunk; number of chunks: ", itr)
    m=message
    flag=0

    total_enc_time =0
    total_dec_time =0
    
    for i in range(itr):
        
        message = m[i*chunk_size:(i+1)*chunk_size]
        # Encrypting our message with public key
        t1 = perf_counter()
        cipher = PKCS1_OAEP.new(public_key)
        ciphertext = cipher.encrypt(message)
        t2 = perf_counter() 
        total_enc_time = total_enc_time + (t2-t1)

        # Decrypting our message with private key
        t1 = perf_counter()
        cipher = PKCS1_OAEP.new(private_key)
        plaintext = cipher.decrypt(ciphertext)
        t2 = perf_counter() 
        total_dec_time = total_dec_time + (t2-t1)

        if plaintext != message:
            flag=i+1
            
    if flag==0:
        print("All chunks checked. ciphertext decrypt = original message --> Encryption Successful.")
        print('\tEncryption Time: %.8f seconds' %(total_enc_time)) 
        print('\tDecryption Time: %.8f seconds' %(total_dec_time))
        print('\tEncryption Speed/byte: %.10f seconds' %((total_enc_time)/size))  
        print('\tDecryption Speed/byte: %.10f seconds' %((total_dec_time)/size))   
    else:
        print("decrypted message and original message do not match at message chunk: ",flag," --> Enryption Failed.")
       
       
print("File1: ",PT_1KB,", FileSize: ",sys.getsizeof(content_1KB),"bytes")
RSA_3072_OAEP(bytes(content_1KB, encoding='utf-8'))

print("\nFile2: ",PT_1MB,", FileSize: ",sys.getsizeof(content_1MB),"bytes")
RSA_3072_OAEP(bytes(content_1MB, encoding='utf-8'))

print("\n\n")


# In[8]:


print("(f) SHA-256, SHA-512, SHA3-256:\n")

# SHA-256
def SHA_256(message):
    print("SHA-256")
    t1 = perf_counter() 
    h256 = SHA256.new()
    h256.update(message)
    t2 = perf_counter() 
    size = len(message)
    print('\tHash Time: %.8f seconds' %(t2-t1))
    print('\tHash Time/byte: %.10f seconds' %((t2-t1)/size))  
    
    
# SHA-512
def SHA_512(message):
    print("SHA-512")
    t1 = perf_counter() 
    h512 = SHA512.new()
    h512.update(message)
    t2 = perf_counter() 
    size = len(message)
    print('\tHash Time: %.8f seconds' %(t2-t1))
    print('\tHash Time/byte: %.10f seconds' %((t2-t1)/size))  
    

# SHA3-256
def SHA3_256_def(message):
    print("SHA3-256")
    t1 = perf_counter() 
    h3_256 = SHA3_256.new()
    h3_256.update(message)
    t2 = perf_counter() 
    size = len(message)
    print('\tHash Time: %.8f seconds' %(t2-t1))
    print('\tHash Time/byte: %.10f seconds' %((t2-t1)/size))  
    
    
print("File1: ",PT_1KB,", FileSize: ",sys.getsizeof(content_1KB),"bytes")
print("\tMessage size: ",len(bytes(content_1KB, encoding='utf-8')))
SHA_256(bytes(content_1KB, encoding='utf-8'))    
SHA3_256_def(bytes(content_1KB, encoding='utf-8'))
SHA_512(bytes(content_1KB, encoding='utf-8'))

print("\nFile2: ",PT_10MB,", FileSize: ",sys.getsizeof(content_10MB),"bytes")
print("\tMessage size: ",len(bytes(content_10MB, encoding='utf-8')))
SHA_256(bytes(content_10MB, encoding='utf-8'))
SHA3_256_def(bytes(content_10MB, encoding='utf-8'))
SHA_512(bytes(content_10MB, encoding='utf-8'))

print("\n\n")


# In[14]:


print("(g) 2048-bit DSA key, signed and verified(hash function used-SHA-256):\n")
    
t1 = perf_counter() 
key = DSA.generate(2048)
t2 = perf_counter() 
print("\tKey Generation Time:", round((t2-t1),3),"seconds\n")

private_key = key
public_key = key.publickey()

def DSA_2048(message):


    # message input
    message = message
    
    # Signing
    t1s = perf_counter() 
    message_hash = SHA256.new(message)
    signing = DSS.new(private_key, 'fips-186-3')
    signature = signing.sign(message_hash)
    t2s = perf_counter() 
    size = sys.getsizeof(message)
    print("\tMessage size: ",size)
    print('\n\tSignature Time: %.06f' %(t2s-t1s))
        
    #Verifying
    t1v = perf_counter()
    message_hash = SHA256.new(message)
    verification = DSS.new(public_key, 'fips-186-3')
    try:
        verification.verify(message_hash, signature)
        t2v = perf_counter() 
        print('\tVerification Time: %.06f \n' %(t2v-t1v))
        
        print('\tSignature Time/byte: %.10f' %((t2s-t1s)/size)) 
        print('\tVerification Time/byte: %.10f' %((t2v-t1v)/size)) 
        
        print("The message is authentic and has integrity.")
    except ValueError:
        print("The message is not authentic and has lost integrity.")
        
print("File1: ",PT_1KB,", FileSize: ",sys.getsizeof(content_1KB),"bytes")
DSA_2048(bytes(content_1KB, encoding='utf-8'))

print("\nFile2: ",PT_10MB,", FileSize: ",sys.getsizeof(content_10MB),"bytes")
DSA_2048(bytes(content_10MB, encoding='utf-8'))

print("\n\n")


# In[15]:


print("(h) 3072-bit DSA key, signed and verified(hash function used-SHA-256):\n")

t1 = perf_counter() 
key = DSA.generate(3072)
t2 = perf_counter() 
print("\tKey Generation Time:", round((t2-t1),3),"seconds\n")
private_key = key
public_key = key.publickey()

def DSA_3072(message):

    # message input
    message = message
    
    # Signing
    t1s = perf_counter() 
    message_hash = SHA256.new(message)
    signing = DSS.new(private_key, 'fips-186-3')
    signature = signing.sign(message_hash)
    t2s = perf_counter() 
    size = sys.getsizeof(message)
    print("\tMessage size: ",size)
    print('\n\tSignature Time: %.06f' %(t2s-t1s))
    
    #Verifying
    t1v = perf_counter()
    message_hash = SHA256.new(message)
    verification = DSS.new(public_key, 'fips-186-3')
    try:
        verification.verify(message_hash, signature)
        t2v = perf_counter() 
        print('\tVerification Time: %.06f \n' %(t2v-t1v))
        
        print('\tSignature Time/byte: %.10f' %((t2s-t1s)/size)) 
        print('\tVerification Time/byte: %.10f' %((t2v-t1v)/size)) 
        print("The message is authentic and has integrity.")
    except ValueError:
        print("The message is not authentic and has lost integrity.")

print("File1: ",PT_1KB,", FileSize: ",sys.getsizeof(content_1KB),"bytes")
DSA_3072(bytes(content_1KB, encoding='utf-8'))

print("\nFile2: ",PT_10MB,", FileSize: ",sys.getsizeof(content_10MB),"bytes")
DSA_2048(bytes(content_10MB, encoding='utf-8'))
print("\n\n")


# In[ ]:




