#!/usr/bin/env python3
# https://asecuritysite.com/encryption/aes_python

from Crypto.Cipher import AES
import sys

import base64
import Padding

plaintext='Hello'
key='-change-me-'
salt='1234567890'

if (len(sys.argv)>1):
        plaintext=str(sys.argv[1])
if (len(sys.argv)>2):
        key=str(sys.argv[2])
if (len(sys.argv)>3):
        salt=str(sys.argv[3])

def get_key_and_iv(password, salt, klen=32, ilen=16, msgdgst='md5'):
    mdf = getattr(__import__('hashlib', fromlist=[msgdgst]), msgdgst)
    password = password.encode('ascii', 'ignore')  # convert to ASCII
    salt = bytearray.fromhex(salt) # convert to ASCII

    try:
        maxlen = klen + ilen
        keyiv = mdf((password + salt)).digest()
        tmp = [keyiv]
        while len(tmp) < maxlen:
            tmp.append( mdf(tmp[-1] + password + salt).digest() )
            keyiv += tmp[-1]  # append the last byte
        key = keyiv[:klen]
        iv = keyiv[klen:klen+ilen]
        return key, iv
    except UnicodeDecodeError:
         return None, None

def encrypt(plaintext, key, salt, mode=AES.MODE_CBC):
	key, iv = get_key_and_iv(key, salt)
	encobj = AES.new(key, mode, iv)
	return(encobj.encrypt(plaintext.encode()))

def decrypt(ciphertext, key, salt, mode=AES.MODE_CBC):
	key, iv = get_key_and_iv(key, salt)
	encobj = AES.new(key, mode, iv)
	return(encobj.decrypt(ciphertext))

print ("Plaintext:\t",plaintext)
print ("Passphrase:\t",key)
print ("Salt:\t\t",salt)
plaintext = Padding.appendPadding(plaintext, mode='CMS')

ciphertext = encrypt(plaintext,key,AES.MODE_CBC,salt)

ctext = b'Salted__' + bytearray.fromhex(salt) + ciphertext


print ("\nCipher (CBC) - Base64:\t",base64.b64encode(bytearray(ctext)).decode())
print ("\nCipher (CBC) - Hex:\t",ctext.hex())
print ("Cipher in binary:\t",ctext)

plaintext = decrypt(ciphertext, key, salt)
print ("\nDecrypted (Before unpad):\t",plaintext)
#plaintext = Padding.removePadding(plaintext.decode(),mode='CMS')

print ("\nDecrypted:\t"+plaintext.decode().strip())
