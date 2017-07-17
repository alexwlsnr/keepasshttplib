"""PoC for keepass http interaction"""
import base64
import requests
import Crypto
import Crypto.Random
import os
import keyring
from Crypto.Cipher import AES
from pkcs7 import PKCS7Encoder

encoder = PKCS7Encoder()

PRIVATE_KEY = Crypto.Random.OSRNG.posix.new().read(AES.block_size)

IV = os.urandom(16)

keyring_key = keyring.get_password("keepasshttplib", "Key2")

if(keyring_key == None):
    BASE64_PRIVATE_KEY = base64.b64encode(PRIVATE_KEY).decode()
else:
    BASE64_PRIVATE_KEY = keyring_key
    PRIVATE_KEY = base64.b64decode(keyring_key)

BASE64_IV = base64.b64encode(IV).decode()

aes = AES.new(PRIVATE_KEY, AES.MODE_CBC, IV)


padded_iv = encoder.encode(BASE64_IV)

encrypted = aes.encrypt(padded_iv)

VERIFIER = base64.b64encode(encrypted).decode()


print("Private key: " +  BASE64_PRIVATE_KEY)

print("IV: " +  str(IV))

print("Base64 IV: " +  BASE64_IV)

print("Verifier: " +  VERIFIER)


jsonreq = {
    "RequestType": "associate",
    "Key": BASE64_PRIVATE_KEY,
    "Nonce": BASE64_IV,
    "Verifier": VERIFIER,
}

r = requests.post('http://10.44.250.139:19455/post', json=jsonreq)

json = r.json()

if json['Success']:
    keyring.set_password("keepasshttplib", "Id", json['Id'])
    keyring.set_password("keepasshttplib", "Key2", BASE64_PRIVATE_KEY)

print("Request: " + str(jsonreq))
print("Status code: " + str(r.status_code))
print("Response: " + str(r.json()))