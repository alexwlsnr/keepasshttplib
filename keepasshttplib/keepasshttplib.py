"""PoC for keepass http interaction"""
import base64
import requests
import Crypto
import Crypto.Random
import os
from Crypto.Cipher import AES
from pkcs7 import PKCS7Encoder

encoder = PKCS7Encoder()

PRIVATE_KEY = Crypto.Random.OSRNG.posix.new().read(AES.block_size)

IV = os.urandom(16)

BASE64_PRIVATE_KEY = base64.b64encode(PRIVATE_KEY).decode()

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

r = requests.post('http://localhost:19455/post', json=jsonreq)

print("Request: " + str(jsonreq))
print("Status code: " + str(r.status_code))
print("Response: " + str(r.json()))