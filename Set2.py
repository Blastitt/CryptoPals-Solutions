from Set1 import *
from Crypto.Cipher import AES

# Ensures all blocks of data are blocksize in length using PKCS#7 block padding.
def padBlocks(data, blocksize):
    if blocksize > 255:
        print("Block size too large: %d" % blocksize)
        return data
    paddingAmt = blocksize - (len(data) % blocksize)
    padding = chr(paddingAmt) * paddingAmt
    data += padding
    return data

# Undoes PKCS#7 padding
def depadBlocks(data):
    padByte = ord(data[-1])
    if padByte == 0:
        return data
    try:
        padding = data[(0-padByte):]
        if all(ord(a) == padByte for a in padding):
            return data[:(0-padByte)]
    except:
        return data

# Takes the plaintext and key and generates ciphertext using AES ECB mode.
def encrypt_AES_ECB(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

# Takes a ciphertext, key, and initialization vector and finds the plaintext
# using AES CBC mode.
def decrypt_AES_CBC(ciphertext, key, iv):
    prevCipherblock = iv
    plaintext = bytearray(len(ciphertext))

    for i in range(0, len(ciphertext), AES.block_size):
        decrypted = bytearray(decrypt_AES_ECB(ciphertext[i:(i+AES.block_size)], key))
        plaintext[i:(i+AES.block_size)] = byteXOR(decrypted, prevCipherblock)
        prevCipherblock = bytearray(ciphertext[i:(i+AES.block_size)])

    return depadBlocks(bytes(plaintext))
    
# Takes a plaintext, key, and initialization vector and generates ciphertext
# using AES CBC mode.
def encrypt_AES_CBC(plaintext, key, iv):
    prevCipherblock = iv
    plaintext = padBlocks(plaintext, AES.block_size)
    ciphertext = bytearray(len(plaintext))

    for i in range(0, len(plaintext), AES.block_size):
        xored = byteXOR(bytearray(plaintext[i:(i+AES.block_size)]), prevCipherblock)
        cipherblock = encrypt_AES_ECB(xored, key)
        ciphertext[i:(i+AES.block_size)] = cipherblock
        prevCipherblock = bytearray(cipherblock)

    return bytes(ciphertext)

def test_encrypt_AES_CBC():
    contents = ""

    with open('plaintext.txt') as f:
        for line in f.readlines():
            contents += line
    plaintext = contents
    key = "YELLOW SUBMARINE"
    iv = bytearray(['\x00'] * AES.block_size)
    ciphertext = encrypt_AES_CBC(plaintext, key, iv)
    print(decrypt_AES_CBC(ciphertext, key, iv))

def test_decrypt_AES_CBC():
    contents = ""

    with open('set2chal10.txt') as f:
        for line in f.readlines():
            contents += line
    ciphertext = contents.decode('base64')
    key = "YELLOW SUBMARINE"
    iv = bytearray(['\x00'] * AES.block_size)
    plaintext = decrypt_AES_CBC(ciphertext, key, iv)
    print(plaintext)

def testPadBlocks():
    print(padBlocks("YELLOW SUBMARINE", 20))

def testDepadBlocks():
    print(depadBlocks(padBlocks("YELLOW SUBMARINE", 20)))

def test_encrypt_AES_ECB():
    contents = ""

    with open('plaintext.txt') as f:
        for line in f.readlines():
            contents += line
    plaintext = contents
    key = "YELLOW SUBMARINE"
    ciphertext = encrypt_AES_ECB(plaintext, key)
    print(decrypt_AES_ECB(ciphertext, key))
