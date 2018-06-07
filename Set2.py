from Set1 import *
from Crypto.Cipher import AES
import random

def randbytes(numbytes):
    return ''.join(chr(random.randint(0,255)) for i in range(numbytes))

def generateKey():
    return randbytes(16)

unknown_key = generateKey()
unknown_string = ("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28" +
"gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvI" +
"HNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").decode('base64')

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
    return cipher.encrypt(bytes(plaintext))

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

def encryption_oracle(plaintext):
    prependBytes = randbytes(random.randint(5,10))
    appendBytes = randbytes(random.randint(5,10))
    plaintext = padBlocks((prependBytes + plaintext + appendBytes), AES.block_size)
    AES_mode = random.randint(1,2)
    key = generateKey()

    if AES_mode == AES.MODE_CBC:
        iv = bytearray(randbytes(16))
        ciphertext = encrypt_AES_CBC(plaintext, key, iv)
    else:
        ciphertext = encrypt_AES_ECB(plaintext, key)

    return {'mode': AES_mode, 'ciphertext': ciphertext}

def detect_AES_mode(ciphertext):
    ciphertext = bytearray.fromhex(bytes(ciphertext).encode('hex'))
    detect = detectECB(ciphertext)
    if detect:
        return AES.MODE_ECB
    else:
        return AES.MODE_CBC

def encrypt_ECB_unknown_string(test_input):
    plaintext = padBlocks((test_input + unknown_string), AES.block_size)
    ciphertext = encrypt_AES_ECB(plaintext, unknown_key)
    return ciphertext

def detect_cipher_blocksize(cipher_function):
    base_length = len(bytes(cipher_function('')))
    initial_diff = len(bytes(cipher_function('A'))) - (base_length+1)
    count = 0
    for i in range(2, 255):
        length = len(bytes(cipher_function('A'*i)))
        diff = (length) - (base_length + i)
        if diff == initial_diff:
            return count+1
        count += 1

def detect_cipher_ECB(cipher_function):
    blocksize = detect_cipher_blocksize(cipher_function)
    result =  detectECB(cipher_function('A'*blocksize*3))
    return bool(result)

def break_ECB_BAAT(cipher_function):
    message_length = len(bytes(cipher_function('')))
    plaintext = bytearray()

    for count in range(message_length):
        base_input = ('A' * (message_length - (count+1)))
        ciphertext = bytes()

        for i in range(256):
            # i is the plaintext byte
            test_input = base_input  + bytes(plaintext) + chr(i)
            ciphertext = bytes(cipher_function(test_input)[:message_length])
            if ciphertext == bytes(cipher_function(base_input)[:message_length]):
                plaintext.append(chr(i))
                break
    return depadBlocks(bytes(plaintext))

print(break_ECB_BAAT(encrypt_ECB_unknown_string))

def test_encryption_oracle():
    contents = ''.join(['a']*100)
    plaintext = contents
    result = encryption_oracle(plaintext)
    print(result)
    return result['ciphertext']

def test_detect_AES_mode():
    ciphertext = test_encryption_oracle()
    print("MODE: %d" % detect_AES_mode(ciphertext))

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
