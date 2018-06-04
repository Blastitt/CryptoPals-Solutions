import codecs
import enchant

# Converts a hex string to its base64 representation.
def hexStrToB64Str(hexStr):
  return hexStr.decode('hex').encode('base64')

# Converts a base64 string to its hex representation.
def b64StrToHexStr(b64Str):
    return b64Str.decode('base64').encode('hex')

# Converts a decimal integer to its hex string representation
# without the leading '0x'.
def prettyHex(integer):
  return hex(integer)[2:]

# XORs two bytearrays and returns the resulting bytes
def byteXOR(b1, b2):
    b = bytearray(len(b1))
    for i in range(len(b1)):
        b[i] = b1[i] ^ b2[i]
    return bytes(b)

# Checks if a given string contains only ascii characters
def is_ascii(s):
    return all(ord(c) < 128 for c in s)

# Returns the percentage of valid English words in a given text.
# Likes to log to console when funky characters are passed in.
def checkEnglish(text):
    d = enchant.Dict("en_US")
    numWords = len(text.split())
    numEnglishWords = 0.0
    for word in text.split():
        if not is_ascii(word):
            continue
        if d.check(word):
          numEnglishWords += 1.0
    return numEnglishWords/numWords * 100.0

# Actual letter frequency analysis method.
# Taken from https://github.com/danepowell/cryptopals/
# Score a string based on enlish letter frequencies.
def english_test(str1):
    frequencies = {'a':0.08167, 'b':0.01492, 'c':0.02782, 'd':0.04253, 'e':0.12702, 'f':0.02228, 'g':0.02015, 'h':0.06094, 'i':0.06966, 'j':0.00153, 'k':0.00772, 'l':0.04025, 'm':0.02406, 'n':0.06749, 'o':0.07507, 'p':0.01929, 'q':0.00095, 'r':0.05987, 's':0.06327, 't':0.09056, 'u':0.02758, 'v':0.00978, 'w':0.02360, 'x':0.00150, 'y':0.01974, 'z':0.00074, ' ':0.21}
    str1 = str1.lower()
    ss = 0.0
    for letter in frequencies.iterkeys():
        expected_frequency = frequencies[letter]
        actual_frequency = str1.count(letter)
        ss += pow(actual_frequency - expected_frequency, 2)
    return ss

# Takes a bytearray of ciphertext encrypted with single-byte XOR
# Outputs the single-byte key and the plaintext
def singleByteXORBruteforce(cipherbytes):
    hiscore = 0
    foundKey = None
    foundPlaintext = ""

    for key in range(256):
        bytekey = [key] * len(cipherbytes)
        plaintext = byteXOR(cipherbytes, bytekey)
        try:
            score = english_test(plaintext)
        except:
            score = 0

        if(score > hiscore):
            hiscore = score
            foundKey = chr(key)
            foundPlaintext = plaintext

    return {'key': foundKey, 'plaintext': foundPlaintext, 'score': hiscore}

# Returns a list of all lines in a given file
def getLines(filename):
    f = open(filename, 'r')
    lines = f.readlines()
    f.close()
    return lines

# Detects which in a given list of ciphertexts has been encrypted
# with single-byte XOR and decrypts it.
def singleByteXORDetect(hexciphertexts):
    results = []
    for hexciphertext in hexciphertexts:
        byteciphertext = bytearray.fromhex(hexciphertext.strip('\r\n'))
        results.append(singleByteXORBruteforce())

    bestResult = None

    for result in results:
        if not bestResult or result['score'] > bestResult['score']:
            bestResult = result

    return bestResult

# Turns an ascii string into a hex string
def asciiToHex(ascii):
    return ''.join(prettyHex(ord(a)) for a in ascii)

# Implementation of repeating key XOR. Returns the ciphertext as a hex string.
def repeatingKeyXOR(bytetext, bytekey):
    fullkey = bytearray(0)
    pos = 0
    while len(fullkey) < len(bytetext):
        if pos >= len(bytekey):
            pos = 0
        fullkey.append(bytekey[pos])
        pos += 1

    byteciphertext = byteXOR(bytetext, fullkey)
    hexciphertext = byteciphertext.encode('hex')
    return hexciphertext

# Converts a string to a string of bits.
def stringToBits(st):
    return ' '.join(map(bin,bytearray(st, 'utf-8')))

# Calculates number of bits required to be flipped between two bytearrays.
def hammingDistance(b1, b2):
    xorRes = byteXOR(b1, b2)
    b = stringToBits(xorRes)
    count = 0
    for bit in b:
        if bit == '1':
            count += 1
    return count

# Returns a list of keysizes in order of likelihood of being correct
def findKeySizes(byteciphertext):
    keysizes = {}

    maxKeySize = min(len(byteciphertext)/4, 40) + 1

    for keysize in range(2, maxKeySize):
        block1 = byteciphertext[:keysize]
        block2 = byteciphertext[keysize:(keysize*2)]
        block3 = byteciphertext[(keysize*2):(keysize*3)]
        block4 = byteciphertext[(keysize*3):(keysize*4)]
        score = (hammingDistance(block1, block2) + hammingDistance(block2, block3) + hammingDistance(block3, block4))/(keysize*3)

        keysizes[str(keysize)] = score

    return sorted(keysizes.iteritems(), key=lambda (k,v): (v,k))

def generateBlocks(byteciphertext, blocksize):
    blocks = []
    blockoffset = 0
    for i in range(len(byteciphertext)/blocksize):
        blocks.append(byteciphertext[(blocksize*blockoffset):(blocksize*(blockoffset+1))])
        blockoffset += blocksize
    blocks.append(byteciphertext[(blocksize*blockoffset):])
    return blocks

def transposeBlocks(blocks):
    transposed = [None] * len(blocks[0])
    for i in range(len(transposed)):
        transposed[i] = []
        for block in blocks:
            try:
                transposed[i].append(block[i])
            except:
                pass
    return transposed

def breakRepeatingKeyXOR(hexciphertext):
    byteciphertext = bytearray.fromhex(hexciphertext)
    #keysizes = findKeySizes(byteciphertext)
    keysizes = [('29', 2)]
    hiscore = 0
    bestKey = None
    bestPlaintext = None

    for keysize, hamDist in keysizes:
        keysize = int(keysize)
        blocks = generateBlocks(byteciphertext, keysize)
        transposedBlocks = transposeBlocks(blocks)

        foundKey = []

        for block in transposedBlocks:
            foundKey.append(singleByteXORBruteforce(block)['key'])
        print("%s" % ''.join(foundKey))
        plaintext = repeatingKeyXOR(byteciphertext, foundKey).decode('hex')
        score = english_test(plaintext)
        if score > hiscore:
            hiscore = score
            bestKey = ''.join(foundKey)
            bestPlaintext = plaintext

    return {'key': bestKey, 'plaintext': bestPlaintext, 'score': hiscore}

contents = ""
with open('set1chal6.txt') as f:
    for line in f.readlines():
        contents += line.strip('\r\n')

hexciphertext = b64StrToHexStr(contents)
result = breakRepeatingKeyXOR(hexciphertext)
print("\nKey:\n %s\n\nPlaintext:\n %s" % (result['key'], result['plaintext']))
