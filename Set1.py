import enchant
from Crypto.Cipher import AES
from collections import defaultdict

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
    return all(ord(c) < 128 and ord(c) > 31 for c in s)

# Returns the percentage of valid ascii characters in a given text.
def ascii_test(text):
    good = 0.0
    for c in text:
        if is_ascii(c):
            good += 1.0
    return good/len(text)*100.0

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

# Simple chi-squared test. Python implementation of the algo presented at:
# https://crypto.stackexchange.com/questions/30209/developing-algorithm-for-detecting-plain-text-via-frequency-analysis
def english_test(text):
    english_freq = [0.0651738, 0.0124248, 0.0217339, 0.0349835,
    0.1041442, 0.0197881, 0.0158610, 0.0492888,
    0.0558094, 0.0009033, 0.0050529, 0.0331490,
    0.0202124, 0.0564513, 0.0596302, 0.0137645,
    0.0008606, 0.0497563, 0.0515760, 0.0729357,
    0.0225134, 0.0082903, 0.0171272, 0.0013692,
    0.0145984, 0.0007836, 0.1918182]

    count = [0] * 27
    ignored = 0

    for i in range(len(text)):
        c = ord(text[i])
        if c == 32:
            count[26] += 1      # Space
        elif c >= 65 and c <= 90:
            count[c - 65] += 1  # uppercase A-Z
        elif c >= 97 and c <= 122:
            count[c - 97] += 1  # lowercase a-z
        elif c >= 33 and c <= 126:
            ignored += 1        # numbers and punctuation
        elif c == 9 or c == 10 or c == 13:
            ignored += 1        # TAB, CR, LF
        else:
            return float('inf')

    score = 0
    length = len(text) - ignored
    for i in range(27):
        observed = count[i]
        expected = length * english_freq[i]
        difference = observed - expected
        score += difference*difference / expected

    return score

# Takes a bytearray of ciphertext encrypted with single-byte XOR
# Outputs the single-byte key and the plaintext
def singleByteXORBruteforce(cipherbytes):
    hiscore = float("inf")
    foundKey = None
    foundPlaintext = ""

    for key in range(32, 128):
        bytekey = [key] * len(cipherbytes)
        plaintext = byteXOR(cipherbytes, bytekey)
        try:
            score = english_test(plaintext)
        except:
            score = float('inf')
        if(score < hiscore):
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

# Splits a bytearray into chunks of size blocksize.
def generateBlocks(byteciphertext, blocksize):
    blocks = []
    blockoffset = 0
    for i in range(len(byteciphertext)/blocksize):
        blocks.append(byteciphertext[(blocksize*blockoffset):(blocksize*(blockoffset+1))])
        blockoffset += 1 # Here lies my sanity. RIP. This line used to read `blockoffset += blocksize` and it broke EVERYTHING. FOR DAYS.
    blocks.append(byteciphertext[(blocksize*blockoffset):])
    return blocks

# Creates transposed blocks representing the columns of the blocks given as rows.
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

# Breaks vigenere ciphers.
def breakRepeatingKeyXOR(hexciphertext):
    byteciphertext = bytearray.fromhex(hexciphertext)
    keysizes = findKeySizes(byteciphertext)
    hiscore = float("inf")
    bestKey = None
    bestPlaintext = None

    for keysize, hamDist in keysizes:
        keysize = int(keysize)
        blocks = generateBlocks(byteciphertext, keysize)
        transposedBlocks = transposeBlocks(blocks)

        foundKey = []
        badKey = False

        for block in transposedBlocks:
            result = singleByteXORBruteforce(block)
            if result['key'] is None:
                badKey = True
                break
            foundKey.append(result['key'])

        if not badKey:
            plaintext = repeatingKeyXOR(byteciphertext, foundKey).decode('hex')
            score = english_test(plaintext)
            if score < hiscore:
                hiscore = score
                bestKey = ''.join(foundKey)
                bestPlaintext = plaintext

    return {'key': bestKey, 'plaintext': bestPlaintext, 'score': hiscore}

# Tests the breakRepeatingKeyXOR function on the file set1chal6.txt
def testBreakRepeatingKeyXOR():
    contents = ""

    with open('set1chal6.txt') as f:
        for line in f.readlines():
            contents += line

    hexciphertext = b64StrToHexStr(contents)
    result = breakRepeatingKeyXOR(hexciphertext)
    print("\nKey:\n %s\n\nPlaintext:\n %s" % (result['key'], result['plaintext']))

# Takes the bytes representation of ciphertext and key and returns the plaintext.
def decrypt_AES_ECB(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

def test_decrypt_AES_ECB():
    contents = ""

    with open('set1chal7.txt') as f:
        for line in f.readlines():
            contents += line
    ciphertext = contents.decode('base64')
    key = "YELLOW SUBMARINE"
    print(decrypt_AES_ECB(ciphertext, key))

def detectECB(ciphertext):
    repeats = defaultdict(lambda: -1)
    for i in range(0, len(ciphertext), AES.block_size):
        block = bytes(ciphertext[i:i+AES.block_size])
        repeats[block] += 1
    score = sum(repeats.values())

    return score

def testDetectECB():
    scores = []

    with open('set1chal8.txt') as f:
        for line in f.readlines():
            scores.append(detectECB(bytearray.fromhex(line.strip('\r\n'))))

    print(scores)
