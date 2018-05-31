import codecs
import enchant

# Converts a hex string to its base64 string representation.
def hexStrToB64Str(hexStr):
  return codecs.encode(codecs.decode(hexStr, "hex"), "base64").decode()

# Converts a decimal integer to its hex string representation
# without the leading '0x'.
def prettyHex(integer):
  return hex(integer)[2:]

# XORs two hex strings and returns the resulting hex string.
def hexStrXOR(h1, h2):
  h1 = int(h1, 16)
  h2 = int(h2, 16)
  return prettyHex(h1^h2)

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

# Takes a hex encoded ciphertext encrypted with single-byte XOR
# Outputs the single-byte key and the plaintext
def singleByteXORBruteforce(hexciphertext):
    cipherbytes = bytearray.fromhex(hexciphertext)
    hiscore = 0
    foundKey = None
    foundPlaintext = ""

    for key in range(256):
        bytekey = [key] * len(cipherbytes)
        plaintext = byteXOR(cipherbytes, bytekey)
        try:
            score = checkEnglish(plaintext)
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
        results.append(singleByteXORBruteforce(hexciphertext.strip('\r\n')))

    bestResult = None

    for result in results:
        if not bestResult or result['score'] > bestResult['score']:
            bestResult = result

    return bestResult

# Converts a string to a binary string.
def strToBinStr(st):
    return ' '.join(map(bin,bytearray(st, encoding='utf8')))

# Binary XORs two strings and returns the resulting string.
def strXOR(s1, s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

# Calculates number of bits required to be flipped between two strings.
def hammingDistance(s1, s2):
    xorRes = strXOR(s1, s2)
    b = strToBinStr(xorRes)
    count = 0
    for bit in b:
        if bit == '1':
            count += 1
    return count
