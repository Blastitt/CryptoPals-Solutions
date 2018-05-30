import codecs
import enchant

# Converts a hex string to its base64 string representation.
def hexStrToB64Str(hexStr):
  return codecs.encode(codecs.decode(hexStr, "hex"), "base64").decode()

# Converts a decimal integer to its hex string representation without the leading '0x'.
def prettyHex(integer):
  return hex(integer)[2:]

# XORs two hex strings and returns the resulting hex string.
def hexStrXOR(h1, h2):
  h1 = int(h1, 16)
  h2 = int(h2, 16)
  return prettyHex(h1^h2)

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

# Returns the percentage of valid English words in a given text.
def checkEnglish(text):
  d = enchant.Dict("en_US")
  numWords = len(text.split())
  numEnglishWords = 0.0
  for word in text.split():
    if d.check(word):
      numEnglishWords += 1.0
  return numEnglishWords/numWords * 100.0
