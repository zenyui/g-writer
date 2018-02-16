# G-Writer
Breaking the WWII Geheimschreiber

### Background

The [Geheimschreiber](https://en.wikipedia.org/wiki/Siemens_and_Halske_T52) was a WWII cipher machine (successor to the Enigma). The machine consisted of 10 rotors of different sizes with bits that would perform transformations on the input text.

For a given input character, the G-Writer would:
- lookup the 5-bit binary index of a character in the following alphabet: `2T3O4HNM5LRGIPCVEZDBSYFXAWJ6UQK7` (00000 to 11111)
- XOR those bits with 5 bits from specific rotors
- Swap the output bits according to the following:
  - if `bit #5 = 1`, swap bits `0` and `4`
  - if `bit #6 = 1`, swap bits `0` and `1`
  - if `bit #7 = 1`, swap bits `1` and `2`
  - if `bit #8 = 1`, swap bits `2` and `3`
  - if `bit #9 = 1`, swap bits `3` and `4`
- Rotate all rotors by 1 bit

The 10 rotors were of lengths `{47, 53, 59, 61, 64, 65, 67, 69, 71, 73}`, and the G-Writer had a switchboard that configured the order that those rotors would be read.


### Usage

The repository implements a `gwriter.GWriter` class in Python 3.6 that, given the rotor configuration, can encrypt and decrypt messages.

Example:
```python
from gwriter import GWriter

rotors_bits = [
    '00110010110000001111011111011010101100110101000',
    '10111111001110000110011010000101010111110100001110100',
    '11110110110001111110001101011001001011000011011011011110010',
    '1111111110001101110101100000101100110011001001100010011101101',
    '1101110000101000000101000010110101111010010100100010011101100100',
    '10100110000011011110111011001110000101111001110011100111000001001',
    '0100100001010101011001110011001001110000101101111001010010110001011',
    '100101011100000000011000011001010100110000110100111011000000101001111',
    '01000011101101101001000010110010011101001000110110011100110000011110001',
    '0110011111111110101111010110100000111010000001101101100010101100110001010',
]

sender = GWriter(rotors_bits=rotors_bits)
receiver = GWriter(rotors_bits=rotors_bits)

ciphertext = sender.encrypt('UMUM4VEVE35KING4HENRY4IV35') # ciphertext = F4QR72QKRBZFTECBNMTYI6T2XF
plaintext = receiver.decrypt(ciphertext)
```
