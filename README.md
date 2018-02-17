# G-Writer
Breaking the WWII Geheimschreiber

### Background

The [Geheimschreiber](https://en.wikipedia.org/wiki/Siemens_and_Halske_T52) was a WWII cipher machine (successor to the Enigma). The machine consisted of 10 rotors of different sizes with bits that would perform transformations on the input text.

For a given input character, the G-Writer would:
- lookup the 5-bit binary index of a character in the following alphabet:
`2T3O4HNM5LRGIPCVEZDBSYFXAWJ6UQK7`
- XOR those bits with 5 bits from specific rotors
- Swap the output bits according to the following:
  - if `bit #5 = 1`, swap bits `0` and `4`
  - if `bit #6 = 1`, swap bits `0` and `1`
  - if `bit #7 = 1`, swap bits `1` and `2`
  - if `bit #8 = 1`, swap bits `2` and `3`
  - if `bit #9 = 1`, swap bits `3` and `4`
- Rotate all rotors by 1 bit

The 10 rotors were of lengths `{47, 53, 59, 61, 64, 65, 67, 69, 71, 73}`, and the G-Writer had a switchboard that configured the order that the rotors were read.


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
receiver = sender.copy()

plaintext = 'UMUM4VEVE35KING4HENRY4IV35'
ciphertext = sender.encrypt(plaintext) # ciphertext = F4QR72QKRBZFTECBNMTYI6T2XF
new_plaintext = receiver.decrypt(ciphertext)
plaintext == new_plaintext # True
```

Also implemented is a `gwriter.crack()` function, which yields an instantiated `GWriter` class object given ciphertext messages and (optionally) the corresponding plaintext messages.

Example:

```python
from gwriter import crack

with open('./ciphertext_messages.txt', 'r') as f:
    ciphertext_messages = f.read()

success, receiver = crack(ciphertext_messages=ciphertext_messages)

if success:  
    ciphertext_messages = ciphertext_messages.strip().splitlines()
    decrypted_messages = receiver.decrypt(ciphertext_messages)

    with open('./decrypted_messages.txt','w') as f:
        f.writelines(decrypted_messages)
```

The provided `cli.py` offers a command-line interface for the `gwriter.crack` function:

```sh
python cli.py -c <path_to_ciphertext> -p <optional_path_to_plaintext>
```

### The Crack

Despite the apparent complexity of the G-Writer, this crack is (given enough sample text) able to break the ciphertext instantly.

**Observations**:

- The ciphertext characters `2` and `7` are binary indicies `00000` and `11111` respectively, which are not affected by any swapping actions.  Therefore, these ciphertext characters can be XOR'd directly to the corresponding plaintext character to discover the exact rotor bits in those locations.
- All messages begin with the string `UMUM4VEVE35` and end with `35`. Given a large enough sample ciphertext, the attack can infer significant portions of the plaintext and, thereby, solve the XOR and swap rotors.
- If 4/5 XOR bits are known, the 5th can be inferred by comparing the sum of binary digits between the ciphertext and the known XOR'd plaintext.  If the sums match, the 5th XOR bit is a 0, else it is a 1. This works because swapping can only arrange the positions of bits, but not their sum.

**Methodology:**

- Either using known plaintext or inferred (partial) plaintext from message prefix/suffix, locate all `2` and `7` characters in ciphertext and XOR with plaintext to discover a large portion of rotor bits.  As rotor lengths are not yet known, store these known XOR bits for `n` cipher characters into a `[10 x n]` array.
- Per rotor, traverse known XOR rotor bits and check each bit at position `i` to the bit at position `i + rotor_length` to eliminate rotors who's bits do not repeat. This significantly reduces the permutations of rotor lengths available to the XOR rotors. Sort these permutations according to count of positive matches to push likely rotor length permutations early in the iterations.
- Per possible XOR rotor configuration:
  - assume those rotor lengths are correct and fill in any bits where the other 4 XOR bits are known.
  - Per possible XOR rotor configurations, attempt all possible swap rotor orientations, and, per rotor, store possible bit values. Once complete, those bits with only one possible value are persisted
- Use this completed rotor configuration to encrypt the known plaintext and compare against corresponding ciphertext, and return successfully if encryption matches.
