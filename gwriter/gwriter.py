ALPHABET = '2T3O4HNM5LRGIPCVEZDBSYFXAWJ6UQK7'
ALPHABET_MAP = {letter:index for index,letter in enumerate(ALPHABET)}
ROTOR_LENGTHS = (47, 53, 59, 61, 64, 65, 67, 69, 71, 73)

class GWriter():
    '''python implementation of Nazi Geheimschreiber aka G-Writer'''

    def __init__(self, rotors_bits, rotor_offsets=None):
        self.iterations = 0

        if not rotor_offsets:
            rotor_offsets = [0] * len(rotors_bits)

        self.rotors = []
        for i,k in enumerate(range(len(rotors_bits))):
            rotor = Rotor(
                bits=rotors_bits[k],
                offset=rotor_offsets[i],
                gwriter=self
            )
            self.rotors.append(rotor)

    def to_str(self):
        output = 'Gwriter Rotors:\n'
        rotors = [r.to_str() for r in self.rotors]
        return output + '\n'.join(rotors)

    def reset(self):
        self.iterations = 0

    def try_encrypt_char(self, plainchar):
        '''if unknown character, just increment but don't decrypt'''
        if not plainchar in ALPHABET_MAP:
            self.iterations += 1
            return None
        else:
            return self.encrypt(plainchar)

    def encrypt(self, plaintext, skip_chars=None):
        if isinstance(plaintext, (list, tuple)):
            return [self.encrypt(plaintext=msg, skip_chars=skip_chars) for msg in plaintext]

        cipher_text = ''

        for letter in plaintext:

            if skip_chars and letter in skip_chars:
                cipher_text += letter

            else:
                # get first 5 rotor bits
                b = sum(rotor.read()<<(4-i) for i,rotor in enumerate(self.rotors[:5]))

                # get char index in alphabet
                c = ALPHABET_MAP[letter]

                # do XOR
                c ^= b

                # do swaps
                if self.rotors[5].read():
                    c = swap_bits_left(c,0,4)
                if self.rotors[6].read():
                    c = swap_bits_left(c,0,1)
                if self.rotors[7].read():
                    c = swap_bits_left(c,1,2)
                if self.rotors[8].read():
                    c = swap_bits_left(c,2,3)
                if self.rotors[9].read():
                    c = swap_bits_left(c,3,4)

                cipher_text += ALPHABET[c]

            self.iterations += 1

        return cipher_text

    def decrypt(self, ciphertext, skip_chars=None):
        if isinstance(ciphertext, (list, tuple)):
            return [self.decrypt(msg,skip_chars) for msg in ciphertext]

        plaintext = ''

        for letter in ciphertext:
            if skip_chars and letter in skip_chars:
                plaintext += skip_chars

            else:
                # get first 5 rotor bits
                b = sum(rotor.read()<<(4-i) for i,rotor in enumerate(self.rotors[:5]))

                # get char index in alphabet
                c = ALPHABET_MAP[letter]

                # reverse swaps
                if self.rotors[9].read():
                    c = swap_bits_left(c,3,4)
                if self.rotors[8].read():
                    c = swap_bits_left(c,2,3)
                if self.rotors[7].read():
                    c = swap_bits_left(c,1,2)
                if self.rotors[6].read():
                    c = swap_bits_left(c,0,1)
                if self.rotors[5].read():
                    c = swap_bits_left(c,0,4)

                # do reversing XOR
                c ^= b
                plaintext += ALPHABET[c]
                
            self.iterations += 1

        return plaintext

class Rotor():
    '''gwriter rotor class'''
    def __init__(self,bits,gwriter,offset=0):
        self.bits = tuple(int(b) for b in bits)
        self.length = len(self.bits)
        self.offset = offset
        self.gwriter=gwriter

    def to_str(self):
        return 'len: {length}, offset: {offset}, bits: {bits}'.format(
            length=self.length,
            offset=self.offset,
            bits=''.join(map(str, self.bits))
        )

    def read(self):
        '''read current bit given gwriter'''
        return self[self.gwriter.iterations]

    def __getitem__(self, n):
        return self.bits[(self.offset + n) % self.length]

def swap_bits(n,i,j):
    '''swap bits at i,j position from right'''
    bit_1 = (n >> i) & 1
    bit_2 = (n >> j) & 1
    x = bit_1 ^ bit_2
    x = (x<<i) | (x<<j)
    return n ^ x

def swap_bits_left(n,i,j,length=5):
    '''swap bits i,j from the left'''
    return swap_bits(n,length-i-1,length-j-1)

def nth_bit(i,n):
    '''return nth bit of integer i'''
    return (i&(1<<n))>>n

def bin_5(i):
    '''return 5-digit binary representation of integer i'''
    return '{0:05b}'.format(i)

def nested_permutations(arrays, i=0):
    '''given array of arrays, return all permutations of single digits from each
    sub-array'''
    if i == len(arrays):
        return [[]]

    res_next = nested_permutations(arrays, i+1)
    res = []
    for n in arrays[i]:
        for arr in res_next:
            res.append([n] + arr)
    return res

def sum_binary_digits(integer, length=5):
    '''given an integer and length, return the sum of each binary digit'''
    return sum(nth_bit(integer, n) for n in range(length))
