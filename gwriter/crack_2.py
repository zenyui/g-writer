import os
from itertools import permutations
from . import gwriter
import logging

def crack_2(plaintext, ciphertext, rotor_lengths):
    logger = logging.getLogger()
    logger.info('Start attack 2')
    plaintext_concat = ''.join(plaintext.strip().splitlines())
    ciphertext_concat = ''.join(ciphertext.strip().splitlines())

    # write bit streams into continuous separate arrays for each rotor
    rotor_placeholders = [[] for _ in range(10)]

    for i in range(len(ciphertext_concat)):
        p = plaintext_concat[i]
        c = ciphertext_concat[i]

        pi = gwriter.ALPHABET_MAP[p]
        ci = gwriter.ALPHABET_MAP[c]

        if ci in (0,31):
            bi = ci ^ pi
            for j in range(5):
                rotor_placeholders[j].append(gwriter.nth_bit(bi,4-j))
        else:
            for j in range(5):
                rotor_placeholders[j].append(None)

    rotors = [{} for _ in range(10)]

    for rotor_id in range(5):

        rotor_placeholder = rotor_placeholders[rotor_id]
        rotor = rotors[rotor_id]
        rotor_length = rotor_lengths[rotor_id]

        for ix, b in enumerate(rotor_placeholder):
            target_ix = ix % rotor_length

            if (b is not None) and (target_ix not in rotor):
                rotor[target_ix] = b

            if len(rotor)==rotor_length:
                break

    # solve left side
    for ix in range(len(plaintext_concat)):

        if all(rotor_lengths[rotor_id] == len(r) for rotor_id, r in enumerate(rotors[:5])):
            break

        xor_bits = 0
        missing_ids = []

        for rotor_id, rotor in enumerate(rotors[:5]):
            rotor_bit = rotor.get(ix % rotor_lengths_left[rotor_id])
            if rotor_bit == 1:
                xor_bits += (1 << (4-rotor_id))
            elif rotor_bit is None:
                # it assumes a zero
                missing_ids.append(rotor_id)

        # if xor output has same pre-swap digits, sum of digits will match
        if gwriter.sum_binary_digits(plain_bits ^ xor_bits) == gwriter.sum_binary_digits(cipher_bits):
            fill_value = 0
        else:
            fill_value = 1

        rotors[missing_id][ix % rotor_lengths_left[missing_id]] = fill_value

    # solve right side
    for ix in range(len(plaintext_concat)):

        tmp_swap = [set() for _ in range(5)] # storage for bits

        d = gwriter.ALPHABET_MAP[ciphertext_concat[ix]] # cipher int
        a = gwriter.ALPHABET_MAP[plaintext_concat[ix]] # plain int

        # xor bits
        b = 0
        for rotor_id, rotor in enumerate(rotors[:5]):
            b += (rotor[ix%rotor_lengths[rotor_id]] << (4-rotor_id))

        # xor output
        c = a ^ b

        # brute force swap bits, store possible bits per rotor in a set
        for i in range(32):
            skip = False
            for rotor_id in range(5,10):
                bit_id = rotor_id-5
                rotor_bit = rotors[rotor_id].get(ix%rotor_lengths[rotor_id])
                if (rotor_bit is not None) and (rotor_bit != gwriter.nth_bit(i,4-bit_id)):
                    skip = True
                    break

            if skip:
                continue

            tmp_c = c
            if gwriter.nth_bit(i,4):
                tmp_c = gwriter.swap_bits_left(tmp_c,0,4)
            if gwriter.nth_bit(i,3):
                tmp_c = gwriter.swap_bits_left(tmp_c,0,1)
            if gwriter.nth_bit(i,2):
                tmp_c = gwriter.swap_bits_left(tmp_c,1,2)
            if gwriter.nth_bit(i,1):
                tmp_c = gwriter.swap_bits_left(tmp_c,2,3)
            if gwriter.nth_bit(i,0):
                tmp_c = gwriter.swap_bits_left(tmp_c,3,4)

            if tmp_c == d:
                for tix, t in enumerate(tmp_swap):
                    t.add(gwriter.nth_bit(i, 4-tix))

        # persist swap rotor bits if only 1 bit is possible from brute force
        for s_id, s in enumerate(tmp_swap):
            if len(s) == 1:
                bit = s.pop()
                rotor_id = s_id+5
                rotors[rotor_id][ix%rotor_lengths[rotor_id]] = bit

    # convert rotor bit dictionaries to arrays
    rotor_data = [[r[k] for k in sorted(r.keys())]for r in rotors]

    # perform encryption per character, short-circuit if doesn't match ciphertext
    sender = gwriter.GWriter(rotors_bits=rotor_data)

    comparison = (
        sender.encrypt(plaintext_concat[c]) == ciphertext_concat[c]
        for c in range(len(plaintext_concat))
    )

    if all(comparison):
        logger.info('Success')
        sender.reset()
        return True, sender

    logger.info('Failure')
    return False, None
