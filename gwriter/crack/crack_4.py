import os
import logging
from itertools import permutations
from gwriter import gwriter

def crack_4(ciphertext):
    logger = logging.getLogger()
    logger.info('Begin Attack 4')

    ciphertext_messages = ciphertext.strip().splitlines()

    logger.info('Create fake plaintext')
    UNKNOWN = '*'

    plaintext_prefix = 'UMUM4VEVE35'
    plaintext_suffix = '35'
    plaintext_filler_len = len(plaintext_prefix) + len(plaintext_suffix)

    plaintext_messages = []

    for c in ciphertext_messages:
        p = plaintext_prefix + \
            UNKNOWN * (len(c) - plaintext_filler_len) + \
            plaintext_suffix
        plaintext_messages.append(p)

    plaintext_concat = ''.join(plaintext_messages)
    ciphertext_concat = ''.join(ciphertext_messages)

    # write bit streams into continuous separate arrays for each rotor
    logger.info('Solving XOR bits...')
    rotor_placeholders = [[] for _ in range(5)]

    for i in range(len(ciphertext_concat)):
        p = plaintext_concat[i]
        c = ciphertext_concat[i]
        ci = gwriter.ALPHABET_MAP[c]

        if p != UNKNOWN and ci in (0,31):
            pi = gwriter.ALPHABET_MAP[p]
            bi = ci ^ pi
            for j in range(5):
                rotor_placeholders[j].append(gwriter.nth_bit(bi,4-j))
        else:
            for j in range(5):
                rotor_placeholders[j].append(None)

    # determine possible rotor permutations
    possible_rotor_order = []
    for rp in rotor_placeholders[:5]:
        possible = {}
        for length in gwriter.ROTOR_LENGTHS:
            possible[length] = 0
            for ix in range(len(rp)-length):
                c1 = rp[ix]
                if not c1 is None:
                    c2 = rp[ix + length]
                    if (not c2 is None):
                        if (c1 != c2):
                            del possible[length]
                            break
                        else:
                            possible[length] += 1

        possible = sorted(possible, key=lambda x: possible[x] * -1)
        possible_rotor_order.append(possible)

    rotor_permutations = []
    for rotor_permutation in gwriter.nested_permutations(possible_rotor_order):
        if len(set(rotor_permutation))==5:
            rotor_permutations.append(rotor_permutation)

    logger.info('Found {} possible XOR rotor permutations'.format(len(rotor_permutations)))

    iterations = 0
    all_done = False

    for rotor_lengths_left in rotor_permutations:

        logger.info('Trying with XOR rotors {}'.format(rotor_lengths_left))

        rotors = [{} for _ in range(10)]

        # for each rotor, write known bits into rotor given predicted rotor length
        for rotor_id in range(5):
            rotor_placeholder = rotor_placeholders[rotor_id]
            rotor = rotors[rotor_id]
            rotor_length = rotor_lengths_left[rotor_id]

            for ix, b in enumerate(rotor_placeholder):
                target_ix = ix % rotor_length
                if (b is not None) and (target_ix not in rotor):
                    rotor[target_ix] = b

        # solve left side
        logger.info('Solving XOR rotor bits')
        for ix in range(len(plaintext_concat)):

            if all(rotor_lengths_left[rotor_id] == len(r) for rotor_id, r in enumerate(rotors[:5])):
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

            if len(missing_ids)==1:
                missing_id = missing_ids[0]
                plain_char = plaintext_concat[ix]
                if plain_char == UNKNOWN:
                    continue

                plain_bits = gwriter.ALPHABET_MAP[plain_char]
                cipher_bits = gwriter.ALPHABET_MAP[ciphertext_concat[ix]]

                # if xor output has same pre-swap digits, sum of digits will match
                if gwriter.sum_binary_digits(plain_bits ^ xor_bits) == gwriter.sum_binary_digits(cipher_bits):
                    fill_value = 0
                else:
                    fill_value = 1

                rotors[missing_id][ix % rotor_lengths_left[missing_id]] = fill_value

        # compute possible right rotors given left rotors and brute force
        possible_right_rotors = set(gwriter.ROTOR_LENGTHS).difference(set(rotor_lengths_left))
        possible_right_rotors = permutations(possible_right_rotors,5)
        possible_right_rotors = list(map(list, possible_right_rotors))

        logger.info('Brute force {} possible swap rotor orientations'.format(len(possible_right_rotors)))

        # for each possible swap rotor lengths
        for rotor_lengths_right in possible_right_rotors:

            logger.info('Attempting with swap rotors {}'.format(rotor_lengths_right))

            # set right rotors and lengths
            rotor_lengths = rotor_lengths_left + rotor_lengths_right
            rotors = rotors[:5] + [{} for _ in range(5)]

            iterations += 1

            # solve right side
            for ix in range(len(plaintext_concat)):

                # quit early if length of swap rotors == desired rotors lengths
                if all(len(rotor)==rotor_lengths_right[rotor_id] for rotor_id, rotor in enumerate(rotors[5:])):
                    break

                plain_char = plaintext_concat[ix]
                if plain_char == UNKNOWN:
                    continue

                d = gwriter.ALPHABET_MAP[ciphertext_concat[ix]] # cipher int
                a = gwriter.ALPHABET_MAP[plain_char] # plain int

                tmp_swap = [set() for _ in range(5)] # storage for bits

                # xor bits
                b = 0
                for rotor_id, rotor in enumerate(rotors[:5]):
                    b += (rotor[ix%rotor_lengths[rotor_id]] << (4-rotor_id))

                # xor output
                c = a ^ b

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

                for s_id, s in enumerate(tmp_swap):
                    if len(s) == 1:
                        bit = s.pop()
                        rotor_id = s_id+5
                        rotors[rotor_id][ix%rotor_lengths[rotor_id]] = bit

            rotor_data = [[r[k] for k in sorted(r.keys())]for r in rotors]

            sender = gwriter.GWriter(rotors_bits=rotor_data)
            comparison = (
                sender.encrypt(p,UNKNOWN) in (ciphertext_concat[cix], UNKNOWN)
                for cix,p in enumerate(plaintext_concat)
            )

            if all(comparison):
                logger.info('success in {} brute force iterations'.format(iterations))
                sender.reset()
                all_done = True
                return True, sender

    logger.info('failed after {} iterations'.format(iterations))
    return False, None
