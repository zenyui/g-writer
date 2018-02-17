import os
from itertools import permutations
from gwriter import gwriter
import logging

def crack_3(plaintext, ciphertext):
    logger = logging.getLogger()
    logger.info('Start attack 3')

    plaintext_concat = ''.join(plaintext.strip().splitlines())
    ciphertext_concat = ''.join(ciphertext.strip().splitlines())

    known_rotor_lengths = gwriter.ROTOR_LENGTHS

    # write bit streams into continuous separate arrays for each rotor
    logger.info('Solving XOR bits...')
    rotor_placeholders = [[] for _ in range(5)]

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

    # determine possible rotor permutations
    possible_rotor_order = []
    for rp in rotor_placeholders[:5]:
        possible = {}
        for length in known_rotor_lengths:
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
                plain_bits = gwriter.ALPHABET_MAP[plaintext_concat[ix]]
                cipher_bits = gwriter.ALPHABET_MAP[ciphertext_concat[ix]]

                # if xor output has same pre-swap digits, sum of digits will match
                if gwriter.sum_binary_digits(plain_bits ^ xor_bits) == gwriter.sum_binary_digits(cipher_bits):
                    fill_value = 0
                else:
                    fill_value = 1

                rotors[missing_id][ix % rotor_lengths_left[missing_id]] = fill_value

        # compute possible right rotors given left rotors and brute force
        possible_right_rotors = permutations(set(known_rotor_lengths).difference(set(rotor_lengths_left)),5)
        possible_right_rotors = list(map(list, possible_right_rotors))

        logger.info('Brute force {} possible swap rotor orientations'.format(len(possible_right_rotors)))

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

                tmp_swap = [set() for _ in range(5)] # storage for bits

                d = gwriter.ALPHABET_MAP[ciphertext_concat[ix]] # cipher int
                a = gwriter.ALPHABET_MAP[plaintext_concat[ix]] # plain int

                # xor bits
                b = 0
                for rotor_id, rotor in enumerate(rotors[:5]):
                    b += (rotor[ix%rotor_lengths[rotor_id]] << (4-rotor_id))

                # xor output
                c = a ^ b

                # for all possible swap rotor bits
                for i in range(32):
                    skip = False

                    # for each swap rotor
                    for rotor_id in range(5,10):
                        bit_id = rotor_id-5

                        # get the persisted swap rotor bit
                        rotor_bit = rotors[rotor_id].get(ix%rotor_lengths[rotor_id])

                        # if it's persisted and != current brute force bit, skip this brute force
                        if (rotor_bit is not None) and (rotor_bit != gwriter.nth_bit(i,4-bit_id)):
                            skip = True
                            break

                    if skip:
                        continue

                    # do swapping on xor output with brute force rotor bits
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

                    # if swapped == cipher, cache each swap bit as a possibility
                    if tmp_c == d:
                        for tix, t in enumerate(tmp_swap):
                            t.add(gwriter.nth_bit(i, 4-tix))

                # if only 1 possible swap bit for a rotor, persist
                for s_id, s in enumerate(tmp_swap):
                    if len(s) == 1:
                        bit = s.pop()
                        rotor_id = s_id+5
                        rotors[rotor_id][ix%rotor_lengths[rotor_id]] = bit

            rotor_data = [[r[k] for k in sorted(r.keys())]for r in rotors]

            sender = gwriter.GWriter(rotors_bits=rotor_data)
            comparison = (
                sender.encrypt(plaintext_concat[c]) == ciphertext_concat[c]
                for c in range(len(plaintext_concat))
            )
            if all(comparison):
                logger.info('success in {} brute force iterations'.format(iterations))
                sender.reset()
                return True, sender

    logger.info('failed after {} iterations'.format(iterations))
    return False, None
