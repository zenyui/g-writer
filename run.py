import argparse
import os
import gwriter
import logging

def cli():
    configure_logging()
    p = argparse.ArgumentParser()

    p.add_argument('question', help='select 2, 3, or bonus')
    a = p.parse_args()

    if a.question=='1':
        folder = './data/part_1'
        data = {}
        for fp in ('ciphertext','plaintext','rotors','key'):
            with open(os.path.join(folder, '{}.txt'.format(fp))) as f:
                data[fp] = f.read().strip()

        plaintext = data['plaintext']
        ciphertext = data['ciphertext']

        rotors = [r.split(':')[1].strip() for r in data['rotors'].splitlines()]
        rotors = list(map(list,rotors))
        rotors = [[int(r) for r in rotor] for rotor in rotors]

        key = data['key'].strip()
        key = (k.split(':')[1].strip().split(' ') for k in key.splitlines())
        key = list([int(c) for c in k] for k in key)
        rotor_order, rotor_offsets = key

        rotors_ordered = [rotors[ix] for ix in rotor_order]

        gwriter_obj = gwriter.GWriter(
            rotors_bits=rotors_ordered,
            rotor_offsets=rotor_offsets
        )
        print('*'*10+'\nSample Encryption\n')
        my_plaintext = gwriter_obj.encrypt(plaintext.splitlines())
        print('\n'.join(my_plaintext))

        gwriter_obj.reset()
        print('\n'+'*'*10+'\nSample Decryption\n')
        my_ciphertext = gwriter_obj.decrypt(ciphertext.splitlines())
        print('\n'.join(my_ciphertext))


    elif a.question=='2':
        folder = './data/part_2'
        data = {}
        for fp in ('ciphertext','plaintext'):
            with open(os.path.join(folder, '{}.txt'.format(fp))) as f:
                data[fp] = f.read().strip()

        plaintext = data['plaintext']
        ciphertext = data['ciphertext']
        rotor_lengths = [47, 53, 59, 61, 64, 65, 67, 69, 71, 73]

        success, gwriter_obj = gwriter.crack_2(plaintext, ciphertext, rotor_lengths)

        if success:
            print(gwriter_obj.to_str())

    elif a.question=='3':
        folder = './data/part_3'
        data = {}
        for fp in ('ciphertext','plaintext'):
            with open(os.path.join(folder, '{}.txt'.format(fp))) as f:
                data[fp] = f.read().strip()

        plaintext = data['plaintext']
        ciphertext = data['ciphertext']

        success, gwriter_obj = gwriter.crack_3(plaintext, ciphertext)

        if success:
            print(gwriter_obj.to_str())

    elif a.question in ('bonus','4'):
        with open('./data/bonus/bonus_ciphertext.txt') as f:
            ciphertext = f.read().strip()

        success, gwriter_obj = gwriter.crack_4(ciphertext)

        if success:
            print(gwriter_obj.to_str())

    else:
        logging.error('Unknown argument {}'.format(a.question))


def configure_logging():
    root = logging.getLogger()
    h = logging.StreamHandler()
    fmt = logging.Formatter(
        # fmt='%(asctime)s %(levelname)s (%(name)s) %(message)s',
        fmt='%(asctime)s %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S'
    )
    h.setFormatter(fmt)
    for oh in root.handlers:
        root.removeHandler(oh)
    root.addHandler(h)
    root.setLevel(logging.INFO)

if __name__=='__main__':
    cli()
