import argparse
import os
import gwriter
import logging

def cli():
    configure_logging()
    p = argparse.ArgumentParser()

    p.add_argument('question', help='select 2, 3, or bonus')
    a = p.parse_args()

    if a.question=='3':
        folder = './data/part_3'

        with open(os.path.join(folder, 'ciphertext.txt')) as f:
            ciphertext = f.read().strip()

        with open(os.path.join(folder, 'plaintext.txt')) as f:
            plaintext = f.read().strip()

        success, gwriter_obj = gwriter.crack(
            plaintext=plaintext,
            ciphertext=ciphertext
        )

        if success:
            print(gwriter_obj.to_str())

    elif a.question in ('bonus','4'):
        with open('./data/bonus/bonus_ciphertext.txt') as f:
            ciphertext = f.read().strip()

        success, gwriter_obj = gwriter.crack(ciphertext=ciphertext)

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
