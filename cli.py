import argparse
import os
import gwriter
import logging

def cli():
    configure_logging()
    logger = logging.getLogger()

    p = argparse.ArgumentParser()

    p.add_argument('-c', help='path to ciphertext', dest='ciphertext', required=True)
    p.add_argument('-p', help='(optional) path to plaintext', dest='plaintext')
    p.add_argument('--show', help='output decrypted plaintext', dest='show_plain', action='store_true')
    a = p.parse_args()

    with open(a.ciphertext,'r') as f:
        ciphertext = f.read().strip()

    plaintext = None
    if a.plaintext:
        with open(a.plaintext, 'r') as f:
            plaintext = f.read().strip()

    success, gwriter_obj = gwriter.crack(
        plaintext=plaintext,
        ciphertext=ciphertext
    )

    if success:
        logger.info('success\n{}'.format(gwriter_obj.to_str()))
        if a.show_plain:
            logger.info('\n{s}\n\tBEGIN MESSAGES\n{s}\n'.format(s='*'*50))
            decrypted = gwriter_obj.decrypt(ciphertext.splitlines())
            print('\n'.join(decrypted))

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
