#!/usr/bin/env python

from __future__ import print_function
import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization, padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1, PSS
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import cryptography
import os
import sys

def main():
    parser = argparse.ArgumentParser(description='Keypair generation helper.')
    parser.add_argument('-g', help="Generate keypair and save as .pub and .priv", type=str, nargs='?', default=None)
    args = parser.parse_args(sys.argv[1:])
    g = args.g
    # Checks for arg length
    if g == None:
        print("Please use -h for help.")
        return
    if g != None:
        print("Generating public and private keys for", g)
        private_key = ec.generate_private_key(
                ec.SECP384R1(), default_backend())
        serialized_private = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                encryption_algorithm=serialization.NoEncryption(),
                format=serialization.PrivateFormat.TraditionalOpenSSL)
        serialized_public = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
        with open(g+".pub", "wb") as pubfile:
            pubfile.write(serialized_public)
        with open(g+".priv", "wb") as privfile:
            privfile.write(serialized_private)
        return

if __name__ == "__main__":
    main()
