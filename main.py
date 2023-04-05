import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def generate_keys(symmetric_key_path: str, public_key_path: str, private_key_path: str) -> None:
    pass


def encrypt_data(input_file_path: str, private_key_path: str, symmetric_key_path: str, output_file_path: str):
    pass


def decrypt_data(input_file_path: str, private_key_path: str, symmetric_key_path: str, output_file_path: str):
    pass
