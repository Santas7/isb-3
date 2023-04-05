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


def menu():
    """
        основное меню программы
    """
    while True:
        print('Encrypt or decrypt data using SEED algorithm')
        command = int(input("[1] generate\n[2] encrypt\n[3] decrypt\n--> "))

        if command == 1:
            os.system("cls")
            symmetric_key_path = input("symmetric key path--> ")
            public_key_path = input("public key path--> ")
            private_key_path = input("private key path--> ")
            generate_keys(symmetric_key_path, public_key_path, private_key_path)
            os.system("cls")
        elif command == 2:
            os.system("cls")
            input_file_path = input("input file path--> ")
            symmetric_key_path = input("symmetric key path--> ")
            private_key_path = input("private key path--> ")
            output_file_path = input("output file path--> ")
            encrypt_data(input_file_path, private_key_path, symmetric_key_path, output_file_path)
            os.system("cls")
        elif command == 3:
            os.system("cls")
            input_file_path = input("input file path--> ")
            symmetric_key_path = input("symmetric key path--> ")
            private_key_path = input("private key path--> ")
            output_file_path = input("output file path--> ")
            decrypt_data(input_file_path, private_key_path, symmetric_key_path, output_file_path)
            os.system("cls")
        else:
            os.system("cls")
            print("Error! I'm not found this command!\n")
            os.system("cls")

if __name__ == '__main__':
    menu()