import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def generate_keys(symmetric_key_path: str, public_key_path: str, private_key_path: str) -> None:
    """
        1 пункт л.р - Генерация ключей гибридной системы
        1.1. Сгеренировать ключ для симметричного алгоритма.
        1.2. Сгенерировать ключи для ассиметричного алгоритма.
        1.3. Сериализовать ассиметричные ключи.
        1.4. Зашифровать ключ симметричного шифрования открытым ключом и сохранить по указанному пути.
        :param symmetric_key_path: путь для ключа симметричного алгоритма
        :param public_key_path: путь для публичного ключа ассиметричного алгоритма
        :param private_key_path: путь для закрытого ключа ассиметричного алгоритма
        :return: None
    """
    # Генерация ключа для симметричного алгоритма
    symmetric_key = os.urandom(16)

    # Генерация ключей для ассиметричного алгоритма
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Сериализация ассиметричных ключей
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_key_path, 'wb') as f:
        f.write(public_key_bytes)
    with open(private_key_path, 'wb') as f:
        f.write(private_key_bytes)

    # Шифрование ключа симметричного шифрования открытым ключом и сохранение по указанному пути
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(symmetric_key_path, 'wb') as f:
        f.write(encrypted_symmetric_key)

def encrypt_data(input_file_path: str, private_key_path: str, symmetric_key_path: str, output_file_path: str):
    """
        2 пункт л.р - Шифрование данных гибридной системой
        2.1. Расшифровать симметричный ключ.
        2.2. Зашифровать текст симметричным алгоритмом и сохранить по указанному пути.
        :param input_file_path: входной файл
        :param private_key_path: путь для закрытого ключа ассиметричного алгоритма
        :param symmetric_key_path: путь для ключа симметричного алгоритма
        :param output_file_path: выходной файл
        :return: None
    """
    # Расшифровка симметричного ключа
    with open(symmetric_key_path, 'rb') as f:
        encrypted_symmetric_key = f.read()
    with open(private_key_path, 'rb') as f:
        private_key_bytes = f.read()
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
    )
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Шифрование текста симметричным алгоритмом и сохранение по указанному пути
    with open(input_file_path, 'rb') as f:
        data = f.read()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.SEED(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    with open(output_file_path, 'wb') as f:
        f.write(iv)
        f.write(encryptor.update(data) + encryptor.finalize())


def decrypt_data(input_file_path: str, private_key_path: str, symmetric_key_path: str, output_file_path: str):
    """
        3 пункт л.р - Дешифрование данных гибридной системой
        3.1. Расшифровать симметричный ключ.
        3.2. Расшифровать текст симметричным алгоритмом и сохранить по указанному пути.
        :param input_file_path: входной файл
        :param private_key_path: путь для закрытого ключа ассиметричного алгоритма
        :param symmetric_key_path: путь для ключа симметричного алгоритма
        :param output_file_path: выходной файл
        :return: None
    """
    # Расшифровка симметричного ключа
    with open(symmetric_key_path, 'rb') as f:
        encrypted_symmetric_key = f.read()
    with open(private_key_path, 'rb') as f:
        private_key_bytes = f.read()
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
    )
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Расшифровка текста симметричным алгоритмом и сохранение по указанному пути
    with open(input_file_path, 'rb') as f:
        data = f.read()
    iv = data[:16]
    data = data[16:]
    cipher = Cipher(algorithms.SEED(symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    with open(output_file_path, 'wb') as f:
        f.write(decryptor.update(data) + decryptor.finalize())


def menu():
    """
        основное меню программы
        1 - генерация ключей
        2 - шифрование данных
        3 - дешифрование данных
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