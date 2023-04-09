import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


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
    try:
        with open(public_key_path, 'wb') as f:
            f.write(public_key_bytes)
    except Exception as e:
        logging.error(e)
    try:
        with open(private_key_path, 'wb') as f:
            f.write(private_key_bytes)
    except Exception as e:
        logging.error(e)

    # Шифрование ключа симметричного шифрования открытым ключом и сохранение по указанному пути
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    try:
        with open(symmetric_key_path, 'wb') as f:
            f.write(encrypted_symmetric_key)
    except Exception as e:
        logging.error(e)


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
    try:
        with open(symmetric_key_path, 'rb') as f:
            encrypted_symmetric_key = f.read()
    except Exception as e:
        logging.error(e)
    try:
        with open(private_key_path, 'rb') as f:
            private_key_bytes = f.read()
    except Exception as e:
        logging.error(e)
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
    try:
        with open(input_file_path, 'rb') as f:
            data = f.read()
    except Exception as e:
        logging.error(e)

    iv = os.urandom(16)
    cipher = Cipher(algorithms.SEED(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    try:
        with open(output_file_path, 'wb') as f:
            f.write(iv)
            f.write(encryptor.update(data) + encryptor.finalize())
    except Exception as e:
        logging.error(e)


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
    try:
        with open(symmetric_key_path, 'rb') as f:
            encrypted_symmetric_key = f.read()
    except Exception as e:
        logging.error(e)
    try:
        with open(private_key_path, 'rb') as f:
            private_key_bytes = f.read()
    except Exception as e:
        logging.error(e)
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
    try:
        with open(input_file_path, 'rb') as f:
            data = f.read()
    except Exception as e:
        logging.error(e)
    iv = data[:16]
    data = data[16:]
    cipher = Cipher(algorithms.SEED(symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    try:
        with open(output_file_path, 'wb') as f:
            f.write(decryptor.update(data) + decryptor.finalize())
    except Exception as e:
        logging.error(e)


def menu():
    """
        основное меню программы
        1 - генерация ключей
        2 - шифрование данных
        3 - дешифрование данных
    """
    # create main menu with using match/case
    while True:
        print('1 - генерация ключей')
        print('2 - шифрование данных')
        print('3 - дешифрование данных')
        print('4 - выход')
        choice = input('Выберите пункт меню: ')
        match choice:
            case '1':
                generate_keys()
            case '2':
                encrypt_data(
                    input_file_path=input('Введите путь к файлу для шифрования: '),
                    private_key_path=input('Введите путь к закрытому ключу: '),
                    symmetric_key_path=input('Введите путь к симметричному ключу: '),
                    output_file_path=input('Введите путь к файлу для сохранения зашифрованных данных: ')
                )
            case '3':
                decrypt_data(
                    input_file_path=input('Введите путь к файлу для расшифрования: '),
                    private_key_path=input('Введите путь к закрытому ключу: '),
                    symmetric_key_path=input('Введите путь к симметричному ключу: '),
                    output_file_path=input('Введите путь к файлу для сохранения расшифрованных данных: ')
                )
            case '4':
                break
            case _:
                print('Неверный пункт меню')

if __name__ == '__main__':
    menu()