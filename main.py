import os
import sys

from PyQt6.QtCore import QSize
from PyQt6.uic.properties import QtWidgets
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, asymmetric, hashes, padding
import logging
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog, QPushButton
from PyQt6 import uic

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class Window(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Cryptographic system")
        self.setGeometry(200, 200, 400, 300)
        self.dialog = QFileDialog()
        self.dialog.setFileMode(QFileDialog.FileMode.Directory)
        self.symmetric_key_path = self.dialog.getOpenFileName(None, "Выберите файл (symmetric)", "", "Текстовые файлы (*.txt)")[0]
        self.public_key_path = self.dialog.getOpenFileName(None, "Выберите файл (public)", "", "Текстовые файлы (*.pem)")[0]
        self.private_key_path = self.dialog.getOpenFileName(None, "Выберите файл (private)", "", "Текстовые файлы (*.pem)")[0]
        self.input_file_path = None
        self.output_file_path = None

        # кнопки
        self.btn_gen_keys = self.add_button("Генерация ключей", 250, 50, 75, 50)
        self.btn_encrypt_data = self.add_button("Шифрование данных", 250, 50, 75, 100)
        self.btn_decrypt_data = self.add_button("Дешифрование данных", 250, 50, 75, 150)
        self.btn_exit = self.add_button("Выход", 250, 50, 75, 200)

        # события на кнопки
        self.btn_gen_keys.clicked.connect(self.generate_keys)
        self.btn_encrypt_data.clicked.connect(self.encrypt_data)
        self.btn_decrypt_data.clicked.connect(self.decrypt_data)
        self.btn_exit.clicked.connect(self.exit)

        self.show()

    def add_button(self, name: str, size_x: int, size_y: int, pos_x: int, pos_y: int) -> QPushButton:
        """
            добавление кнопки на форму с заданными параметрами и возврат кнопки
            :name: - название кнопки
            :size_x: - размер по x
            :size_y: - размер по y
            :pos_x: - положение по x
            :pos_y: - положение по y
        """
        button = QPushButton(name, self)
        button.setFixedSize(QSize(size_x, size_y))
        button.move(pos_x, pos_y)
        return button

    def generate_keys(self) -> None:
        """
            1 пункт л.р - Генерация ключей гибридной системы
            1.1. Сгеренировать ключ для симметричного алгоритма.
            1.2. Сгенерировать ключи для ассиметричного алгоритма.
            1.3. Сериализовать ассиметричные ключи.
            1.4. Зашифровать ключ симметричного шифрования открытым ключом и сохранить по указанному пути.
            :return: None
        """
        # Генерация ключа для симметричного алгоритма
        symmetric_key = os.urandom(16)
        # Генерация ключей для ассиметричного алгоритма
        private_key = asymmetric.rsa.generate_private_key(
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
            with open(self.public_key_path, 'wb') as f:
                f.write(public_key_bytes)
        except Exception as e:
            logging.error(e)
        try:
            with open(self.private_key_path, 'wb') as f:
                f.write(private_key_bytes)
        except Exception as e:
            logging.error(e)
        # Шифрование ключа симметричного шифрования открытым ключом и сохранение по указанному пути
        encrypted_symmetric_key = public_key.encrypt(
            symmetric_key,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        try:
            # Запись зашифрованного ключа в файл
            with open(self.symmetric_key_path, 'wb') as f:
                f.write(encrypted_symmetric_key)
        except Exception as e:
            logging.error(e)

    def encrypt_data(self) -> None:
        """
            2 пункт л.р - Шифрование данных
            2.1. Считать зашифрованный ключ симметричного шифрования из файла.
            2.2. Расшифровать ключ симметричного шифрования закрытым ключом.
            2.3. Считать данные из файла.
            2.4. Зашифровать данные симметричным алгоритмом.
            2.5. Сохранить зашифрованные данные в файл.
            :param input_file_path: путь к файлу с данными для шифрования
            :param output_file_path: путь к файлу, в который будут сохранены зашифрованные данные
            :return: None
        """
        self.input_file_path = self.dialog.getOpenFileName(None, "Выберите файл", "", "Текстовые файлы (*.txt)")[0]
        self.output_file_path = self.dialog.getOpenFileName(None, "Выберите файл", "", "Текстовые файлы (*.txt)")[0]
        # Считывание зашифрованного ключа симметричного шифрования из файла
        try:
            with open(self.symmetric_key_path, 'rb') as f:
                encrypted_symmetric_key = f.read()
        except Exception as e:
            logging.error(e)
        # Расшифровка ключа симметричного шифрования закрытым ключом
        try:
            with open(self.private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
        except Exception as e:
            logging.error(e)
        symmetric_key = private_key.decrypt(
            encrypted_symmetric_key,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Чтение данных из файла
        try:
            with open(self.input_file_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            logging.error(e)

        padder = padding.PKCS7(128).padder()
        padded_text = padder.update(data) + padder.finalize()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.SEED(symmetric_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_text) + encryptor.finalize()
        encrypted_data = iv + encrypted_data
        # Сохранение зашифрованных данных в файл
        try:
            with open(self.output_file_path, 'wb') as f:
                f.write(encrypted_data)
        except Exception as e:
            logging.error(e)

    def decrypt_data(self) -> None:
        """
            3 пункт л.р - Расшифровка данных
            3.1. Считать зашифрованный ключ симметричного шифрования из файла.
            3.2. Расшифровать ключ симметричного шифрования закрытым ключом.
            3.3. Считать зашифрованные данные из файла.
            3.4. Расшифровать данные симметричным алгоритмом.
            3.5. Сохранить расшифрованные данные в файл.
            :param input_file_path: путь к файлу с зашифрованными данными
            :param output_file_path: путь к файлу, в который будут сохранены расшифрованные данные
            :return: None
        """
        self.input_file_path = self.dialog.getOpenFileName(None, "Выберите файл", "", "Текстовые файлы (*.txt)")[0]
        self.output_file_path = self.dialog.getOpenFileName(None, "Выберите файл", "", "Текстовые файлы (*.txt)")[0]
        # Считывание зашифрованного ключа симметричного шифрования из файла
        try:
            with open(self.symmetric_key_path, 'rb') as f:
                encrypted_symmetric_key = f.read()
        except Exception as e:
            logging.error(e)
        # Расшифровка ключа симметричного шифрования закрытым ключом
        try:
            with open(self.private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
        except Exception as e:
            logging.error(e)
        symmetric_key = private_key.decrypt(
            encrypted_symmetric_key,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Чтение зашифрованных данных из файла
        try:
            with open(self.input_file_path, 'rb') as f:
                encrypted_data = f.read()
        except Exception as e:
            logging.error(e)
        # Расшифровка данных симметричным алгоритмом
        iv = encrypted_data[:16]
        encrypted_data = encrypted_data[16:]
        cipher = Cipher(algorithms.SEED(symmetric_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(data) + unpadder.finalize()
        # Сохранение расшифрованных данных в файл
        try:
            with open(self.output_file_path, 'wb') as f:
                f.write(data)
        except Exception as e:
            logging.error(e)

    def exit(self) -> None:
        """
            Выход из программы
        :return:
        """
        sys.exit()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = Window()
    app.exec()