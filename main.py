import sys
from PyQt6.QtCore import QSize
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog, QPushButton
import cryptography as crypto


class Window(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Cryptographic system")
        self.setGeometry(200, 200, 400, 300)
        self.dialog = QFileDialog()
        self.dialog.setFileMode(QFileDialog.FileMode.Directory)
        self.symmetric_key_path = self.choose_file("Выберите файл (symmetric)", "Текстовые файлы (*.txt)")
        self.public_key_path = self.choose_file("Выберите файл (public)", "Текстовые файлы (*.pem)")
        self.private_key_path = self.choose_file("Выберите файл (private)", "Текстовые файлы (*.pem)")
        self.input_file_path = None
        self.output_file_path = None

        self.cryptography = crypto.Cryptography(self.symmetric_key_path, self.public_key_path, self.private_key_path)

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

    def set_path_input_and_output(self) -> None:
        """
            установка путей к файлам ввода и вывода
        """
        self.input_file_path = self.choose_file("Выберите файл (input)", "Текстовые файлы (*.txt)")
        self.output_file_path = self.choose_file("Выберите файл (output)", "Текстовые файлы (*.txt)")

    def choose_file(self, title: str, file_type: str) -> str:
        """
            выбор файла
            :title: - название окна
            :file_type: - тип файла
            :return: путь к файлу
        """
        return self.dialog.getOpenFileName(None, title, "", file_type)[0]

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
            Генерация ключей гибридной системы шифрования
            :return: None
        """
        self.cryptography.generate_keys()

    def encrypt_data(self) -> None:
        """
            Шифрование данных
            :param input_file_path: путь к файлу с данными для шифрования
            :param output_file_path: путь к файлу, в который будут сохранены зашифрованные данные
            :return: None
        """
        self.set_path_input_and_output()
        self.cryptography.encrypt_data(self.input_file_path, self.output_file_path)

    def decrypt_data(self) -> None:
        """
            Расшифровка данных
            :param input_file_path: путь к файлу с зашифрованными данными
            :param output_file_path: путь к файлу, в который будут сохранены расшифрованные данные
            :return: None
        """
        self.set_path_input_and_output()
        self.cryptography.decrypt_data(self.input_file_path, self.output_file_path)

    def exit(self) -> None:
        """
            Выход из программы
            :return: None
        """
        sys.exit()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = Window()
    app.exec()