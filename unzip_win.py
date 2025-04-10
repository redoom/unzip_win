import os
import pyzipper
import hashlib
import logging
import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox, QProgressBar
)
from PyQt6.QtCore import QUrl, pyqtSignal, QObject, QEvent
from PyQt6.QtGui import QDesktopServices
from datetime import datetime
import pytz
import multiprocessing
from PyQt6.QtCore import QRunnable, QThreadPool, QMutex
import re


def except_hook(cls, exception, traceback):
    sys.__excepthook__(cls, exception, traceback)


sys.excepthook = except_hook


class WorkerSignals(QObject):
    log_signal = pyqtSignal(str, str)
    progress_signal = pyqtSignal(int)


class Worker(QRunnable):
    def __init__(self, func, *args):
        super().__init__()
        self.func = func
        self.args = args
        self.signals = WorkerSignals()

    def run(self):
        try:
            self.func(*self.args, self.signals)
        except Exception as e:
            print(f"Worker thread error: {e}")
            logging.error(f"Worker thread error: {e}")


class AuthUnzipApp(QWidget):
    def __init__(self):
        super().__init__()
        sys.excepthook = self.handle_exception
        self.thread_pool = QThreadPool()
        self.thread_pool.setMaxThreadCount(multiprocessing.cpu_count())
        self.log_mutex = QMutex()
        self.file_mutex = QMutex()
        self.current_dir = os.getcwd()
        self.init_ui()
        self.set_style()
        self.init_logging()

    def init_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler()
            ]
        )

    def handle_exception(self, exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        error_msg = f"未处理的异常: {exc_type.__name__}\n{exc_value}"
        QMessageBox.critical(self, "致命错误", error_msg)
        self.log_message(f"崩溃日志: {error_msg}", level="ERROR")
        logging.error(f"崩溃日志: {error_msg}")
        sys.exit(1)

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        title_label = QLabel("长尾猴量化数据处理工具")
        title_label.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 15px;
        """)
        main_layout.addWidget(title_label)

        input_layout = QVBoxLayout()
        input_layout.setSpacing(12)

        phone_hbox = QHBoxLayout()
        phone_label = QLabel("手机号:")
        phone_label.setStyleSheet("""
            font-size: 14px;
            font-weight: bold;
            color: #333333;
        """)
        self.phone_input = QLineEdit()
        self.phone_input.setPlaceholderText("输入你的长尾猴量化账号，官网：vvtr.com")
        self.phone_input.setStyleSheet("""
            QLineEdit {
                background: white;
                border: 2px solid #007BFF;
                border-radius: 5px;
                padding: 6px;
                min-width: 280px;
                color: #333333;
            }
            QLineEdit::placeholder {
                color: #7f8c8d;
            }
        """)
        phone_hbox.addWidget(phone_label)
        phone_hbox.addWidget(self.phone_input)
        input_layout.addLayout(phone_hbox)

        code_hbox = QHBoxLayout()
        code_label = QLabel("操作码:")
        code_label.setStyleSheet("""
            font-size: 14px;
            font-weight: bold;
            color: #333333;
        """)
        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("登录长尾猴后点击右侧按钮获取")
        self.code_input.setStyleSheet("""
            QLineEdit {
                background: white;
                border: 2px solid #007BFF;
                border-radius: 5px;
                padding: 6px;
                min-width: 280px;
                color: #333333;
            }
            QLineEdit::placeholder {
                color: #7f8c8d;
            }
        """)
        code_hbox.addWidget(code_label)
        code_hbox.addWidget(self.code_input)

        self.get_code_button = QPushButton("获取操作码")
        self.get_code_button.setStyleSheet("""
            QPushButton {
                background: #007BFF;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 5px;
                font-size: 14px;
                min-width: 80px;
            }
            QPushButton:hover {
                background: #0056b3;
            }
        """)
        self.get_code_button.clicked.connect(self.open_code_url)
        code_hbox.addWidget(self.get_code_button)
        input_layout.addLayout(code_hbox)

        submit_button = QPushButton("提交并处理")
        submit_button.setStyleSheet("""
            QPushButton {
                background: #007BFF;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 14px;
                min-width: 150px;
            }
            QPushButton:hover {
                background: #0056b3;
            }
        """)
        submit_button.clicked.connect(self.submit_data)
        input_layout.addWidget(submit_button)

        main_layout.addLayout(input_layout)

        log_label = QLabel("运行日志:")
        log_label.setStyleSheet("""
            font-size: 14px;
            font-weight: bold;
            color: #333333;
        """)
        main_layout.addWidget(log_label)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setStyleSheet("""
            background: white;
            border: 2px solid #bdc3c7;
            color: #333;
            font-size: 12px;
            font-family: 'Courier New', monospace;
            border-radius: 5px;
            padding: 8px;
            min-height: 200px;
        """)
        self.log.append("请将解压软件与被解压文件放到一个文件夹，程序运行时会将解压后的文件输出到Output文件夹")
        main_layout.addWidget(self.log)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #eee;
                border: none;
                border-radius: 3px;
                height: 4px;
            }
            QProgressBar::chunk {
                background-color: #BDC3C7;
                border-radius: 3px;
            }
        """)
        main_layout.addWidget(self.progress_bar)

        self.setLayout(main_layout)
        self.setWindowTitle("数据解压工具")
        self.setGeometry(100, 100, 600, 500)
        self.show()

    def set_style(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #F5F7FA;
                color: #333333;
            }
            QLabel {
                font-size: 14px;
            }
            QLineEdit {
                border: 2px solid #007BFF;
                border-radius: 5px;
                padding: 6px;
                min-width: 280px;
                background-color: white;
                color: #333333;
            }
            QPushButton {
                background-color: #007BFF;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 14px;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
            QTextEdit {
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                padding: 8px;
                min-height: 200px;
                font-family: 'Segoe UI', sans-serif;
                font-size: 12px;
            }
        """)

    def log_message(self, message, level="INFO"):
        self.log_mutex.lock()
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.log.append(f"[{timestamp} {level}] {message}")
            self.log.repaint()
            logging.info(f"[{timestamp} {level}] {message}")
        finally:
            self.log_mutex.unlock()

    def get_zip_files(self):
        zip_files = []
        for root, _, files in os.walk(self.current_dir):
            if '.venv' in root or '__pycache__' in root:
                continue
            for file in files:
                if file.lower().endswith('.zip'):
                    zip_files.append(os.path.join(root, file))
        return zip_files

    def submit_data(self):
        phone = self.phone_input.text()
        code = self.code_input.text()
        zip_files = self.get_zip_files()

        if not phone:
            QMessageBox.warning(self, "警告", "请输入手机号")
            return
        if not code:
            QMessageBox.warning(self, "警告", "请输入操作码")
            return
        if not zip_files:
            QMessageBox.warning(self, "警告", "未找到有效压缩文件")
            return

        if self.authenticate(phone, code):
            self.log_message("身份验证成功，开始解压文件...")
            self.progress_bar.setRange(0, len(zip_files))
            self.progress_bar.setValue(0)
            worker = Worker(self.unzip_files_parallel, zip_files)
            worker.signals.log_signal.connect(self.log_message)
            worker.signals.progress_signal.connect(self.update_progress)
            self.thread_pool.start(worker)
        else:
            self.log_message("身份验证失败，请检查输入信息")

    def authenticate(self, phone_number, op_code):
        shanghai_tz = pytz.timezone('Asia/Shanghai')
        now = datetime.now(shanghai_tz)
        today_date = now.strftime("%Y%m%d")

        data_to_hash = f"{phone_number}{today_date}{'vvtr123!@#qwe'}".encode('utf-8')
        expected_op_code = hashlib.sha256(data_to_hash).hexdigest()
        return op_code == expected_op_code

    def unzip_files_parallel(self, zip_files, signals):
        output_dir = os.path.join(self.current_dir, 'output')
        os.makedirs(output_dir, exist_ok=True)
        signals.log_signal.emit(f"解压文件存放路径：{output_dir}", "INFO")
        completed_count = 0
        for zip_path in zip_files:
            self.unzip_single_file(zip_path, output_dir, signals)
            completed_count += 1
            signals.progress_signal.emit(completed_count)
        signals.log_signal.emit("所有操作完成！", "INFO")

    def unzip_single_file(self, zip_path, output_dir, signals):
        file = os.path.basename(zip_path)
        password = self.generate_zip_password(file)
        try:
            signals.log_signal.emit(f"正在解压 {zip_path}", "INFO")
            with pyzipper.AESZipFile(zip_path) as zipf:
                zipf.setpassword(password.encode('utf-8'))

                # 获取压缩包相对于当前工作目录的相对路径
                relative_path = os.path.relpath(os.path.dirname(zip_path), self.current_dir)
                # 构建最终输出目录
                base_output_dir = os.path.join(output_dir, relative_path)

                # 检查压缩包名称是否为 YYYYMMDD 格式
                date_match = re.match(r'(\d{8})\.zip', file)
                if date_match:
                    date_folder = date_match.group(1)
                    final_output_dir = os.path.join(base_output_dir, date_folder)
                else:
                    final_output_dir = base_output_dir

                os.makedirs(final_output_dir, exist_ok=True)

                encodings = ['utf-8', 'gbk', 'cp936']
                for info in zipf.infolist():
                    for encoding in encodings:
                        try:
                            info.filename = info.filename.encode('cp437').decode(encoding)
                            break
                        except UnicodeDecodeError:
                            continue
                    extract_path = os.path.join(final_output_dir, info.filename)
                    try:
                        if not os.path.exists(os.path.dirname(extract_path)):
                            with self.file_mutex:
                                os.makedirs(os.path.dirname(extract_path), exist_ok=True)
                        zipf.extract(info, final_output_dir)
                    except RuntimeError as e:
                        if "Bad password for file" in str(e):
                            signals.log_signal.emit(f"解压 {file} 失败，密码错误: {str(e)}", "ERROR")
                        else:
                            signals.log_signal.emit(f"解压 {file} 失败: {str(e)}", "ERROR")
                    except Exception as e:
                        signals.log_signal.emit(f"解压 {file} 失败: {str(e)}", "ERROR")

            signals.log_signal.emit(f"成功解压 {file}", "INFO")
        except Exception as e:
            signals.log_signal.emit(f"解压 {file} 失败: {str(e)}", "ERROR")
            logging.error(f"解压 {file} 失败: {str(e)}")

    def generate_zip_password(self, filename):
        data_to_hash = f"{filename}vvtr123!@#qwe".encode('utf-8')
        return hashlib.sha256(data_to_hash).hexdigest()

    def open_code_url(self):
        QDesktopServices.openUrl(QUrl("https://www.vvtr.com/v/PW/"))

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def closeEvent(self, event: QEvent):
        # 停止线程池中的所有线程
        self.thread_pool.clear()
        self.thread_pool.waitForDone()
        event.accept()


if __name__ == '__main__':
    try:
        app = QApplication(sys.argv)
        window = AuthUnzipApp()
        sys.exit(app.exec())
    except Exception as e:
        print(f"主程序出现异常: {e}")
        logging.error(f"主程序出现异常: {e}")
