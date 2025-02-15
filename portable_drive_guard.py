import FreeSimpleGUI as sg
import os
import hashlib
import base64
from cryptography.fernet import Fernet
import sys
import threading
from queue import Queue
import win32api
import win32file
import logging
from datetime import datetime

class PortableDriveGuard:
    def __init__(self):
        sg.theme('DarkBlack')
        self.setup_logging()
        self.key_file_name = "drive_key.enc"
        self.unlocked_list_file = "unlocked_files.dat"
        self.progress_queue = Queue()
        self.total_files = 0
        self.processed_files = 0
        self.drive = self.detect_drive()
        self.logger.info(f"Initialized with drive: {self.drive}")

    def setup_logging(self):
        log_file = f"portable_guard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.logger = logging.getLogger('PortableDriveGuard')
        self.logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

    def resource_path(self, relative_path):
        try:
            base_path = sys._MEIPASS
        except Exception:
            base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)

    def create_gui(self):
        layout = [
            [sg.Text(f"Drive: {self.drive if self.drive else 'Not detected'}", key='-DRIVE-', font=('Helvetica', 12))],
            [sg.Text("Folder:"), sg.Input(key="-FOLDER-", size=(30, 1), default_text=self.drive if self.drive else ""), sg.Button("Select Folder", button_color=("white", "#0078D7"))],
            [sg.Text("Enter Password:"), sg.Input(password_char="●", key="-PASSWORD-", size=(20, 1))],
            [sg.Button("Unlock Drive", button_color=("white", "#28A745")),
             sg.Button("Lock Drive", button_color=("white", "#DC3545")),
             sg.Button("Refresh Drive", button_color=("white", "#0078D7"))],
            [sg.ProgressBar(100, orientation='h', size=(20, 20), key='-PROGRESS-', visible=False)],
            [sg.Text("", key="-STATUS-", size=(40, 1))]
        ]
        return sg.Window("Drive Guard FCSec Portable", layout, finalize=True, size=(400, 250), icon=self.resource_path('portable_drive_guard.ico'))

    def detect_drive(self):
        try:
            drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
            self.logger.debug(f"Detected drives: {drives}")
            for drive in drives:
                if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                    key_path = os.path.join(drive, self.key_file_name)
                    if os.path.exists(key_path):
                        self.logger.info(f"Found drive with key file: {drive}")
                        return drive
            for drive in drives:
                if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                    self.logger.info(f"Found removable drive without key file: {drive}")
                    return drive
            self.logger.warning("No removable drive detected")
            return None
        except Exception as e:
            self.logger.error(f"Error detecting drive: {str(e)}")
            return None

    def derive_key(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        kdf = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200000)
        derived = base64.urlsafe_b64encode(kdf)
        return derived, salt

    def load_key(self, password):
        if not self.drive:
            self.logger.error("No drive detected")
            return False
        key_path = os.path.join(self.drive, self.key_file_name)
        if not os.path.exists(key_path):
            self.logger.error(f"Key file not found: {key_path}")
            return False
        with open(key_path, 'rb') as f:
            data = f.read()
        parts = data.split(b'::', 1)
        if len(parts) != 2:
            self.logger.error("Key file format invalid")
            return False
        salt, stored_key = parts[0], parts[1]
        derived, _ = self.derive_key(password, salt)
        if derived == stored_key:
            self.logger.info("Key verified successfully")
            return True
        else:
            self.logger.error("Derived key does not match stored key")
            return False

    def load_unlocked_list(self):
        file_path = os.path.join(self.drive, self.unlocked_list_file)
        if not os.path.exists(file_path):
            return []
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]

    def save_unlocked_list(self, file_list):
        file_path = os.path.join(self.drive, self.unlocked_list_file)
        with open(file_path, 'w') as f:
            for path in file_list:
                f.write(path + '\n')

    def add_to_unlocked_list(self, file_path):
        lst = self.load_unlocked_list()
        if file_path not in lst:
            lst.append(file_path)
        self.save_unlocked_list(lst)

    def clear_unlocked_list(self):
        file_path = os.path.join(self.drive, self.unlocked_list_file)
        if os.path.exists(file_path):
            os.remove(file_path)

    def process_file(self, file_path, encrypt=True, password=None):
        try:
            if encrypt:
                if file_path.endswith('.enc'):
                    return
                with open(file_path, 'rb') as f:
                    data = f.read()
                salt = os.urandom(16)
                derived_key, _ = self.derive_key(password, salt)
                fernet = Fernet(derived_key)
                processed = fernet.encrypt(data)
                new_file = file_path + '.enc'
                out_data = salt + b'::' + processed
            else:
                if not file_path.endswith('.enc'):
                    return
                with open(file_path, 'rb') as f:
                    data = f.read()
                parts = data.split(b'::', 1)
                if len(parts) != 2:
                    self.logger.error(f"Invalid file format: {file_path}")
                    return
                salt, encrypted_data = parts[0], parts[1]
                derived_key, _ = self.derive_key(password, salt)
                fernet = Fernet(derived_key)
                processed = fernet.decrypt(encrypted_data)
                new_file = file_path[:-4]
                out_data = processed
            with open(new_file, 'wb') as f:
                f.write(out_data)
            os.remove(file_path)
            self.processed_files += 1
            self.progress_queue.put(self.processed_files)
            self.logger.debug(f"Processed file: {file_path}")
        except Exception as e:
            self.logger.error(f"Error processing file {file_path}: {str(e)}")

    def process_unlock_thread(self, folder, password):
        try:
            self.total_files = 0
            self.processed_files = 0
            for root, _, files in os.walk(folder):
                for file in files:
                    if file.endswith('.enc'):
                        self.total_files += 1
            self.logger.info(f"Files to unlock: {self.total_files}")
            for root, _, files in os.walk(folder):
                for file in files:
                    if not file.endswith('.enc'):
                        continue
                    full_path = os.path.join(root, file)
                    self.process_file(full_path, encrypt=False, password=password)
                    new_path = full_path[:-4]
                    self.add_to_unlocked_list(new_path)
            self.progress_queue.put('DONE')
        except Exception as e:
            self.logger.error(f"Error in unlock thread: {str(e)}")
            self.progress_queue.put(f"ERROR: {str(e)}")

    def process_lock_thread(self, password):
        try:
            unlocked_files = self.load_unlocked_list()
            self.total_files = len(unlocked_files)
            self.processed_files = 0
            self.logger.info(f"Files to lock: {self.total_files}")
            for file_path in unlocked_files:
                if os.path.exists(file_path):
                    self.process_file(file_path, encrypt=True, password=password)
            self.clear_unlocked_list()
            self.progress_queue.put('DONE')
        except Exception as e:
            self.logger.error(f"Error in lock thread: {str(e)}")
            self.progress_queue.put(f"ERROR: {str(e)}")

    def run(self):
        window = self.create_gui()
        processing_thread = None
        while True:
            event, values = window.read(timeout=100)
            if event in (sg.WIN_CLOSED, 'Exit'):
                break
            if event == "Select Folder":
                folder = sg.popup_get_folder("Select Folder", no_window=True)
                if folder:
                    window['-FOLDER-'].update(folder)
            if event == "Refresh Drive":
                self.drive = self.detect_drive()
                window['-DRIVE-'].update(f"Drive: {self.drive if self.drive else 'Not detected'}")
            if not self.progress_queue.empty():
                msg = self.progress_queue.get()
                if isinstance(msg, int) and self.total_files > 0:
                    progress = (msg / self.total_files) * 100
                    window['-PROGRESS-'].update(progress)
                elif isinstance(msg, str):
                    if msg == 'DONE':
                        window['-STATUS-'].update("Operation completed successfully!", text_color='green')
                        window['-PROGRESS-'].update(visible=False)
                    elif msg.startswith('ERROR'):
                        window['-STATUS-'].update(msg, text_color='red')
                        window['-PROGRESS-'].update(visible=False)
            if event in ("Unlock Drive", "Lock Drive") and processing_thread is None:
                pwd = values['-PASSWORD-']
                folder = values['-FOLDER-']
                if not folder or not os.path.exists(folder):
                    window['-STATUS-'].update('Invalid folder!', text_color='red')
                    continue
                if not pwd:
                    window['-STATUS-'].update('Password cannot be empty!', text_color='red')
                    continue
                if not self.load_key(pwd):
                    window['-STATUS-'].update('Invalid password or key file missing!', text_color='red')
                    continue
                window['-PROGRESS-'].update(0, visible=True)
                if event == "Unlock Drive":
                    processing_thread = threading.Thread(target=self.process_unlock_thread, args=(folder, pwd))
                else:
                    processing_thread = threading.Thread(target=self.process_lock_thread, args=(pwd,))
                processing_thread.start()
            if processing_thread and not processing_thread.is_alive():
                processing_thread = None
        window.close()

if __name__ == '__main__':
    PortableDriveGuard().run()
