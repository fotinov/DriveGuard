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

class PortableDriveGuard:
    def __init__(self):
        sg.theme('DarkBlack')
        self.key_file_name = "drive_key.enc"
        self.drive = self.detect_drive()
        self.progress_queue = Queue()
        self.total_files = 0
        self.processed_files = 0
        self.key = None

    def resource_path(self, relative_path):
        try:
            base_path = sys._MEIPASS
        except Exception:
            base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)

    def create_gui(self):
        layout = [
            [sg.Text(f"Drive: {self.drive if self.drive else 'Not detected'}", font=('Helvetica', 12))],
            [sg.Text("Enter Password:"), sg.Input(password_char="●", key="-PASSWORD-", size=(20, 1))],
            [sg.Button("Unlock Drive", button_color=("white", "#28A745")),
             sg.Button("Lock Drive", button_color=("white", "#DC3545"))],
            [sg.ProgressBar(100, orientation='h', size=(20, 20), key='-PROGRESS-', visible=False)],
            [sg.Text("", key="-STATUS-", size=(40, 1))]
        ]
        return sg.Window("Drive Guard FCSec Portable", layout, finalize=True, size=(350, 200), icon=self.resource_path('portable_drive_guard.ico'))

    def detect_drive(self):
        drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
        for drive in drives:
            if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                if os.path.exists(os.path.join(drive, self.key_file_name)):
                    return drive
        for drive in drives:
            if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                return drive
        return None

    def derive_key(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        kdf = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200000)
        derived = base64.urlsafe_b64encode(kdf)
        return derived, salt

    def load_key(self, password):
        if self.drive is None:
            return False
        key_path = os.path.join(self.drive, self.key_file_name)
        if not os.path.exists(key_path):
            return False
        with open(key_path, 'rb') as f:
            data = f.read()
        salt = data[:16]
        stored_key = data[16:]
        derived, _ = self.derive_key(password, salt)
        if derived == stored_key:
            self.key = derived
            return True
        else:
            return False

    def process_file(self, file_path, encrypt=True):
        if encrypt:
            if file_path.endswith('.enc'):
                return
        else:
            if not file_path.endswith('.enc'):
                return
        with open(file_path, 'rb') as f:
            data = f.read()
        fernet = Fernet(self.key)
        processed = fernet.encrypt(data) if encrypt else fernet.decrypt(data)
        new_file = file_path + '.enc' if encrypt else file_path[:-4]
        with open(new_file, 'wb') as f:
            f.write(processed)
        os.remove(file_path)
        self.processed_files += 1
        self.progress_queue.put(self.processed_files)

    def count_files(self, drive):
        count = 0
        for root, _, files in os.walk(drive):
            for file in files:
                if file == self.key_file_name:
                    continue
                count += 1
        return count

    def process_drive_thread(self, encrypt=True):
        try:
            self.total_files = self.count_files(self.drive)
            self.processed_files = 0
            for root, _, files in os.walk(self.drive):
                for file in files:
                    if file == self.key_file_name:
                        continue
                    full_path = os.path.join(root, file)
                    if encrypt:
                        if full_path.endswith('.enc'):
                            continue
                    else:
                        if not full_path.endswith('.enc'):
                            continue
                    self.process_file(full_path, encrypt)
            self.progress_queue.put('DONE')
        except Exception as e:
            self.progress_queue.put(f'ERROR: {str(e)}')

    def run(self):
        window = self.create_gui()
        processing_thread = None
        while True:
            event, values = window.read(timeout=100)
            if event in (sg.WIN_CLOSED, 'Exit'):
                break
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
                if not pwd:
                    window['-STATUS-'].update('Password cannot be empty!', text_color='red')
                    continue
                if not self.load_key(pwd):
                    window['-STATUS-'].update('Invalid password or key file missing!', text_color='red')
                    continue
                window['-PROGRESS-'].update(0, visible=True)
                processing_thread = threading.Thread(target=self.process_drive_thread, args=(event=="Lock Drive",))
                processing_thread.start()
            if processing_thread and not processing_thread.is_alive():
                processing_thread = None
        window.close()

if __name__ == '__main__':
    PortableDriveGuard().run()
