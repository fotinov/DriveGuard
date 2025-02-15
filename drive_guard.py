import FreeSimpleGUI as sg
import os
import hashlib
import base64
from cryptography.fernet import Fernet
import sys
import threading
from queue import Queue
import win32file


class SecureFolderTool:
    def __init__(self):
        sg.theme('DarkBlack')
        self.progress_queue = Queue()
        self.total_files = 0
        self.processed_files = 0

    def resource_path(self, relative_path):
        try:
            base_path = sys._MEIPASS
        except Exception:
            base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)

    def create_gui(self):
        layout = [
            [sg.Text('🔒 File/Folder Protection', font=('Helvetica', 14))],
            [sg.Text('Path:'), sg.Input(key='-PATH-', size=(40, 1))],
            [sg.Button("Select Folder", button_color=('white', '#0078D7')),
             sg.Button("Select Files", button_color=('white', '#0078D7'))],
            [sg.Text('Password:'), sg.Input(password_char='●', key='-PASSWORD-', size=(20, 1))],
            [sg.Button("Encrypt", button_color=('white', '#28A745')),
             sg.Button("Decrypt", button_color=('white', '#DC3545'))],
            [sg.ProgressBar(100, orientation='h', size=(20, 20), key='-PROGRESS-', visible=False)],
            [sg.Text("", key="-STATUS-", size=(50, 1))]
        ]
        return sg.Window('Drive Guard FCSec', layout, finalize=True, size=(500, 250),
                         icon=self.resource_path('drive_guard.ico'))

    def derive_key(self, password, salt):
        kdf = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200000)
        return base64.urlsafe_b64encode(kdf)

    def encrypt_file(self, file_path, password):
        with open(file_path, 'rb') as f:
            data = f.read()
        salt = os.urandom(16)
        encryption_key = self.derive_key(password, salt)
        fernet = Fernet(encryption_key)
        encrypted_data = fernet.encrypt(data)
        new_file_path = file_path + '.enc'
        with open(new_file_path, 'wb') as f:
            f.write(salt + b'::' + encrypted_data)
        os.remove(file_path)
        self.processed_files += 1
        self.progress_queue.put(self.processed_files)

    def create_drive_key(self, drive_path, password):
        salt = os.urandom(16)
        key = self.derive_key(password, salt)
        drive_key_path = os.path.join(drive_path, "drive_key.enc")
        with open(drive_key_path, 'wb') as f:
            f.write(salt + b'::' + key)

    def decrypt_file(self, file_path, password):
        if not file_path.endswith('.enc'):
            raise ValueError("File is not encrypted!")
        with open(file_path, 'rb') as f:
            content = f.read()
        try:
            metadata, encrypted_data = content.split(b'::', 1)
            salt = metadata[:16]
            decryption_key = self.derive_key(password, salt)
            fernet = Fernet(decryption_key)
            decrypted_data = fernet.decrypt(encrypted_data)
            original_file_path = file_path[:-4]
            with open(original_file_path, 'wb') as f:
                f.write(decrypted_data)
            os.remove(file_path)
            self.processed_files += 1
            self.progress_queue.put(self.processed_files)
        except Exception as e:
            raise ValueError("Decryption failed: " + str(e))

    def count_files(self, path):
        if os.path.isfile(path):
            return 1
        count = 0
        for root, _, files in os.walk(path):
            count += len(files)
        return count

    def process_files_thread(self, paths, password, encrypt=True):
        try:
            if isinstance(paths, str):
                paths = [paths]

            for path in paths:
                if os.path.isdir(path):
                    drive_root = os.path.splitdrive(path)[0] + '\\'
                    if encrypt and win32file.GetDriveType(drive_root) == win32file.DRIVE_REMOVABLE:
                        self.create_drive_key(drive_root, password)

                    for root, _, files in os.walk(path):
                        for file in files:
                            full_path = os.path.join(root, file)
                            if encrypt and not full_path.endswith('.enc'):
                                self.encrypt_file(full_path, password)
                            elif not encrypt and full_path.endswith('.enc'):
                                self.decrypt_file(full_path, password)
                else:
                    if encrypt and not path.endswith('.enc'):
                        self.encrypt_file(path, password)
                    elif not encrypt and path.endswith('.enc'):
                        self.decrypt_file(path, password)

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
                if isinstance(msg, int):
                    progress = (msg / self.total_files) * 100
                    window['-PROGRESS-'].update(progress)
                elif isinstance(msg, str):
                    if msg == 'DONE':
                        window['-STATUS-'].update("Operation completed successfully!", text_color='green')
                        window['-PROGRESS-'].update(visible=False)
                    elif msg.startswith('ERROR'):
                        window['-STATUS-'].update(msg, text_color='red')
                        window['-PROGRESS-'].update(visible=False)

            if event == "Select Folder":
                folder = sg.popup_get_folder("Select Folder", no_window=True)
                if folder:
                    window['-PATH-'].update(folder)

            elif event == "Select Files":
                files = sg.popup_get_file("Select File(s)", multiple_files=True, no_window=True)
                if files:
                    if isinstance(files, tuple):
                        file_list = [f.strip("{}") for f in files]
                    else:
                        file_list = [f.strip("{}") for f in files.split(';')]
                    window['-PATH-'].update(";".join(file_list))

            elif event in ("Encrypt", "Decrypt") and not processing_thread:
                path = values['-PATH-']
                password = values['-PASSWORD-']

                if not path:
                    window['-STATUS-'].update('No path selected!', text_color='red')
                    continue

                if not password:
                    window['-STATUS-'].update('Password cannot be empty!', text_color='red')
                    continue

                paths = [p.strip() for p in path.split(";") if p.strip()]
                if not all(os.path.exists(p) for p in paths):
                    window['-STATUS-'].update("Invalid path!", text_color='red')
                    continue

                self.total_files = sum(self.count_files(p) for p in paths)
                self.processed_files = 0
                window['-PROGRESS-'].update(0, visible=True)

                processing_thread = threading.Thread(
                    target=self.process_files_thread,
                    args=(paths, password, event == "Encrypt")
                )
                processing_thread.start()

            if processing_thread and not processing_thread.is_alive():
                processing_thread = None

        window.close()


if __name__ == '__main__':
    SecureFolderTool().run()
