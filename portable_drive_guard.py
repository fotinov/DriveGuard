# portable_app.py
import FreeSimpleGUI as sg
import os
import hashlib
import base64
from cryptography.fernet import Fernet
import win32api
import win32file


class PortableDriveGuard:
    def __init__(self):
        sg.theme('DarkBlack')
        self.key = None
        self.key_file_name = "drive_key.enc"
        self.drive = self.detect_drive()

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
        kdf = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
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
        if encrypt and file_path.endswith('.enc'):
            return
        if (not encrypt) and (not file_path.endswith('.enc')):
            return
        with open(file_path, 'rb') as f:
            data = f.read()
        fernet = Fernet(self.key)
        processed = fernet.encrypt(data) if encrypt else fernet.decrypt(data)
        new_file = file_path + '.enc' if encrypt else file_path[:-4]
        with open(new_file, 'wb') as f:
            f.write(processed)
        os.remove(file_path)

    def process_drive(self, encrypt=True):
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

    def create_gui(self):
        layout = [
            [sg.Text(f'Drive: {self.drive if self.drive else "Not detected"}', font=('Helvetica', 12))],
            [sg.Text('Enter Password:'), sg.Input(password_char='●', key='-PASSWORD-', size=(20, 1))],
            [sg.Button('Unlock Drive', button_color=('white', '#28A745')),
                sg.Button('Lock Drive', button_color=('white', '#DC3545'))],
            [sg.Text('', key='-STATUS-', size=(40, 1))]
        ]
        return sg.Window('Portable Drive Guard', layout, finalize=True, size=(350, 200))

    def run(self):
        window = self.create_gui()
        while True:
            event, values = window.read()
            if event in (sg.WIN_CLOSED, 'Exit'):
                break
            if event == 'Unlock Drive':
                pwd = values['-PASSWORD-']
                if not self.load_key(pwd):
                    window['-STATUS-'].update('Invalid password or key file missing!', text_color='red')
                    continue
                try:
                    self.process_drive(encrypt=False)
                    window['-STATUS-'].update('Drive unlocked!', text_color='green')
                except Exception as e:
                    window['-STATUS-'].update(f'Error: {str(e)}', text_color='red')
            if event == 'Lock Drive':
                pwd = values['-PASSWORD-']
                if not self.load_key(pwd):
                    window['-STATUS-'].update('Invalid password or key file missing!', text_color='red')
                    continue
                try:
                    self.process_drive(encrypt=True)
                    window['-STATUS-'].update('Drive locked!', text_color='green')
                except Exception as e:
                    window['-STATUS-'].update(f'Error: {str(e)}', text_color='red')
        window.close()


if __name__ == '__main__':
    PortableDriveGuard().run()
