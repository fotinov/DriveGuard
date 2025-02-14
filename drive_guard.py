import FreeSimpleGUI as sg
import os
import hashlib
import base64
from cryptography.fernet import Fernet


class SecureFolderTool:
    def __init__(self):
        sg.theme('DarkBlack')

    def create_gui(self):
        layout = [
            [sg.Text('🔒 File/Folder Protection', font=('Helvetica', 14))],
            [sg.Text('Path:'), sg.Input(key='-PATH-', size=(40, 1))],
            [sg.Button("Select Folder", button_color=('white', '#0078D7')),
                sg.Button("Select Files", button_color=('white', '#0078D7'))],
            [sg.Text('Password:'), sg.Input(password_char='●', key='-PASSWORD-', size=(20, 1))],
            [sg.Button("Encrypt", button_color=('white', '#28A745')),
                sg.Button("Decrypt", button_color=('white', '#DC3545'))],
            [sg.Text("", key="-STATUS-", size=(50, 1))]
        ]
        return sg.Window('File/Folder Protection Tool', layout, finalize=True, size=(500, 250))

    def derive_key(self, password, salt):
        kdf = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)
        return base64.urlsafe_b64encode(kdf)

    def encrypt_file(self, file_path, password):
        with open(file_path, 'rb') as f:
            data = f.read()
        salt = os.urandom(16)  # Generate unique salt for each file
        encryption_key = self.derive_key(password, salt)
        fernet = Fernet(encryption_key)
        encrypted_data = fernet.encrypt(data)
        metadata = salt  # Store the salt as metadata
        new_file_path = file_path + '.enc'
        with open(new_file_path, 'wb') as f:
            f.write(metadata + b'::' + encrypted_data)
        os.remove(file_path)

    def decrypt_file(self, file_path, password):
        if not file_path.endswith('.enc'):
            raise ValueError("File is not encrypted!")
        with open(file_path, 'rb') as f:
            content = f.read()
        try:
            metadata, encrypted_data = content.split(b'::', 1)
        except ValueError:
            raise ValueError("Invalid file format!")
        salt = metadata[:16]  # Extract the salt from metadata
        decryption_key = self.derive_key(password, salt)
        try:
            fernet = Fernet(decryption_key)
            decrypted_data = fernet.decrypt(encrypted_data)
            original_file_path = file_path[:-4]
            with open(original_file_path, 'wb') as f:
                f.write(decrypted_data)
            os.remove(file_path)
        except Exception as e:
            raise ValueError("Decryption failed: " + str(e))

    def process_folder(self, folder_path, password, encrypt=True):
        for root, _, files in os.walk(folder_path):
            for file in files:
                full_path = os.path.join(root, file)
                try:
                    if encrypt and not full_path.endswith('.enc'):
                        self.encrypt_file(full_path, password)
                    elif (not encrypt) and full_path.endswith('.enc'):
                        self.decrypt_file(full_path, password)
                except Exception as e:
                    print(f"Error processing {full_path}: {str(e)}")

    def run(self):
        window = self.create_gui()

        while True:
            event, values = window.read()
            if event in (sg.WIN_CLOSED, 'Exit'):
                break

            if event == "Select Folder":
                folder = sg.popup_get_folder("Select Folder", no_window=True)
                if folder:
                    window['-PATH-'].update(folder)

            elif event == "Select Files":
                raw_files = sg.popup_get_file("Select File(s)", multiple_files=True, no_window=True)
                if raw_files:
                    if isinstance(raw_files, tuple):
                        file_list = [f.strip("{}") for f in raw_files]
                    else:
                        file_list = [f.strip("{}") for f in raw_files.split(';')]
                    window['-PATH-'].update(";".join(file_list))

            if event in ("Encrypt", "Decrypt"):
                path = values['-PATH-']
                password = values['-PASSWORD-']

                if not path:
                    window['-STATUS-'].update('No path selected!', text_color='red')
                    continue

                if not password:
                    window['-STATUS-'].update('Password cannot be empty!', text_color='red')
                    continue

                if os.path.exists(path):
                    try:
                        if os.path.isdir(path):
                            self.process_folder(path, password, encrypt=(event == "Encrypt"))
                        elif os.path.isfile(path):
                            if event == "Encrypt":
                                self.encrypt_file(path, password)
                            else:
                                self.decrypt_file(path, password)
                        window['-STATUS-'].update(f"{event} successful!", text_color='green')
                    except Exception as e:
                        window['-STATUS-'].update(f"Error: {str(e)}", text_color='red')
                else:
                    files = [f.strip() for f in path.split(";") if f.strip()]
                    if all(os.path.exists(f) for f in files):
                        try:
                            for file in files:
                                if event == "Encrypt":
                                    self.encrypt_file(file, password)
                                else:
                                    self.decrypt_file(file, password)
                            window['-STATUS-'].update(f"{event} successful!", text_color='green')
                        except Exception as e:
                            window['-STATUS-'].update(f"Error: {str(e)}", text_color='red')
                    else:
                        window['-STATUS-'].update("Invalid path!", text_color='red')

        window.close()


if __name__ == '__main__':
    SecureFolderTool().run()
