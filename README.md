<h1 align="center">🔒 Secure File Protection Tools</h1>

<p align="center">
  This repository contains two related Python tools that work together for secure file protection.
</p>

---

## [Tools](pplx://action/followup)

### [<span style="color:#0078D7;">Secure Folder/File Protection Tool</span>](pplx://action/followup)
- Encrypts/decrypts local files and folders individually using unique password‑derived keys.
- **[Can also secure entire flash drives](pplx://action/followup)** by encrypting all files on the drive.

### [<span style="color:#28A745;">Portable Drive Guard</span>](pplx://action/followup)
- Runs directly from your flash drive.
- **[Works only if the flash drive is secured](pplx://action/followup)** using the main tool.  
- Allows you to lock/unlock files on the drive with the correct password.
- Allows selective unlocking of files, and tracks unlocked files in an encrypted “.dat” file so that only files explicitly unlocked by the portable tool are re‑encrypted.

---

## [Key Features](pplx://action/followup)

- **[Per-File Encryption](pplx://action/followup):**  
  Each file stores its own encrypted metadata so that only the correct password can decrypt it.
  
- **[Dark-Themed GUI](pplx://action/followup):**  
  Built with **FreeSimpleGUI**, featuring a responsive interface with real‑time progress updates and background processing.
  
- **[Flexible Use](pplx://action/followup):**  
  - Encrypt entire folders or select individual files.  
  - Secure entire flash drives with the main tool, and use the portable tool to lock/unlock them.
  - Prevent unintended changes by re‑locking only those files tracked by the portable tool
---

This project was created in **Python** using **FreeSimpleGUI** for the interface and the **cryptography** library for AES encryption. Its design focuses on simplicity and security so you can safely protect your important data without worry.


