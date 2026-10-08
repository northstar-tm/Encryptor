# Northstar Encrypt

Northstar Encrypt is a Windows desktop application for protecting files and folders in password-encrypted `.crypt` archives. Archive creation and restoration happen locally on your device.

## Features

- Encrypt an individual file or package a folder into one `.crypt` archive.
- Restore archives with the original passphrase.
- Use AES-256-GCM authenticated encryption with a key derived by PBKDF2-HMAC-SHA256.
- Open `.crypt` files from Windows Explorer after file association is registered.
- Install per user with the optional Windows installer; administrator privileges are not required.

## Install

Download and run `NorthstarEncrypt-Setup-1.0.0-win-x64.exe` from the project's Releases page. The installer adds a Start Menu shortcut, optionally creates a desktop shortcut, and registers `.crypt` for the current Windows user. Windows may still ask you to choose Northstar in **Settings > Apps > Default apps**.

The installer is currently unsigned, so Windows may show a publisher or SmartScreen warning.

On first launch, create a separate app access code. Northstar asks for this code each time it starts. It is not the same as the archive passphrase:

- The **app access code** is a local access deterrent. Its salted PBKDF2 verifier is stored in your Windows user profile.
- The **archive passphrase** encrypts and decrypts the archive contents. Northstar does not store it. If it is lost, the archive cannot be recovered.

The app access code is not an operating-system security boundary. Someone who can modify your Windows account or the installed application may bypass the app gate. Use a strong archive passphrase to protect the contents.

## Use

1. Choose **Encrypt** and select a file or folder.
2. Choose an output location, enter an archive passphrase of at least 12 characters, and confirm it.
3. Select **Encrypt** to create the `.crypt` archive. The source remains unchanged.
4. To restore, choose **Decrypt**, select a `.crypt` archive, choose an output location, and enter the same archive passphrase.

Double-clicking a `.crypt` file opens Northstar with the archive and suggested restore location prefilled. The passphrase is never prefilled.

## Build and test

Requirements: Windows and the .NET 8 SDK.

```powershell
dotnet restore NorthstarEncrypt.csproj
dotnet build NorthstarEncrypt.csproj
dotnet run --project NorthstarEncrypt.csproj
```

Run the crypto smoke checks:

```powershell
dotnet run --project tests/NorthstarEncrypt.SmokeTests/NorthstarEncrypt.SmokeTests.csproj
```

## Build the installer

Requirements: Windows, the .NET 8 SDK, and Inno Setup 6.

From the repository root, run:

```powershell
powershell -ExecutionPolicy Bypass -File installer/build-installer.ps1
```

The script publishes a self-contained `win-x64` application and builds:

```text
artifacts/installer/NorthstarEncrypt-Setup-1.0.0-win-x64.exe
```

The publish output is written to `artifacts/publish/win-x64/`. Both generated directories are excluded from Git. For a custom Inno Setup installation path, pass `-InnoCompiler "C:\path\to\ISCC.exe"` to the script.

## Security and limitations

- Archive contents use AES-256-GCM in independently authenticated chunks of up to 1 MiB.
- A 256-bit key is derived from the archive passphrase with PBKDF2-HMAC-SHA256 and 600,000 iterations. Each archive uses a random 128-bit salt and random nonce prefix.
- Version 2 archives authenticate their header independently, including when the payload is empty. Version 1 archives remain supported for decryption.
- The header is authenticated but not encrypted. It exposes the original base name, whether the payload is a file or folder, and the exact plaintext byte length.
- Folder packaging is held in memory and supports up to 1 GiB of compressed archive data. Folder restoration is limited to 10 GiB expanded data and 100,000 entries; unsafe paths and symbolic links are rejected.
- Files are written to temporary sibling paths and moved into place after successful completion. Failed file decryption does not leave a partial output file.
- Keep a separate backup of important originals. This utility has not undergone an independent security audit and is not a replacement for enterprise key management.

## Container format

Version 2 starts with the `NSTARCRY` magic value and stores a format version, payload kind, PBKDF2 iteration count, salt, nonce prefix, plaintext length, and UTF-8 original base name. A dedicated AES-GCM tag authenticates this header. The payload follows as records containing ciphertext and a 128-bit authentication tag. A per-archive nonce prefix plus a monotonically increasing counter provides a distinct nonce for the header and each record.
