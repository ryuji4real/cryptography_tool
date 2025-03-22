## 🔒 Cryptography Tool – A Versatile Encryption & Decryption Utility

This repository provides a powerful C-based cryptography tool, designed to implement a wide range of classic and modern encryption algorithms. Whether you're a cryptography enthusiast or a student exploring computer security, this tool is perfect for learning and experimenting! 🔐💻

### ✨ Features

✅ **Encryption/Decryption**: Supports César, XOR, Vigenère, ROT13, Base64, Substitution, AES, and Transposition  
✅ **Cryptanalysis**: Algorithm detection, César brute force, frequency analysis  
✅ **Hashing**: Compute SHA-256 hashes  
✅ **Compression**: Compress/decompress with zlib  
✅ **Batch Processing**: Encrypt multiple files at once  
✅ **History Tracking**: Log your actions  
✅ **Key Generation**: Generate random keys (letters, numbers, mixed, or secure for AES)  
✅ **Interface**: Interactive menu and command-line interface (CLI)

---

## 🚀 Installation

### Prerequisites
This project was developed and tested on **Windows** using **MSYS2 MinGW64**. Follow these steps to set up your environment:

1️⃣ **Install MSYS2**  
- Download MSYS2 from [msys2.org](https://www.msys2.org/).  
- Follow the installation instructions.  
- Open the **MSYS2 MinGW 64-bit** terminal (important: use this environment).

2️⃣ **Update MSYS2**  
In the MSYS2 MinGW 64-bit terminal:  
```bash
pacman -Syu
```
If prompted to close and restart the terminal, do so and rerun the command.

3️⃣ **Install Dependencies**  
Install the required tools and libraries:  
```bash
pacman -S mingw-w64-x86_64-gcc    # GCC compiler
pacman -S mingw-w64-x86_64-make   # For 'make' command
pacman -S mingw-w64-x86_64-openssl  # OpenSSL (for AES and SHA-256)
pacman -S mingw-w64-x86_64-zlib   # zlib (for compression)
```

4️⃣ **Verify Installations**  
Ensure everything is installed correctly:  
```bash
gcc --version
make --version
openssl version
```

### Clone and Compile

1️⃣ **Clone the Repository**  
```bash
git clone https://github.com/ryuji4real/cryptography_tool.git
```

2️⃣ **Navigate to the Project Folder**  
```bash
cd Cryptography_Tool
```

3️⃣ **Compile the Project**  
```bash
make clean
make
```
This will generate the executable in the `bin` directory.

---

## 🌐 Execution

### Option 1: Run from MSYS2 MinGW64 (Recommended)  
The MSYS2 terminal automatically sets up the path for DLLs, making this the easiest method:  
```bash
./bin/program
```

### Option 2: Run from Windows Explorer or CMD  
You may encounter a DLL error (`libcrypto-3-x64.dll not found`). Here’s how to fix it:  

1️⃣ **Add DLL Path to PATH**  
Temporarily add the DLL path:  
```cmd
set PATH=%PATH%;C:\msys64\mingw64\bin
```  
Or add `C:\msys64\mingw64\bin` to your PATH permanently via Windows settings:  
- Search for "Edit environment variables" in the Start menu.  
- Under "System variables," find `Path`, click "Edit," and add `C:\msys64\mingw64\bin`.  

2️⃣ **Run the Program**  
```cmd
cd path\to\Cryptography_Tool
bin\program.exe
```

**Alternative**: Copy `libcrypto-3-x64.dll`, `libssl-3-x64.dll`, and `zlib1.dll` from `C:\msys64\mingw64\bin` to the `bin` directory of your project.

### Usage Examples

- **Interactive Mode**  
  Launch the program:  
  ```bash
  ./bin/program
  ```  
  Choose an option (0–29) from the menu.  
  Example: Option 1 (César) with "HELLO" and key 3 → Result: "KHOOR".  

- **CLI Mode**  
  Encrypt directly from the command line:  
  ```bash
  ./bin/program --encrypt cesar --key 3 --input HELLO
  ```  
  Expected result: `Result: KHOOR`

---

💡 **Powerful and easy to use – perfect for exploring cryptography!** 🚀
