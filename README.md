# Encrypted File Transfer: Client-Server Project

## Project Overview

This project implements a secure file transfer system using a client-server architecture. The server is written in **Python**, and the client is implemented in **C++**. The project uses **RSA** and **AES** encryption to ensure secure communication and file transfer between the client and the server.

### Features:
- **Client-server communication** over TCP.
- **Encrypted file transfer** using AES for symmetric encryption and RSA for key exchange.
- **Checksum verification** to ensure file integrity during transmission.
- Supports **multiple clients** through multi-threading on the server side.

## Architecture

### Server
- **Language:** Python (version 3.12.1)
- **Encryption library:** PyCryptodome
- The server manages file storage and client registration.
- It listens on a port (specified in a configuration file) and handles multiple clients using selectors.
- Upon receiving a file, the server verifies the integrity of the file using a checksum, and it can request retransmission if errors are detected.

### Client
- **Language:** C++ (version 17)
- **Encryption library:** Crypto++ (for RSA and AES encryption)
- **Communication library:** boost (for TCP communication)
- The client initiates communication, exchanges encryption keys with the server, and securely sends files.
- The client uses a configuration file to specify the server’s port, user details and the file to be transferred.

## Setup Instructions

### Prerequisites
- **Python 3.12.1** (for the server)
- **Visual Studio 2022** (for compiling the C++ client)
- **PyCryptodome** Python package for encryption in the server:
  ```bash
  pip install pycryptodome
  ```
  or just
  ```bash
  pip install -r requirements.txt
  ```
- Crypto++ library for the C++ client

## Installation

### Server Setup
1. Clone the repository and navigate to the server directory.
2. Ensure you have Python 3.12 installed. Install the required dependencies with:

   ```bash
   pip install pycryptodome
   ```

3. Create a file named `port.info` in the server directory, containing the port number the server should listen on (e.g., `1234`).
4. Run the server:

   ```bash
   python server.py
   ```

### Client Setup
1. Open the C++ client project in Visual Studio.
2. Install the Crypto++ library (ensure it is linked properly in the project).
3. Create a `transfer.info` file in the client directory with the following information:
  - Server IP and port (e.g., `127.0.0.1:1234`)
  - Client name (up to 100 characters)
  - File path to the file you wish to transfer
4. Build and run the client.

## Usage
1. Start the server first by running the Python script.
2. Once the server is running, execute the client, which will:
  - Register with the server if it’s the first connection.
  - Exchange RSA keys for encryption.
  - Transfer the file to the server using AES encryption.
3. The server will verify the file using a checksum and request retransmission if necessary.

## Example

### Server Command:
```bash
python server.py
```

### Client Command (in Visual Studio terminal):
1. Modify the `transfer.info` file as described.
2. Run the client from Visual Studio.

## Project Structure
```
/server
  - server.py
  - port.info
  /common (Unites many useful functions and utils to be used across the server)
    - cksum.py
    - crypto.py
    - utils.py
  /communication (Unites all logics related to the actual communication)
    - communication.py
    - constants.py
    - requests_handlers.py
  /entities (OOP implementation of entities in the buissness logic of the project)
    - file.py
    - user.py
    - users.py
    - users_db.py
  /users_files (To store the exchanged files)
/client
  - client.cpp
  - transfer.info
  - Makefile
  - me.info (Optional. If does not exist, should be created during an initial run)
  /common (Unites many useful functions and utils to be used across the client)
    - cksum.cpp
    - cksum.h
    - crypto.cpp
    - crypto.h
    - utils.cpp
    - utils.h
  /communication (Unites all logics related to the actual communication)
    - communication.cpp
    - communication.h
    - constants.h
    - utils.cpp
    - utils.h
- README.md
```

## License
This project is part of a study assignment and is not licensed for commercial use.
