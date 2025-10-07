# SSH Implementation in C

## Overview
This project implements a simplified, SSH-like system in C for educational purposes, demonstrating core SSH features such as secure connections, key exchange, authentication, and encrypted command execution. It includes a server, client, and setup utility, using OpenSSL for cryptography and POSIX sockets for networking. **This is not production-ready** and should only be used in a controlled, local environment for learning.

### Features
- **Secure Connection**: TCP sockets with TLS/SSL encryption (port 2222) using OpenSSL.
- **Key Exchange**: Elliptic-Curve Diffie-Hellman (ECDH) with a fallback to basic Diffie-Hellman (commented in code).
- **Authentication**: Supports password-based (SHA-256 hashed) and public-key (ECDSA) authentication.
- **Encrypted Command Channel**: AES-256-CBC encryption with HMAC-SHA256 for integrity.
- **Session Management**: Persistent sessions with an interactive shell-like interface.
- **Error Handling**: Robust logging for network, authentication, and protocol errors.
- **Extensibility**: Modular design for future additions like file transfer or port forwarding.

### Security Warning
This implementation is for **educational purposes only**. It lacks production-grade features like perfect forward secrecy, replay protection, and side-channel attack mitigations. For real-world use, use [OpenSSH](https://www.openssh.com/) or [libssh](https://www.libssh.org/).

## Dependencies
- **OpenSSL**: For cryptography (TLS, ECDH, AES, HMAC, ECDSA).
- **GCC**: C compiler.
- **Make**: Build tool.
- **Linux**: POSIX-compliant system (e.g., Ubuntu).

Install dependencies on Ubuntu/Debian:
```bash
sudo apt update
sudo apt install libssl-dev gcc make
```

## Project Structure
- `ssh_server.c`: SSH server listening on `localhost:2222`.
- `ssh_client.c`: SSH client for connecting and executing commands.
- `generate_keys.c`: Utility to generate ECDSA key pairs and self-signed TLS certificates.
- `Makefile`: Build configuration for compiling with OpenSSL.
- `users.txt`: User database (generated; format: `username:sha256_password:pubkey_file`).
- `server.crt`, `server.key`: TLS certificates (generated).
- `user.pub`, `user.key`: User ECDSA key pair (generated).
- `ssh_server.log`, `ssh_client.log`: Log files for debugging.

## Setup Instructions
1. **Clone or Create Files**:
   - Save `ssh_server.c`, `ssh_client.c`, `generate_keys.c`, and `Makefile` in a project directory.
2. **Install Dependencies**:
   - Run the command above to install OpenSSL, GCC, and Make.
3. **Compile the Project**:
   ```bash
   make
   ```
   - Produces `ssh_server`, `ssh_client`, and `generate_keys` executables.
4. **Generate Keys and Certificates**:
   ```bash
   ./generate_keys
   ```
   - Creates `server.crt`, `server.key`, `user.pub`, `user.key`, and `users.txt` (with user `user`, password `mysecurepass`, and public key).
5. **Start the Server**:
   ```bash
   ./ssh_server
   ```
   - Listens on `localhost:2222`. Logs to `ssh_server.log`.
6. **Run the Client**:
   - Use test commands below to connect and execute commands.

## Usage
- **Server**: Run `./ssh_server` to start the server on `localhost:2222`.
- **Client**: Run `./ssh_client` with options:
  ```bash
  ./ssh_client <username> <host> -p <port> [-password <pass> | -i <keyfile>] [command]
  ```
  - Examples:
    - Password auth: `./ssh_client user@localhost -p 2222 -password mysecurepass "echo 'Test SSH'"`
    - Public-key auth: `./ssh_client user@localhost -p 2222 -i user.key "whoami"`
    - Interactive mode: `./ssh_client user@localhost -p 2222 -i user.key`

## Test Commands
These commands verify the implementation’s features:

1. **Password Authentication**:
   ```bash
   ./ssh_client user@localhost -p 2222 -password mysecurepass "echo 'Test SSH'"
   ```
   - **Expected**: Outputs `Test SSH`.
   - **Verifies**: Password authentication, TLS, AES-256-CBC encryption, HMAC integrity.

2. **Public-Key Authentication**:
   ```bash
   ./ssh_client user@localhost -p 2222 -i user.key "whoami"
   ```
   - **Expected**: Outputs username (e.g., `user`).
   - **Verifies**: ECDSA authentication, ECDH key exchange.

3. **Interactive Session**:
   ```bash
   ./ssh_client user@localhost -p 2222 -i user.key
   ```
   - At `ssh>` prompt, enter:
     - `ls -la` (lists files)
     - `pwd` (shows directory)
     - `cat test.txt` (reads file, if exists)
     - `exit` (terminates session)
   - **Expected**: Executes commands and shows output in real-time.
   - **Verifies**: Persistent session, real-time I/O, encryption.

4. **Multiple Commands**:
   ```bash
   ./ssh_client user@localhost -p 2222 -i user.key "ls; pwd; whoami"
   ```
   - **Expected**: Executes commands sequentially, outputs results.
   - **Verifies**: Command parsing, session stability.

5. **Authentication Failure**:
   ```bash
   ./ssh_client wronguser@localhost -p 2222 -password wrongpass "echo test"
   ```
   - **Expected**: Fails with `Authentication failed` in logs or stderr.
   - **Verifies**: Authentication security.

6. **Encryption and Integrity**:
   - Use Wireshark to capture traffic on `localhost:2222`.
   - **Expected**: No plaintext visible (TLS and AES-256-CBC encryption); HMAC ensures integrity.
   - Alternatively, check `ssh_server.log` and `ssh_client.log` for encryption details.
   - **Verifies**: Secure channel, data integrity.

## Security Limitations
- **No Perfect Forward Secrecy**: ECDH uses static keys per session, risking past session data if keys are compromised.
- **No Replay Protection**: Lacks sequence numbers or timestamps to prevent replay attacks.
- **Simplified Protocol**: Omits SSH’s full packet structure, compression, and advanced features.
- **Mitigations**:
  - Add ephemeral keys for forward secrecy.
  - Implement sequence numbers or nonces for replay protection.
  - Use OpenSSH or libssh for production systems.

## Extensibility
- **File Transfer**: Add a protocol message type for SFTP-like operations.
- **Port Forwarding**: Extend server to handle TCP forwarding.
- **Modular Design**: Separate networking, crypto, and auth functions allow easy modifications.

## Notes
- **Diffie-Hellman Fallback**: ECDH is used by default. To use basic Diffie-Hellman, modify `perform_ecdh` in `ssh_server.c` and `ssh_client.c` to use `DH_new()`, `DH_generate_key()`, and `DH_compute_key()` (see OpenSSL documentation).
- **Logging**: Debug logs in `ssh_server.log` and `ssh_client.log`.
- **Testing**: Run only on `localhost` to avoid exposing vulnerabilities.
- **User Database**: Edit `users.txt` to add users or change credentials.

## License
This project is for educational use and provided as-is, with no warranty. Use at your own risk.

## Prompt

```
You are an expert in C programming, network security, and cryptography. Help me build a sophisticated SSH (Secure Shell) implementation in C, including both a server and client, with advanced features for educational purposes. Focus on the following:

1. **Secure Connection**: Use TCP sockets (server on port 2222) with TLS/SSL encryption using OpenSSL for secure transport.
2. **Key Exchange**: Implement a simplified Diffie-Hellman key exchange for session key derivation using OpenSSL's `BIGNUM` or `EC_KEY` for elliptic-curve Diffie-Hellman (ECDH). Provide code for both, but default to ECDH for better security.
3. **Authentication**: Support both password-based authentication (with hashed passwords stored in a file using SHA-256) and public-key authentication (using RSA or ECDSA via OpenSSL). Allow configurable user credentials.
4. **Encrypted Command Channel**: Use AES-256-CBC for symmetric encryption of commands and responses, with HMAC-SHA256 for message integrity (via OpenSSL).
5. **Session Management**: Support persistent sessions with an interactive shell-like interface, allowing multiple commands in one connection.
6. **Error Handling**: Include robust error handling for connection issues, authentication failures, and malformed packets, with detailed logging to a file or console.
7. **Extensibility**: Design modular code to allow future additions like file transfer (SFTP-like) or port forwarding.

Provide complete, well-commented, runnable code for:
- An SSH server (`ssh_server.cpp`) listening on `localhost:2222`.
- An SSH client (`ssh_client.cpp`) connecting to `localhost:2222`.
- A setup utility (`generate_keys.cpp`) to create RSA/ECDSA key pairs and self-signed TLS certificates.
- A `CMakeLists.txt` file for building the project with OpenSSL.

Use OpenSSL for all cryptographic operations and standard C libraries (e.g., `<sys/socket.h>`, `<netinet/in.h>` for POSIX systems) for networking. Warn about security limitations (e.g., no perfect forward secrecy, simplified protocol) and recommend production alternatives like OpenSSH or libssh.

After the code, provide:
1. Instructions to install dependencies (e.g., OpenSSL, CMake) on a Linux system.
2. Steps to compile and run the server and client.
3. A set of test commands to verify features like authentication, command execution, encryption, and session management.

Ensure the code is modular, follows
```

**Credits:** Grok


