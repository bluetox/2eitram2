# Oblivion Messenger

## What is Oblivion?

Oblivion is a decentralized messenger app. It prioritizes user anonymity and data security by leveraging cutting-edge encryption and privacy-preserving technologies. All connections are automatically routed through the Tor network, ensuring your communication remains private and untraceable. It relies on a network of community operated nodes.

## Key Features

### Privacy at Its Core
- **No Logging Policy**: Nodes don't really get any data to work with all the sensitive parts like ip or message are hidden.
- **Tor Integration**: All communications are automatically routed through the Tor network, protecting your identity and masking your online activity.

### Flexible User Access
- **Anonymous Chatting**: Quickly connect and chat without creating an account. A unique user ID is assigned securely using postquantum asymetric keys and a nonce to improve security.
- **Open source and easy to customize**: We aim to provide the user all the tools he needs to easily customize his messaging experience without compromising annonymity.

### Advanced local Security
- **Password encryption**: When first connecting you get Mnemonic words and a password the words are used to recover the password and the password itself is used to encrypt the entirity of your data. Make sure to put a strong one.
- **Password Storage**: Passwords are stored securely using bcrypt, providing robust protection against brute-force attacks.

### End-to-End Encryption (E2EE)
Every interaction in Oblivion is encrypted, ensuring complete confidentiality:
- **Key Exchange**: Uses Kyber 1024, a quantum-resistant algorithm, to establish secure keys.
- **Data Encryption**: Messages are encrypted using AES-GCM with unique keys and initialization vectors for each message.
- **Message Signing**: Employs Dilithium for message authentication and integrity.

### Encrypted File Transfer
Share files securely using the same advanced encryption techniques applied to messages. Files are encrypted with AES-GCM, ensuring confidentiality during transfer.

### User-Defined Password Protection
- Users define a password to encrypt their messages and shared secrets.
- This password is derived using PBKDF2 with 100,000 iterations to create a strong encryption key.
- The derived key decrypts AES-GCM-encrypted messages, with unique keys and initialization vectors for each transfer.

## Modern and Reliable Architecture
Built on the Tauri framework, Oblivion offers a good cross plateform experience.

## Technical Advantages
- **No Plaintext Vulnerabilities**: Passwords, messages, and file transfers are never stored or transmitted in plaintext.
- **Quantum-Resistant Cryptography**: Kyber 1024 and Dilithium secure your data against threats posed by quantum computing.
- **Encrypted Communication**: Unique encryption keys and initialization vectors for every message or file ensure robust security.
- **Zero Logging Policy**: No user data or activity is logged, guaranteeing anonymity.

## Why Choose Oblivion?

- **Privacy First**: No personal information is required to use the app.
- **Secure by Design**: Leveraging Tor, SHA-256, bcrypt, and modern cryptographic algorithms, your data is always protected.
- **Comprehensive Security**: From messages to file transfers, every aspect of your communication is encrypted end-to-end.
- **Ease of Use**: Whether chatting anonymously or logged in, Oblivion provides a user-friendly, secure messaging experience.

With Oblivion, your privacy isn’t just respected—it’s built into every line of code.
