# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-03-08

### Added
- Encrypted file transfer support over LAN
- New `FileTransfer` class for sending and receiving files securely
- CLI commands for file transfer operations:
  - `send-file` - Send a file to a specific target
  - `receive-file` - Listen for incoming files
- Progress tracking for file transfers
- File integrity verification via SHA-256 checksums
- Support for digital signatures in file transfers
- File chunking for efficient transfer of large files
- Comprehensive documentation and examples

## [0.2.1] - 2025-03-07

### Fixed
- Fixed thread handling in Scanner class to properly handle thread termination
- Improved test coverage for thread management in scanner specs
- Resolved issue with ARP updater thread cleanup

## [0.2.0] - 2025-03-07

### Added
- Digital signature support for message authentication and integrity
- New `Signer` class for creating and verifying digital signatures
- RSA-based key pair generation for signing and verification
- CLI command for generating key pairs (`keygen`)
- Support for signed-encrypted and signed-plaintext message formats
- Signature verification in message processing
- Updated documentation with signature examples

### Changed
- Enhanced `Encryptor.prepare_message` to accept a private key for signing
- Modified `Encryptor.process_message` to verify signatures with public keys
- Extended message formats to include signature information
- CLI commands updated to support digital signature options
- Return values from message processing now include verification status

### Fixed
- Improved error handling for encryption and signature operations

## [0.1.0] - 2025-03-06

### Added
- Initial release of Lanet
- Basic UDP-based message sending and receiving
- Support for encrypted and plaintext messages
- Broadcasting capability
- Simple CLI interface
