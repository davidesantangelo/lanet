# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-03-08

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
