# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-10-19

### 🎉 Major Release - Architectural Improvements

This is a major milestone release focused on code quality, maintainability, and architectural improvements while maintaining 100% backward compatibility.

### Added
- **Configuration Management**: New centralized `Config` class for managing all application constants and settings
- **Transfer State Management**: New `TransferState` class for better file transfer state handling
- **Enhanced Error Handling**: Custom exception classes (`SendError`, `ReceiveError`) with detailed context
- **Resource Management**: Proper cleanup methods (`close`, `closed?`) for network resources
- **Logging Infrastructure**: Centralized logger configuration via `Config.logger`
- **Health Monitoring**: Added `healthy?` and `stats` methods to Mesh network for monitoring
- **Documentation**: Comprehensive refactoring reports (`REFACTORING_REPORT.md`, `REFACTORING_SUMMARY.md`)

### Changed
- **Encryptor Refactoring**: Split monolithic methods into focused, single-purpose methods
  - Reduced cyclomatic complexity from 12+ to 2-3 per method
  - Extracted `prepare_plaintext`, `prepare_encrypted`, `prepare_signed_plaintext`, `prepare_signed_encrypted`
  - Improved message type parsing with `MessageType` enumeration
- **Sender Class**: Enhanced with input validation, error handling, and lifecycle management
- **Receiver Class**: Added graceful shutdown, configurable buffer sizes, and proper cleanup
- **FileTransfer**: Refactored using `TransferState` for cleaner state management
  - Reduced complexity by extracting state logic
  - Improved progress tracking and checksum verification
- **Code Organization**: Better separation of concerns across all modules
- **Constants Management**: Migrated all constants to centralized `Config` class

### Improved
- **Code Quality Metrics**:
  - 60% reduction in average method length (from 20-30 lines to 5-10 lines)
  - 75% reduction in cyclomatic complexity (critical components)
  - Better error messages with context-specific exceptions
- **Resource Management**: Eliminated resource leak risks with ensure blocks
- **Test Coverage**: All 96 tests passing with maintained backward compatibility
- **Memory Management**: Automatic cleanup of temporary files and network resources
- **Error Recovery**: More robust failure handling throughout the codebase

### Fixed
- Resource leaks in socket handling (proper cleanup in all scenarios)
- Potential memory issues in file transfer (proper temp file cleanup)
- Port conflict detection and reporting (clearer error messages)

### Technical Details
For detailed information about the architectural improvements and refactoring:
- See `REFACTORING_REPORT.md` for comprehensive analysis with metrics
- See `REFACTORING_SUMMARY.md` for technical implementation details

### Backward Compatibility
✅ **100% Backward Compatible** - All public APIs remain unchanged. No migration needed.

## [0.5.1] - 2025-03-20

### Changed
- Optimized traceroute implementation for better performance and code readability
- Simplified protocol selection logic with dedicated methods
- Improved error handling for socket operations
- Enhanced hostname extraction in traceroute results
- Reorganized code structure for better maintainability
- Added Windows-specific socket handling optimizations

### Fixed
- Fixed redundant code in socket handling for different operating systems
- Improved error messages for unprivileged traceroute attempts
- Fixed potential memory leaks in socket resource management
- Added proper handling for non-standard traceroute output formats

## [0.5.0] - 2025-03-12

### Added
- Advanced traceroute functionality for network path analysis
- Multiple protocol support for traceroute: ICMP, UDP, and TCP
- Load balancing detection in traceroute results
- CLI command: `traceroute` with protocol selection and customizable parameters
- Ruby API for programmatic traceroute operations
- Comprehensive documentation and examples for traceroute feature

## [0.4.0] - 2025-03-10

### Added
- Mesh networking functionality for decentralized communication
- Auto-discovery of mesh nodes
- Message routing through intermediate nodes
- CLI commands for mesh network operations: `mesh start`, `mesh send`, `mesh info`
- Ruby API methods for creating and managing mesh networks

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
