# CASTLEfs

**Cascading Door Filesystem Encryption**

[[License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[[Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[[Version](https://img.shields.io/badge/version-2.0.0-green.svg)](https://github.com/username/CASTLEfs)

CASTLEfs is a portable filesystem encryption system that implements a cascading door authentication architecture. It provides layered security through multiple configurable "doors," each with distinct key requirements, combined with fractal-modulated cryptographic transformations for data protection.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Door Types](#door-types)
- [Cascade Configurations](#cascade-configurations)
- [Usage](#usage)
  - [Interactive CLI](#interactive-cli)
  - [Programmatic API](#programmatic-api)
- [Castle File Format](#castle-file-format)
- [Security Considerations](#security-considerations)
- [API Reference](#api-reference)
- [Testing](#testing)
- [License](#license)

## Features

CASTLEfs offers a comprehensive set of encryption and key management capabilities:

- **Multiple Door Types**: Four distinct door types (OPEN, SEQUENTIAL, COMPOUND, EXTERNAL) with flexible key requirements enabling complex access control patterns
- **Fractal-Modulated Cryptography**: Key derivation enhanced with fractal generators (Julia sets, Lorenz attractors, Hénon maps, logistic maps) for additional entropy
- **Cryptographic Lockbox System**: Secure storage for derived keys with HMAC verification
- **Portable Castle Files**: Export and import encrypted vaults as self-contained `.castle` files with N-key protection
- **Directory-to-Room Import**: Recursive directory encryption with passthrough or fine-grained key control
- **Encrypted Notes System**: Built-in secure notes with create, read, update, delete, and search capabilities
- **100% Round-Trip Accuracy**: Full reversibility verified through comprehensive test suite
- **Interactive CLI**: Menu-driven interface for all operations

## Installation

CASTLEfs requires Python 3.8 or higher and uses NumPy for numerical operations.

```bash
# Clone the repository
git clone https://github.com/username/CASTLEfs.git
cd CASTLEfs

# Install dependencies
pip install numpy

# Optional: Install scipy for differential evolution optimization
pip install scipy
```

### Dependencies

| Package | Required | Purpose |
|---------|----------|---------|
| numpy | Yes | Numerical operations and FFT transforms |
| scipy | No | Differential evolution optimization (optional) |

## Quick Start

Launch the interactive CLI to create your first encrypted castle:

```bash
python CASTLEfs.py
```

For a quick encryption workflow:

```python
from CASTLEfs import create_simple_cascade, CastleFile, DoorKey

# Create a cascade with 2 doors
cascade = create_simple_cascade(num_doors=2)

# Create a key from password
key = DoorKey.from_password("your-secure-password", "master_key")

# Unlock the cascade
cascade.unlock_cascade(key)

# Encrypt data
data = b"Sensitive information to protect"
result = cascade.encrypt(data)

# Decrypt data
decrypted = cascade.decrypt(result)
assert decrypted == data
```

## Architecture

CASTLEfs implements a layered encryption architecture where data passes through multiple "doors," each applying cryptographic transformations based on its configuration.

```
┌─────────────────────────────────────────────────────────────────┐
│                        CASTLE STRUCTURE                         │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐      │
│  │  Door 1 │───▶│  Door 2 │───▶│  Door 3 │───▶│  Door N │      │
│  │  (OPEN) │    │  (SEQ)  │    │(COMPOUND│    │   ...   │      │
│  └─────────┘    └─────────┘    └─────────┘    └─────────┘      │
│       │              │              │              │            │
│       ▼              ▼              ▼              ▼            │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐      │
│  │ Lockbox │    │ Lockbox │    │ Lockbox │    │ Lockbox │      │
│  └─────────┘    └─────────┘    └─────────┘    └─────────┘      │
├─────────────────────────────────────────────────────────────────┤
│                     ENCRYPTION PIPELINE                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │   FFT    │─▶│ Permute  │─▶│  Phase   │─▶│  Chain   │        │
│  │Transform │  │  (Braid) │  │  Twist   │  │   Next   │        │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

### Core Components

The system consists of several interconnected components. **DoorKey** represents cryptographic key material with methods for derivation and combination. **DoorConfig** defines the configuration for a single door including its type, key requirements, and cryptographic parameters. **CascadeConfig** holds the complete configuration for a door cascade including all doors and the master salt. **CascadingDoor** implements the encryption and decryption logic for a single door. **CascadingDoorSystem** orchestrates the complete cascade of doors. **CastleFile** provides the portable file format for exporting and importing encrypted vaults. **Lockbox** offers secure storage for derived keys with integrity verification.

## Door Types

CASTLEfs supports four distinct door types, each serving different access control requirements:

### OPEN

The OPEN door requires no key to pass through but propagates an initial key for the chain. It serves as an entry point that establishes the key derivation chain without requiring authentication at that specific door.

```python
DoorConfig(
    door_id="entrance",
    door_type=DoorType.OPEN,
    block_size=512
)
```

### SEQUENTIAL

The SEQUENTIAL door requires the key derived from the previous door. This creates a strict chain where each door depends on successfully unlocking all preceding doors.

```python
DoorConfig(
    door_id="inner_gate",
    door_type=DoorType.SEQUENTIAL,
    block_size=512
)
```

### COMPOUND

The COMPOUND door requires both the previous door's key and N additional external keys. This enables scenarios where multiple parties must cooperate to access protected data.

```python
DoorConfig(
    door_id="vault",
    door_type=DoorType.COMPOUND,
    required_external_keys=2,
    block_size=512
)
```

### EXTERNAL

The EXTERNAL door ignores the chain entirely and requires only N external keys. This allows for independent access control points within a cascade.

```python
DoorConfig(
    door_id="external_lock",
    door_type=DoorType.EXTERNAL,
    required_external_keys=1,
    block_size=512
)
```

## Cascade Configurations

CASTLEfs provides three pre-configured cascade patterns optimized for different use cases:

### RC1: Gemini Depth-Based

This configuration uses depth-based key derivation with fractal-modulated permutations. It consists of three doors (OPEN, SEQUENTIAL, COMPOUND) and employs Julia and Lorenz fractals for modulation.

```python
cascade = create_rc1_cascade("password", salt)
```

### RC2: SHA256 Fractal

This configuration uses SHA256 direct key derivation with fractal permutations. It features three doors (OPEN, SEQUENTIAL, EXTERNAL) and employs Julia and Hénon fractals.

```python
cascade = create_rc2_cascade("password", salt)
```

### RC3: Blake2b Mixed

This configuration uses Blake2b with fractal modulation and password-seeded permutations. It provides four doors for maximum security depth and employs logistic map, Julia, Lorenz, and Hénon fractals.

```python
cascade = create_rc3_cascade("password", salt)
```

### Custom Cascade

You can create custom cascades with specific door configurations:

```python
config = CascadeConfig(
    cascade_id="custom_cascade",
    doors=[
        DoorConfig(door_id="door_1", door_type=DoorType.OPEN, ...),
        DoorConfig(door_id="door_2", door_type=DoorType.SEQUENTIAL, ...),
        # Add more doors as needed
    ],
    master_salt=secrets.token_bytes(32)
)
cascade = CascadingDoorSystem(config)
```

## Usage

### Interactive CLI

Launch the interactive command-line interface:

```bash
python CASTLEfs.py
```

The CLI provides a menu-driven interface for creating castles, managing keys, encrypting and decrypting data, working with the notes system, importing directories, and exporting to castle files.

### Command Line Options

```bash
python CASTLEfs.py           # Launch interactive CLI
python CASTLEfs.py --test    # Run test suite
python CASTLEfs.py --help    # Show help information
python CASTLEfs.py --version # Show version information
```

### Programmatic API

#### Creating and Using a Cascade

```python
from CASTLEfs import (
    CascadeConfig, DoorConfig, DoorType, DoorKey,
    CascadingDoorSystem, KeyDerivationMethod, FractalType
)

# Define cascade configuration
config = CascadeConfig(
    cascade_id="my_cascade",
    doors=[
        DoorConfig(
            door_id="entrance",
            door_type=DoorType.OPEN,
            key_derivation=KeyDerivationMethod.BLAKE2B_FRACTAL,
            fractal_type=FractalType.JULIA,
            block_size=512,
            depth=0
        ),
        DoorConfig(
            door_id="vault",
            door_type=DoorType.SEQUENTIAL,
            key_derivation=KeyDerivationMethod.BLAKE2B_FRACTAL,
            fractal_type=FractalType.LORENZ,
            block_size=512,
            depth=1
        )
    ]
)

# Create system and unlock
cascade = CascadingDoorSystem(config)
master_key = DoorKey.from_password("secure-password", "master")
cascade.unlock_cascade(master_key)

# Encrypt and decrypt
encrypted = cascade.encrypt(b"Secret data")
decrypted = cascade.decrypt(encrypted)
```

#### Working with Castle Files

```python
from CASTLEfs import CastleFile, DoorKey, create_simple_cascade
from pathlib import Path

# Create castle with 2-key protection
castle = CastleFile(required_keys=2)
cascade = create_simple_cascade(2)
castle.set_cascade_config(cascade.config)

# Set up keys
key1 = DoorKey.from_password("password1", "key1")
key2 = DoorKey.from_password("password2", "key2")
keys = [key1, key2]

# Unlock and add encrypted content
cascade.unlock_cascade(key1)
result = cascade.encrypt(b"Protected content")
castle.add_encrypted_item("document", result)

# Export to file
castle.export_to_file(Path("vault.castle"), keys)

# Import from file
imported = CastleFile.import_from_file(Path("vault.castle"), keys)
```

#### Directory Import and Export

```python
from CASTLEfs import DirectoryImporter, DirectoryExporter, ImportMode
from pathlib import Path

# Import a directory
importer = DirectoryImporter(cascade, castle)
room = importer.import_directory(
    Path("/path/to/directory"),
    "my_room",
    ImportMode.PASSTHROUGH
)
castle.rooms["my_room"] = room

# Export a room
exporter = DirectoryExporter(cascade, castle)
exporter.export_room("my_room", Path("/path/to/output"), recursive=True)
```

#### Using the Notes System

```python
from CASTLEfs import NotesManager

notes = NotesManager(cascade, castle)

# Create a note
notes.create_note("Meeting Notes", "Discussion points...")

# Read a note
note = notes.read_note("Meeting Notes")
print(note['content'])

# Search notes
results = notes.search_notes("discussion")

# Update a note
notes.update_note("Meeting Notes", "Updated content...")

# Delete a note
notes.delete_note("Meeting Notes")
```

## Castle File Format

The `.castle` file format is a portable, self-contained encrypted archive:

```
┌────────────────────────────────────────┐
│  Magic Number (8 bytes): "CASTLE02"    │
│  Version (1 byte)                      │
│  Required Keys (1 byte)                │
│  Nonce (16 bytes)                      │
│  HMAC (32 bytes)                       │
│  Payload Length (8 bytes)              │
│  Encrypted Payload (variable)          │
│    └─ Compressed JSON:                 │
│       ├─ cascade_config                │
│       ├─ encrypted_items               │
│       ├─ rooms (hierarchical)          │
│       ├─ notes                         │
│       ├─ lockbox_data                  │
│       └─ metadata                      │
└────────────────────────────────────────┘
```

The payload is compressed with gzip and encrypted using a keystream derived from the combined master keys. HMAC verification ensures integrity.

## Security Considerations

CASTLEfs is designed as an experimental encryption system and should be evaluated carefully before use in production environments.

**Cryptographic Primitives**: The system uses Blake2b and SHA256 for hashing, FFT-based spectral braiding for data transformation, and fractal-modulated phase shifts for additional entropy.

**Key Derivation**: Keys are derived using configurable methods including depth-based derivation, direct SHA256 hashing, and Blake2b with fractal modulation. The fractal modulation adds computational complexity but should not be considered a substitute for established KDFs like Argon2 or scrypt for password-based key derivation.

**Known Limitations**: The system does not implement authenticated encryption (AEAD) beyond HMAC on the castle file. Side-channel resistance has not been formally analyzed. The fractal generation provides deterministic pseudo-randomness, not cryptographic randomness.

**Recommendations**: Use strong, unique passwords for each key. Store castle files securely. Consider this system for defense-in-depth rather than as a sole protection mechanism. Review the source code and conduct security audits before deployment.

## API Reference

### Core Classes

**DoorKey** represents cryptographic key material. The `from_password` class method creates a key from a password string. The `derive_seed` method derives an integer seed from key material. The `combine_with` method combines two keys into a new derived key. The `derive_next` method derives a new key for the next door in chain.

**DoorConfig** configures a single door with properties including `door_id` (unique identifier), `door_type` (OPEN, SEQUENTIAL, COMPOUND, or EXTERNAL), `required_external_keys` (number of external keys needed), `key_derivation` (derivation method), `permutation_method` (permutation generation approach), `fractal_type` (fractal generator for modulation), `block_size` (FFT block size), and `depth` (position in cascade).

**CascadingDoorSystem** orchestrates the cascade with methods including `unlock_cascade` to unlock all doors with provided keys, `lock_cascade` to lock all doors and clear keys, `encrypt` to encrypt data through all doors, and `decrypt` to decrypt data by reversing through all doors.

**CastleFile** manages portable castle files with methods including `export_to_file` to export castle to a .castle file, `import_from_file` class method to import castle from a .castle file, `add_encrypted_item` to add an encrypted item, `add_room` to add a room to the hierarchy, and `add_note` to add an encrypted note.

### Enumerations

**DoorType** defines OPEN (no key required), SEQUENTIAL (requires previous door key), COMPOUND (requires previous key plus N external), and EXTERNAL (requires only N external keys).

**KeyDerivationMethod** defines DEPTH_BASED, SHA256_DIRECT, and BLAKE2B_FRACTAL derivation approaches.

**FractalType** defines JULIA, LOGISTIC_MAP, LORENZ, HENON, and NONE fractal generators.

**ImportMode** defines PASSTHROUGH (single key for tree) and FINE_GRAINED (per-directory keys) import modes.

## Testing

Run the comprehensive test suite:

```bash
python CASTLEfs.py --test
```

The test suite validates cascade creation and unlocking, round-trip encryption and decryption accuracy, edge cases (single byte, all zeros, all byte values), lock and relock cycles, performance benchmarks, castle file export and import, notes system operations, and directory import and export.

Expected output shows test results for each cascade configuration and subsystem, with a summary indicating passed and failed tests.

## License

Copyright (c) Brian Richard RAMOS

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
