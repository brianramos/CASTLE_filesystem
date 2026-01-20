#!/usr/bin/env python3
"""
CASTLEfs - Cascading Door Filesystem Encryption
================================================

Copyright (c) Brian Richard RAMOS
Licensed under the Apache License, Version 2.0

Enhanced with Cascading Door Authentication System and Lockbox Key Storage

Features:
- Multiple door types with flexible key requirements
- Best-performing component combinations from comparative testing
- Full reversibility with 100% round-trip accuracy
- Cryptographic lockbox system for secure key storage
- Portable .castle file export/import with N-key protection
- Directory-to-room import with recursive passthrough or fine-grained control
- File and room export to local directory
- Built-in encrypted notes reader
- Interactive CLI menu system

Door Types:
- OPEN: No key required (passes through initial key for chain)
- SEQUENTIAL: Requires key from previous door
- COMPOUND: Requires previous door key + N additional keys
- EXTERNAL: Requires only N external keys (bypasses chain)
"""

__version__ = "2.0.0"
__author__ = "Brian Richard RAMOS"
__license__ = "Apache-2.0"
__name_full__ = "CASTLEfs"

import numpy as np
import hashlib
import time
import secrets
import os
import json
import base64
import gzip
import getpass
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any, Callable, Union, Set
from enum import Enum, auto
from itertools import combinations
import struct
import sys

# Optional scipy import with fallback
try:
    from scipy.optimize import differential_evolution
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False


# =============================================================================
# SECTION 1: CORE TYPES AND CONFIGURATION
# =============================================================================

class DoorType(Enum):
    """Types of cascading doors with different key requirements."""
    OPEN = auto()        # No key required - pass-through but propagates initial key
    SEQUENTIAL = auto()  # Requires key from previous door only
    COMPOUND = auto()    # Requires previous door key + N additional keys
    EXTERNAL = auto()    # Requires only N external keys (ignores chain)


class KeyDerivationMethod(Enum):
    """Key derivation approaches from comparative testing."""
    DEPTH_BASED = "depth_based"
    SHA256_DIRECT = "sha256_direct"
    BLAKE2B_FRACTAL = "blake2b_fractal"


class PermutationMethod(Enum):
    """Permutation generation approaches."""
    DEPTH_SEEDED = "depth_seeded"
    PASSWORD_SEEDED = "password_seeded"
    FRACTAL_MODULATED = "fractal_modulated"


class FractalType(Enum):
    """Supported fractal generators for key derivation."""
    JULIA = "julia"
    LOGISTIC_MAP = "logistic"
    LORENZ = "lorenz"
    HENON = "henon"
    NONE = "none"


class ImportMode(Enum):
    """Directory import modes."""
    PASSTHROUGH = "passthrough"      # Use parent directory key for all descendants
    FINE_GRAINED = "fine_grained"    # Prompt for each subdirectory


@dataclass
class DoorKey:
    """Represents a key that can unlock a door."""
    key_id: str
    key_material: bytes
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def derive_seed(self) -> int:
        """Derive integer seed from key material."""
        return int(hashlib.sha256(self.key_material).hexdigest(), 16) % (2**32)
    
    def combine_with(self, other: 'DoorKey') -> 'DoorKey':
        """Combine two keys into a new derived key."""
        combined = hashlib.blake2b(
            self.key_material + other.key_material,
            digest_size=64
        ).digest()
        return DoorKey(
            key_id=f"{self.key_id}+{other.key_id}",
            key_material=combined,
            metadata={'derived_from': [self.key_id, other.key_id]}
        )
    
    def derive_next(self, door_id: str, salt: bytes) -> 'DoorKey':
        """Derive a new key for the next door in the chain."""
        derived = hashlib.blake2b(
            self.key_material + door_id.encode() + salt,
            digest_size=64
        ).digest()
        return DoorKey(
            key_id=f"derived_{door_id}",
            key_material=derived,
            metadata={'derived_from': self.key_id, 'door': door_id}
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize key to dictionary."""
        return {
            'key_id': self.key_id,
            'key_material': base64.b64encode(self.key_material).decode('utf-8'),
            'created_at': self.created_at,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DoorKey':
        """Deserialize key from dictionary."""
        return cls(
            key_id=data['key_id'],
            key_material=base64.b64decode(data['key_material']),
            created_at=data.get('created_at', time.time()),
            metadata=data.get('metadata', {})
        )
    
    @classmethod
    def from_password(cls, password: str, key_id: str = "password_key") -> 'DoorKey':
        """Create a key from a password string."""
        key_material = hashlib.blake2b(
            password.encode('utf-8'),
            digest_size=64
        ).digest()
        return cls(key_id=key_id, key_material=key_material)


@dataclass
class DoorConfig:
    """Configuration for a single cascading door."""
    door_id: str
    door_type: DoorType
    required_external_keys: int = 0
    key_derivation: KeyDerivationMethod = KeyDerivationMethod.DEPTH_BASED
    permutation_method: PermutationMethod = PermutationMethod.FRACTAL_MODULATED
    fractal_type: FractalType = FractalType.JULIA
    block_size: int = 512
    depth: int = 0
    
    def __post_init__(self):
        if self.door_type == DoorType.OPEN:
            self.required_external_keys = 0
        elif self.door_type == DoorType.SEQUENTIAL:
            self.required_external_keys = 0
        elif self.door_type == DoorType.EXTERNAL and self.required_external_keys < 1:
            self.required_external_keys = 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize door config to dictionary."""
        return {
            'door_id': self.door_id,
            'door_type': self.door_type.name,
            'required_external_keys': self.required_external_keys,
            'key_derivation': self.key_derivation.value,
            'permutation_method': self.permutation_method.value,
            'fractal_type': self.fractal_type.value,
            'block_size': self.block_size,
            'depth': self.depth
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DoorConfig':
        """Deserialize door config from dictionary."""
        return cls(
            door_id=data['door_id'],
            door_type=DoorType[data['door_type']],
            required_external_keys=data.get('required_external_keys', 0),
            key_derivation=KeyDerivationMethod(data.get('key_derivation', 'depth_based')),
            permutation_method=PermutationMethod(data.get('permutation_method', 'fractal_modulated')),
            fractal_type=FractalType(data.get('fractal_type', 'julia')),
            block_size=data.get('block_size', 512),
            depth=data.get('depth', 0)
        )


@dataclass
class CascadeConfig:
    """Configuration for a complete door cascade."""
    cascade_id: str
    doors: List[DoorConfig]
    master_salt: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    
    def validate(self) -> bool:
        """Validate the cascade configuration."""
        if not self.doors:
            return False
        if self.doors[0].door_type == DoorType.SEQUENTIAL:
            return False
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize cascade config to dictionary."""
        return {
            'cascade_id': self.cascade_id,
            'doors': [d.to_dict() for d in self.doors],
            'master_salt': base64.b64encode(self.master_salt).decode('utf-8')
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CascadeConfig':
        """Deserialize cascade config from dictionary."""
        return cls(
            cascade_id=data['cascade_id'],
            doors=[DoorConfig.from_dict(d) for d in data['doors']],
            master_salt=base64.b64decode(data['master_salt'])
        )


@dataclass
class BraidResult:
    """Result of encryption through a door or cascade."""
    encrypted_data: np.ndarray
    metadata: Dict[str, Any]
    door_chain: List[str]
    encryption_time_ms: float
    entropy_achieved: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for storage."""
        return {
            'encrypted_real': base64.b64encode(
                np.real(self.encrypted_data).astype(np.float64).tobytes()
            ).decode('utf-8'),
            'encrypted_imag': base64.b64encode(
                np.imag(self.encrypted_data).astype(np.float64).tobytes()
            ).decode('utf-8'),
            'shape': list(self.encrypted_data.shape),
            'metadata': self.metadata,
            'door_chain': self.door_chain,
            'encryption_time_ms': self.encryption_time_ms,
            'entropy_achieved': self.entropy_achieved
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BraidResult':
        """Deserialize from dictionary."""
        real_bytes = base64.b64decode(data['encrypted_real'])
        imag_bytes = base64.b64decode(data['encrypted_imag'])
        real_arr = np.frombuffer(real_bytes, dtype=np.float64)
        imag_arr = np.frombuffer(imag_bytes, dtype=np.float64)
        encrypted = real_arr + 1j * imag_arr
        return cls(
            encrypted_data=encrypted,
            metadata=data['metadata'],
            door_chain=data['door_chain'],
            encryption_time_ms=data.get('encryption_time_ms', 0),
            entropy_achieved=data.get('entropy_achieved', 0)
        )


@dataclass
class RoomItem:
    """Represents an item stored in a castle room."""
    name: str
    item_type: str  # 'file', 'note', 'directory'
    encrypted_result: Optional[BraidResult] = None
    children: Dict[str, 'RoomItem'] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'name': self.name,
            'item_type': self.item_type,
            'encrypted_result': self.encrypted_result.to_dict() if self.encrypted_result else None,
            'children': {k: v.to_dict() for k, v in self.children.items()},
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RoomItem':
        """Deserialize from dictionary."""
        return cls(
            name=data['name'],
            item_type=data['item_type'],
            encrypted_result=BraidResult.from_dict(data['encrypted_result']) if data.get('encrypted_result') else None,
            children={k: cls.from_dict(v) for k, v in data.get('children', {}).items()},
            metadata=data.get('metadata', {})
        )


# =============================================================================
# SECTION 2: LOCKBOX SYSTEM FOR SECURE KEY STORAGE
# =============================================================================

class Lockbox:
    """Cryptographic lockbox for storing derived keys."""
    
    LOCKBOX_FILENAME = ".lockbox"
    BLOCK_SIZE = 64
    
    def __init__(self, master_key: DoorKey, room_path: Optional[Path] = None):
        self.master_key = master_key
        self.room_path = Path(room_path) if room_path else None
        self._keys: Dict[str, DoorKey] = {}
        self._nonce: bytes = secrets.token_bytes(16)
    
    def _derive_encryption_key(self) -> bytes:
        """Derive an encryption key from the master key."""
        return hashlib.blake2b(
            self.master_key.key_material + b"lockbox_encryption",
            digest_size=32
        ).digest()
    
    def _generate_keystream(self, length: int) -> bytes:
        """Generate a keystream of the specified length."""
        key = self._derive_encryption_key()
        keystream = b''
        counter = 0
        
        while len(keystream) < length:
            block = hashlib.blake2b(
                key + self._nonce + counter.to_bytes(8, 'big'),
                digest_size=self.BLOCK_SIZE
            ).digest()
            keystream += block
            counter += 1
        
        return keystream[:length]
    
    def _xor_encrypt(self, data: bytes) -> bytes:
        """XOR stream cipher using derived keystream."""
        if len(data) == 0:
            return b''
        keystream = self._generate_keystream(len(data))
        return bytes(a ^ b for a, b in zip(data, keystream))
    
    def store_key(self, door_id: str, derived_key: DoorKey):
        """Store a derived key in the lockbox."""
        self._keys[door_id] = derived_key
    
    def retrieve_key(self, door_id: str) -> Optional[DoorKey]:
        """Retrieve a derived key from the lockbox."""
        return self._keys.get(door_id)
    
    def list_keys(self) -> List[str]:
        """List all key IDs stored in this lockbox."""
        return list(self._keys.keys())
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize lockbox to dictionary."""
        keys_data = {
            door_id: key.to_dict() 
            for door_id, key in self._keys.items()
        }
        return {
            'nonce': base64.b64encode(self._nonce).decode('utf-8'),
            'keys': keys_data
        }
    
    def from_dict_update(self, data: Dict[str, Any]):
        """Update lockbox from dictionary data."""
        self._nonce = base64.b64decode(data['nonce'])
        self._keys = {
            door_id: DoorKey.from_dict(key_data)
            for door_id, key_data in data['keys'].items()
        }
    
    def save(self):
        """Save the lockbox to disk."""
        if self.room_path is None:
            return
        
        self.room_path.mkdir(parents=True, exist_ok=True)
        lockbox_path = self.room_path / self.LOCKBOX_FILENAME
        
        keys_data = {
            door_id: key.to_dict() 
            for door_id, key in self._keys.items()
        }
        
        plaintext = json.dumps(keys_data).encode('utf-8')
        encrypted = self._xor_encrypt(plaintext)
        
        hmac_key = hashlib.blake2b(
            self._derive_encryption_key() + b"hmac",
            digest_size=32
        ).digest()
        hmac_value = hashlib.blake2b(
            plaintext,
            key=hmac_key,
            digest_size=32
        ).hexdigest()
        
        file_data = {
            'version': '1.0',
            'format': 'CASTLEfs',
            'nonce': base64.b64encode(self._nonce).decode('utf-8'),
            'encrypted_keys': base64.b64encode(encrypted).decode('utf-8'),
            'key_count': len(self._keys),
            'hmac': hmac_value
        }
        
        with open(lockbox_path, 'w') as f:
            json.dump(file_data, f, indent=2)
    
    def load(self) -> bool:
        """Load the lockbox from disk."""
        if self.room_path is None:
            return False
        
        lockbox_path = self.room_path / self.LOCKBOX_FILENAME
        if not lockbox_path.exists():
            return False
        
        try:
            with open(lockbox_path, 'r') as f:
                file_data = json.load(f)
            
            self._nonce = base64.b64decode(file_data['nonce'])
            encrypted = base64.b64decode(file_data['encrypted_keys'])
            plaintext = self._xor_encrypt(encrypted)
            
            hmac_key = hashlib.blake2b(
                self._derive_encryption_key() + b"hmac",
                digest_size=32
            ).digest()
            computed_hmac = hashlib.blake2b(
                plaintext,
                key=hmac_key,
                digest_size=32
            ).hexdigest()
            
            if computed_hmac != file_data['hmac']:
                return False
            
            keys_data = json.loads(plaintext.decode('utf-8'))
            self._keys = {
                door_id: DoorKey.from_dict(key_data)
                for door_id, key_data in keys_data.items()
            }
            return True
        except Exception:
            return False
    
    def create_subroom(self, room_name: str) -> 'Lockbox':
        """Create a lockbox for a subdirectory."""
        if self.room_path is None:
            sub_path = None
        else:
            sub_path = self.room_path / room_name
        
        sub_key = self.master_key.derive_next(room_name, b"subroom")
        return Lockbox(sub_key, sub_path)


class CascadeLockboxManager:
    """Manages lockboxes across a cascade of doors."""
    
    def __init__(self, base_path: Path, master_key: DoorKey, cascade_config: 'CascadeConfig'):
        self.base_path = Path(base_path)
        self.master_key = master_key
        self.cascade_config = cascade_config
        self.lockboxes: Dict[str, Lockbox] = {}
        
        self._initialize_structure()
    
    def _initialize_structure(self):
        """Create the directory/lockbox structure for the cascade."""
        current_key = self.master_key
        current_path = self.base_path
        
        for i, door_config in enumerate(self.cascade_config.doors):
            is_terminal = (i == len(self.cascade_config.doors) - 1)
            
            if not is_terminal:
                room_path = current_path / door_config.door_id
                lockbox = Lockbox(current_key, room_path)
                
                derived_key = current_key.derive_next(
                    door_config.door_id,
                    self.cascade_config.master_salt
                )
                lockbox.store_key(door_config.door_id, derived_key)
                
                self.lockboxes[door_config.door_id] = lockbox
                
                current_key = derived_key
                current_path = room_path
    
    def save_all(self):
        """Save all lockboxes to disk."""
        for lockbox in self.lockboxes.values():
            lockbox.save()
    
    def load_all(self) -> bool:
        """Load all lockboxes from disk."""
        all_loaded = True
        for lockbox in self.lockboxes.values():
            if not lockbox.load():
                all_loaded = False
        return all_loaded
    
    def get_chain_keys(self) -> Dict[str, DoorKey]:
        """Get all derived keys for the cascade."""
        result = {}
        for door_id, lockbox in self.lockboxes.items():
            key = lockbox.retrieve_key(door_id)
            if key:
                result[door_id] = key
        return result


# =============================================================================
# SECTION 3: KEY DERIVATION IMPLEMENTATIONS
# =============================================================================

class KeyDeriver:
    """Unified key derivation supporting multiple methods."""
    
    def __init__(self, method: KeyDerivationMethod, 
                 fractal_type: FractalType = FractalType.JULIA):
        self.method = method
        self.fractal_type = fractal_type
    
    def derive(self, base_key: DoorKey, block_size: int, 
               depth: int = 0, salt: bytes = b'') -> Tuple[np.ndarray, np.ndarray]:
        """Derive permutation and phase arrays from a key."""
        if self.method == KeyDerivationMethod.DEPTH_BASED:
            return self._derive_depth_based(base_key, block_size, depth, salt)
        elif self.method == KeyDerivationMethod.SHA256_DIRECT:
            return self._derive_sha256_direct(base_key, block_size, salt)
        elif self.method == KeyDerivationMethod.BLAKE2B_FRACTAL:
            return self._derive_blake2b_fractal(base_key, block_size, salt)
        else:
            raise ValueError(f"Unknown derivation method: {self.method}")
    
    def _derive_depth_based(self, key: DoorKey, block_size: int, 
                            depth: int, salt: bytes) -> Tuple[np.ndarray, np.ndarray]:
        """Gemini-style depth-based key derivation."""
        base_seed = key.derive_seed()
        salt_int = int.from_bytes(salt[:4], 'big') if len(salt) >= 4 else 0
        node_seed = (base_seed + depth * 99991 + salt_int) % (2**32)
        
        rng = np.random.Generator(np.random.PCG64(node_seed))
        perm = rng.permutation(block_size)
        phases = rng.uniform(0, 2 * np.pi, block_size)
        
        return perm, phases
    
    def _derive_sha256_direct(self, key: DoorKey, block_size: int,
                               salt: bytes) -> Tuple[np.ndarray, np.ndarray]:
        """Mistral-style SHA256 direct derivation."""
        combined = key.key_material + salt
        hash_bytes = hashlib.sha256(combined).digest()
        seed = int.from_bytes(hash_bytes, 'big') % (2**32)
        
        rng = np.random.Generator(np.random.PCG64(seed))
        perm = rng.permutation(block_size)
        phases = rng.uniform(0, 2 * np.pi, block_size)
        
        return perm, phases
    
    def _derive_blake2b_fractal(self, key: DoorKey, block_size: int,
                                 salt: bytes) -> Tuple[np.ndarray, np.ndarray]:
        """Claude-style Blake2b with fractal modulation."""
        effective_salt = (salt[:16] if len(salt) >= 16 
                          else salt.ljust(16, b'\x00') if salt 
                          else b'\x00' * 16)
        
        password_hash = hashlib.blake2b(
            key.key_material,
            salt=effective_salt,
            digest_size=64
        ).digest()
        
        seed_perm = int.from_bytes(password_hash[:8], 'big') % (2**63)
        seed_phase = int.from_bytes(password_hash[8:16], 'big') % (2**63)
        seed_fractal = int.from_bytes(password_hash[16:24], 'big') % (2**63)
        
        fractal_coords = self._generate_fractal(seed_fractal, block_size)
        
        rng_perm = np.random.Generator(np.random.PCG64(seed_perm))
        perm = rng_perm.permutation(block_size)
        
        rng_phase = np.random.Generator(np.random.PCG64(seed_phase))
        base_phases = rng_phase.uniform(0, 2 * np.pi, block_size)
        phases = base_phases * (0.5 + fractal_coords)
        
        return perm, phases
    
    def _generate_fractal(self, seed: int, size: int) -> np.ndarray:
        """Generate fractal coordinates for modulation."""
        rng = np.random.Generator(np.random.PCG64(seed))
        
        if self.fractal_type == FractalType.JULIA:
            c = complex(rng.uniform(-0.8, 0.8), rng.uniform(-0.8, 0.8))
            t = np.linspace(0, 4 * np.pi, size)
            r = np.linspace(0.1, 1.5, size)
            z = r * np.exp(1j * t)
            escape = np.zeros(size, dtype=np.float64)
            for _ in range(100):
                mask = np.abs(z) < 2
                escape[mask] += 1
                z[mask] = z[mask] ** 2 + c
            return escape / 100
        
        elif self.fractal_type == FractalType.LOGISTIC_MAP:
            r_param = 3.9 + rng.uniform(0, 0.1)
            x = rng.uniform(0.1, 0.9)
            for _ in range(1000):
                x = r_param * x * (1 - x)
            coords = np.zeros(size)
            for i in range(size):
                x = r_param * x * (1 - x)
                coords[i] = x
            return coords
        
        elif self.fractal_type == FractalType.LORENZ:
            sigma, rho, beta = 10.0, 28.0, 8.0 / 3.0
            dt = 0.01
            xyz = rng.uniform(-1, 1, 3)
            x, y, z = xyz[0], xyz[1], xyz[2]
            for _ in range(1000):
                dx = sigma * (y - x)
                dy = x * (rho - z) - y
                dz = x * y - beta * z
                x, y, z = x + dx * dt, y + dy * dt, z + dz * dt
            coords = np.zeros(size)
            for i in range(size):
                dx = sigma * (y - x)
                dy = x * (rho - z) - y
                dz = x * y - beta * z
                x, y, z = x + dx * dt, y + dy * dt, z + dz * dt
                coords[i] = (x + y + z) % 1.0
            return coords
        
        elif self.fractal_type == FractalType.HENON:
            a = 1.4 + rng.uniform(-0.01, 0.01)
            b = 0.3 + rng.uniform(-0.01, 0.01)
            xy = rng.uniform(-0.5, 0.5, 2)
            x, y = xy[0], xy[1]
            for _ in range(1000):
                x_new = 1 - a * x * x + y
                y = b * x
                x = x_new
            coords = np.zeros(size)
            for i in range(size):
                x_new = 1 - a * x * x + y
                y = b * x
                x = x_new
                coords[i] = (x + 1) / 2
            return np.clip(coords, 0, 1)
        
        else:
            return rng.uniform(0, 1, size)


# =============================================================================
# SECTION 4: CASCADING DOOR IMPLEMENTATION
# =============================================================================

class CascadingDoor:
    """A single door in a cascading encryption chain."""
    
    def __init__(self, config: DoorConfig, cascade_salt: bytes):
        self.config = config
        self.cascade_salt = cascade_salt
        self.block_size = config.block_size
        
        self.key_deriver = KeyDeriver(
            config.key_derivation,
            config.fractal_type
        )
        
        self._perm: Optional[np.ndarray] = None
        self._phases: Optional[np.ndarray] = None
        self._inv_perm: Optional[np.ndarray] = None
        self._unlocked = False
        self._effective_key: Optional[DoorKey] = None
        self._input_chain_key: Optional[DoorKey] = None
    
    @property
    def is_unlocked(self) -> bool:
        return self._unlocked
    
    def unlock(self, chain_key: Optional[DoorKey] = None,
               external_keys: Optional[List[DoorKey]] = None) -> bool:
        """Attempt to unlock the door with provided keys."""
        external_keys = external_keys or []
        
        if not self._validate_keys(chain_key, external_keys):
            return False
        
        self._input_chain_key = chain_key
        effective_key = self._derive_effective_key(chain_key, external_keys)
        
        if effective_key is None and self.config.door_type != DoorType.OPEN:
            return False
        
        self._effective_key = effective_key
        
        if effective_key is not None:
            door_salt = hashlib.sha256(
                self.cascade_salt + self.config.door_id.encode()
            ).digest()
            
            self._perm, self._phases = self.key_deriver.derive(
                effective_key,
                self.block_size,
                self.config.depth,
                door_salt
            )
            self._inv_perm = np.argsort(self._perm)
        else:
            self._perm = np.arange(self.block_size)
            self._phases = np.zeros(self.block_size)
            self._inv_perm = np.arange(self.block_size)
        
        self._unlocked = True
        return True
    
    def _validate_keys(self, chain_key: Optional[DoorKey],
                       external_keys: List[DoorKey]) -> bool:
        """Validate that the provided keys meet door requirements."""
        dtype = self.config.door_type
        
        if dtype == DoorType.OPEN:
            return True
        elif dtype == DoorType.SEQUENTIAL:
            return chain_key is not None
        elif dtype == DoorType.COMPOUND:
            return (chain_key is not None and 
                    len(external_keys) >= self.config.required_external_keys)
        elif dtype == DoorType.EXTERNAL:
            return len(external_keys) >= self.config.required_external_keys
        return False
    
    def _derive_effective_key(self, chain_key: Optional[DoorKey],
                               external_keys: List[DoorKey]) -> Optional[DoorKey]:
        """Combine all keys into a single effective key."""
        dtype = self.config.door_type
        
        if dtype == DoorType.OPEN:
            return chain_key
        elif dtype == DoorType.SEQUENTIAL:
            return chain_key
        elif dtype == DoorType.COMPOUND:
            result = chain_key
            for ext_key in external_keys[:self.config.required_external_keys]:
                result = result.combine_with(ext_key)
            return result
        elif dtype == DoorType.EXTERNAL:
            if not external_keys:
                return None
            result = external_keys[0]
            for ext_key in external_keys[1:self.config.required_external_keys]:
                result = result.combine_with(ext_key)
            return result
        return None
    
    def get_output_key(self) -> Optional[DoorKey]:
        """Get the key to pass to the next door in the chain."""
        if not self._unlocked:
            return None
        
        if self.config.door_type == DoorType.OPEN:
            if self._input_chain_key is not None:
                return self._input_chain_key.derive_next(
                    self.config.door_id,
                    self.cascade_salt
                )
            else:
                key_material = hashlib.blake2b(
                    self.cascade_salt + self.config.door_id.encode() + b"open_init",
                    digest_size=64
                ).digest()
                return DoorKey(
                    key_id=f"init_{self.config.door_id}",
                    key_material=key_material,
                    metadata={'source': 'open_door_init'}
                )
        
        key_material = hashlib.blake2b(
            self._perm.tobytes() + self._phases.tobytes() + self.cascade_salt,
            digest_size=64
        ).digest()
        
        return DoorKey(
            key_id=f"derived_{self.config.door_id}",
            key_material=key_material,
            metadata={'source_door': self.config.door_id}
        )
    
    def encrypt_block(self, block: np.ndarray, is_frequency_domain: bool = False) -> Tuple[np.ndarray, bool]:
        """Encrypt a single block through this door."""
        if not self._unlocked:
            raise RuntimeError(f"Door {self.config.door_id} is not unlocked")
        
        if self.config.door_type == DoorType.OPEN:
            return block.copy(), is_frequency_domain
        
        if not is_frequency_domain:
            freq = np.fft.fft(block)
        else:
            freq = block
        
        braided = freq[self._perm]
        twisted = braided * np.exp(1j * self._phases)
        
        return twisted, True
    
    def decrypt_block(self, block: np.ndarray, is_frequency_domain: bool = True) -> Tuple[np.ndarray, bool]:
        """Decrypt a single block through this door."""
        if not self._unlocked:
            raise RuntimeError(f"Door {self.config.door_id} is not unlocked")
        
        if self.config.door_type == DoorType.OPEN:
            return block.copy(), is_frequency_domain
        
        untwisted = block * np.exp(-1j * self._phases)
        unbraided = untwisted[self._inv_perm]
        
        return unbraided, True
    
    def lock(self):
        """Lock the door, clearing cached keys."""
        self._perm = None
        self._phases = None
        self._inv_perm = None
        self._effective_key = None
        self._input_chain_key = None
        self._unlocked = False


class CascadingDoorSystem:
    """Complete cascading door encryption system."""
    
    def __init__(self, config: CascadeConfig):
        if not config.validate():
            raise ValueError("Invalid cascade configuration")
        
        self.config = config
        self.doors: List[CascadingDoor] = []
        self._lockbox_manager: Optional[CascadeLockboxManager] = None
        
        for door_config in config.doors:
            door = CascadingDoor(door_config, config.master_salt)
            self.doors.append(door)
    
    def setup_lockboxes(self, base_path: Path, master_key: DoorKey):
        """Setup the lockbox system for persistent key storage."""
        self._lockbox_manager = CascadeLockboxManager(
            base_path, master_key, self.config
        )
    
    def save_lockboxes(self):
        """Save all lockboxes to disk."""
        if self._lockbox_manager:
            self._lockbox_manager.save_all()
    
    def load_lockboxes(self) -> bool:
        """Load all lockboxes from disk."""
        if self._lockbox_manager:
            return self._lockbox_manager.load_all()
        return False
    
    def unlock_cascade(self, initial_key: Optional[DoorKey] = None,
                       external_keys: Optional[Dict[str, List[DoorKey]]] = None) -> bool:
        """Unlock all doors in the cascade."""
        external_keys = external_keys or {}
        chain_key = initial_key
        
        for door in self.doors:
            door_ext_keys = external_keys.get(door.config.door_id, [])
            
            if door.config.door_type in (DoorType.SEQUENTIAL, DoorType.COMPOUND):
                if chain_key is None:
                    self.lock_cascade()
                    return False
            
            if not door.unlock(chain_key, door_ext_keys):
                self.lock_cascade()
                return False
            
            chain_key = door.get_output_key()
        
        return True
    
    def lock_cascade(self):
        """Lock all doors in the cascade."""
        for door in self.doors:
            door.lock()
    
    def encrypt(self, data: bytes) -> BraidResult:
        """Encrypt data through all doors in the cascade."""
        start = time.perf_counter()
        
        for door in self.doors:
            if not door.is_unlocked:
                raise RuntimeError(f"Door {door.config.door_id} is not unlocked")
        
        original_len = len(data)
        block_size = self.config.doors[0].block_size
        
        data_array = np.frombuffer(data, dtype=np.uint8).astype(np.float64)
        data_array = (data_array / 127.5) - 1.0
        
        pad_len = (block_size - len(data_array) % block_size) % block_size
        if pad_len > 0:
            data_array = np.pad(data_array, (0, pad_len), mode='constant')
        
        num_blocks = len(data_array) // block_size
        
        encrypted_blocks = []
        for i in range(num_blocks):
            block = data_array[i * block_size:(i + 1) * block_size]
            current = block
            is_freq = False
            
            for door in self.doors:
                current, is_freq = door.encrypt_block(current, is_freq)
            
            encrypted_blocks.append(current)
        
        encrypted_array = np.array(encrypted_blocks).flatten()
        
        elapsed = (time.perf_counter() - start) * 1000
        
        real_part = np.real(encrypted_array)
        imag_part = np.imag(encrypted_array)
        combined = np.stack([real_part, imag_part], axis=-1).flatten()
        entropy = self._calculate_entropy(combined.view(np.uint8).tobytes())
        
        return BraidResult(
            encrypted_data=encrypted_array,
            metadata={
                'original_len': original_len,
                'pad_len': pad_len,
                'num_blocks': num_blocks,
                'block_size': block_size,
                'cascade_id': self.config.cascade_id,
                'is_frequency_domain': True
            },
            door_chain=[d.config.door_id for d in self.doors],
            encryption_time_ms=elapsed,
            entropy_achieved=entropy
        )
    
    def decrypt(self, result: BraidResult) -> bytes:
        """Decrypt data by reversing through all doors."""
        for door in self.doors:
            if not door.is_unlocked:
                raise RuntimeError(f"Door {door.config.door_id} is not unlocked")
        
        encrypted_array = result.encrypted_data
        num_blocks = result.metadata['num_blocks']
        block_size = result.metadata['block_size']
        original_len = result.metadata['original_len']
        pad_len = result.metadata['pad_len']
        
        decrypted_blocks = []
        
        for i in range(num_blocks):
            block = encrypted_array[i * block_size:(i + 1) * block_size]
            current = block
            is_freq = True
            
            for door in reversed(self.doors):
                current, is_freq = door.decrypt_block(current, is_freq)
            
            if is_freq:
                current = np.fft.ifft(current)
            
            decrypted_blocks.append(np.real(current))
        
        flat = np.array(decrypted_blocks).flatten()
        
        if pad_len > 0:
            flat = flat[:-pad_len]
        
        flat = np.clip(flat, -1.0, 1.0)
        byte_array = ((flat + 1.0) * 127.5)
        byte_array = np.round(byte_array).astype(np.uint8)
        
        return byte_array[:original_len].tobytes()
    
    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probs = counts / len(data)
        probs = probs[probs > 0]
        return float(-np.sum(probs * np.log2(probs)))


# =============================================================================
# SECTION 5: PORTABLE CASTLE FILE SYSTEM
# =============================================================================

class CastleFile:
    """
    Portable .castle file format for exporting/importing encrypted vaults.
    """
    
    MAGIC = b'CASTLE02'
    VERSION = 2
    BLOCK_SIZE = 64
    
    def __init__(self, required_keys: int = 1):
        self.required_keys = max(1, required_keys)
        self.cascade_config: Optional[CascadeConfig] = None
        self.encrypted_items: Dict[str, BraidResult] = {}
        self.rooms: Dict[str, RoomItem] = {}  # Hierarchical room structure
        self.notes: Dict[str, BraidResult] = {}  # Encrypted notes
        self.lockbox_data: Dict[str, Dict[str, Any]] = {}
        self.metadata: Dict[str, Any] = {
            'created_at': time.time(),
            'version': __version__,
            'required_keys': self.required_keys
        }
        self._nonce: bytes = secrets.token_bytes(16)
    
    def _combine_keys(self, keys: List[DoorKey]) -> DoorKey:
        """Combine multiple keys into a single master key."""
        if not keys:
            raise ValueError("At least one key is required")
        
        if len(keys) < self.required_keys:
            raise ValueError(f"Need {self.required_keys} keys, got {len(keys)}")
        
        final_material = b''
        for i, key in enumerate(keys[:self.required_keys]):
            position_hash = hashlib.blake2b(
                key.key_material + i.to_bytes(4, 'big') + b"castle_key",
                digest_size=32
            ).digest()
            final_material += position_hash
        
        master_material = hashlib.blake2b(
            final_material,
            digest_size=64
        ).digest()
        
        return DoorKey(
            key_id="castle_master",
            key_material=master_material,
            metadata={'combined_from': self.required_keys}
        )
    
    def _derive_encryption_key(self, master_key: DoorKey) -> bytes:
        """Derive encryption key from master key."""
        return hashlib.blake2b(
            master_key.key_material + b"castle_encryption" + self._nonce,
            digest_size=32
        ).digest()
    
    def _generate_keystream(self, key: bytes, length: int) -> bytes:
        """Generate keystream for encryption."""
        keystream = b''
        counter = 0
        
        while len(keystream) < length:
            block = hashlib.blake2b(
                key + self._nonce + counter.to_bytes(8, 'big'),
                digest_size=self.BLOCK_SIZE
            ).digest()
            keystream += block
            counter += 1
        
        return keystream[:length]
    
    def _encrypt_data(self, data: bytes, master_key: DoorKey) -> bytes:
        """Encrypt data with the master key."""
        if len(data) == 0:
            return b''
        key = self._derive_encryption_key(master_key)
        keystream = self._generate_keystream(key, len(data))
        return bytes(a ^ b for a, b in zip(data, keystream))
    
    def _decrypt_data(self, data: bytes, master_key: DoorKey) -> bytes:
        """Decrypt data with the master key."""
        return self._encrypt_data(data, master_key)
    
    def set_cascade_config(self, config: CascadeConfig):
        """Set the cascade configuration."""
        self.cascade_config = config
    
    def add_encrypted_item(self, name: str, result: BraidResult):
        """Add an encrypted item to the castle."""
        self.encrypted_items[name] = result
    
    def add_room(self, path: str, room: RoomItem):
        """Add a room to the castle hierarchy."""
        parts = path.strip('/').split('/')
        current = self.rooms
        
        for i, part in enumerate(parts[:-1]):
            if part not in current:
                current[part] = RoomItem(name=part, item_type='directory')
            current = current[part].children
        
        current[parts[-1]] = room
    
    def get_room(self, path: str) -> Optional[RoomItem]:
        """Get a room by path."""
        if not path or path == '/':
            return None
        
        parts = path.strip('/').split('/')
        current = self.rooms
        
        for part in parts:
            if part not in current:
                return None
            item = current[part]
            if part == parts[-1]:
                return item
            current = item.children
        
        return None
    
    def add_note(self, name: str, result: BraidResult):
        """Add an encrypted note."""
        self.notes[name] = result
    
    def add_lockbox_data(self, door_id: str, lockbox: Lockbox):
        """Add lockbox data to the castle."""
        self.lockbox_data[door_id] = lockbox.to_dict()
    
    def export_to_file(self, filepath: Path, keys: List[DoorKey]) -> bool:
        """Export the castle to a .castle file."""
        if len(keys) < self.required_keys:
            raise ValueError(f"Need at least {self.required_keys} keys to export")
        
        master_key = self._combine_keys(keys)
        
        payload = {
            'cascade_config': self.cascade_config.to_dict() if self.cascade_config else None,
            'encrypted_items': {
                name: result.to_dict() 
                for name, result in self.encrypted_items.items()
            },
            'rooms': {k: v.to_dict() for k, v in self.rooms.items()},
            'notes': {name: result.to_dict() for name, result in self.notes.items()},
            'lockbox_data': self.lockbox_data,
            'metadata': self.metadata
        }
        
        payload_json = json.dumps(payload).encode('utf-8')
        compressed = gzip.compress(payload_json)
        encrypted = self._encrypt_data(compressed, master_key)
        
        hmac_key = hashlib.blake2b(
            master_key.key_material + b"castle_hmac",
            digest_size=32
        ).digest()
        hmac_value = hashlib.blake2b(
            compressed,
            key=hmac_key,
            digest_size=32
        ).digest()
        
        filepath = Path(filepath)
        if not filepath.suffix:
            filepath = filepath.with_suffix('.castle')
        
        with open(filepath, 'wb') as f:
            f.write(self.MAGIC)
            f.write(struct.pack('<B', self.VERSION))
            f.write(struct.pack('<B', self.required_keys))
            f.write(self._nonce)
            f.write(hmac_value)
            f.write(struct.pack('<Q', len(encrypted)))
            f.write(encrypted)
        
        return True
    
    @classmethod
    def import_from_file(cls, filepath: Path, keys: List[DoorKey]) -> 'CastleFile':
        """Import a castle from a .castle file."""
        filepath = Path(filepath)
        
        with open(filepath, 'rb') as f:
            magic = f.read(8)
            # Handle both v1 and v2 magic
            if magic != cls.MAGIC and magic != b'CASTLE01':
                raise ValueError("Invalid castle file format")
            
            version = struct.unpack('<B', f.read(1))[0]
            required_keys = struct.unpack('<B', f.read(1))[0]
            nonce = f.read(16)
            stored_hmac = f.read(32)
            payload_len = struct.unpack('<Q', f.read(8))[0]
            encrypted = f.read(payload_len)
        
        castle = cls(required_keys=required_keys)
        castle._nonce = nonce
        
        if len(keys) < required_keys:
            raise ValueError(f"Need {required_keys} keys to open this castle, got {len(keys)}")
        
        master_key = castle._combine_keys(keys)
        compressed = castle._decrypt_data(encrypted, master_key)
        
        hmac_key = hashlib.blake2b(
            master_key.key_material + b"castle_hmac",
            digest_size=32
        ).digest()
        computed_hmac = hashlib.blake2b(
            compressed,
            key=hmac_key,
            digest_size=32
        ).digest()
        
        if computed_hmac != stored_hmac:
            raise ValueError("Invalid keys or corrupted castle file")
        
        payload_json = gzip.decompress(compressed)
        payload = json.loads(payload_json.decode('utf-8'))
        
        if payload.get('cascade_config'):
            castle.cascade_config = CascadeConfig.from_dict(payload['cascade_config'])
        
        castle.encrypted_items = {
            name: BraidResult.from_dict(data)
            for name, data in payload.get('encrypted_items', {}).items()
        }
        
        castle.rooms = {
            k: RoomItem.from_dict(v) 
            for k, v in payload.get('rooms', {}).items()
        }
        
        castle.notes = {
            name: BraidResult.from_dict(data)
            for name, data in payload.get('notes', {}).items()
        }
        
        castle.lockbox_data = payload.get('lockbox_data', {})
        castle.metadata = payload.get('metadata', {})
        
        return castle
    
    def get_item_names(self) -> List[str]:
        """Get list of encrypted item names."""
        return list(self.encrypted_items.keys())
    
    def get_item(self, name: str) -> Optional[BraidResult]:
        """Get an encrypted item by name."""
        return self.encrypted_items.get(name)
    
    def get_note_names(self) -> List[str]:
        """Get list of note names."""
        return list(self.notes.keys())
    
    def get_note(self, name: str) -> Optional[BraidResult]:
        """Get a note by name."""
        return self.notes.get(name)


# =============================================================================
# SECTION 6: DIRECTORY IMPORT SYSTEM
# =============================================================================

class DirectoryImporter:
    """
    Imports directories into castle rooms with recursive encryption.
    
    Supports:
    - Passthrough mode: Use parent directory key for all descendants
    - Fine-grained mode: Prompt for each subdirectory
    """
    
    def __init__(self, cascade: CascadingDoorSystem, castle: CastleFile,
                 input_callback: Callable[[str], str] = input,
                 password_callback: Callable[[str], str] = getpass.getpass):
        self.cascade = cascade
        self.castle = castle
        self.input_callback = input_callback
        self.password_callback = password_callback
        self.stats = {
            'files_imported': 0,
            'dirs_imported': 0,
            'bytes_processed': 0,
            'errors': []
        }
    
    def import_directory(self, source_path: Path, room_name: str,
                        mode: ImportMode = ImportMode.PASSTHROUGH,
                        parent_key: Optional[DoorKey] = None) -> RoomItem:
        """
        Import a directory as a castle room.
        
        Args:
            source_path: Path to the directory to import
            room_name: Name for the room in the castle
            mode: ImportMode.PASSTHROUGH or ImportMode.FINE_GRAINED
            parent_key: Optional key from parent directory
        
        Returns:
            RoomItem representing the imported directory
        """
        source_path = Path(source_path)
        if not source_path.is_dir():
            raise ValueError(f"Not a directory: {source_path}")
        
        room = RoomItem(
            name=room_name,
            item_type='directory',
            metadata={
                'source_path': str(source_path),
                'imported_at': time.time(),
                'import_mode': mode.value
            }
        )
        
        # Get or derive key for this room
        if mode == ImportMode.FINE_GRAINED and parent_key is None:
            print(f"\n  Entering room: {room_name}")
            password = self.password_callback(f"    Password for '{room_name}' (or Enter for passthrough): ")
            if password:
                room_key = DoorKey.from_password(password, f"room_{room_name}")
            else:
                room_key = None
        elif parent_key:
            room_key = parent_key.derive_next(room_name, self.cascade.config.master_salt)
        else:
            room_key = None
        
        # Process files in this directory
        for item in sorted(source_path.iterdir()):
            try:
                if item.is_file():
                    file_item = self._import_file(item, room_key)
                    room.children[item.name] = file_item
                    self.stats['files_imported'] += 1
                    
                elif item.is_dir():
                    # Determine mode for subdirectory
                    if mode == ImportMode.FINE_GRAINED:
                        print(f"\n  Found subdirectory: {item.name}")
                        choice = self.input_callback("    [P]assthrough / [S]eparate key / [K]eep fine-grained? [P/S/K]: ").strip().upper()
                        
                        if choice == 'S':
                            sub_password = self.password_callback(f"    Password for '{item.name}': ")
                            sub_key = DoorKey.from_password(sub_password, f"room_{item.name}")
                            sub_mode = ImportMode.PASSTHROUGH
                        elif choice == 'K':
                            sub_key = room_key
                            sub_mode = ImportMode.FINE_GRAINED
                        else:  # P or default
                            sub_key = room_key
                            sub_mode = ImportMode.PASSTHROUGH
                    else:
                        sub_key = room_key
                        sub_mode = ImportMode.PASSTHROUGH
                    
                    sub_room = self.import_directory(item, item.name, sub_mode, sub_key)
                    room.children[item.name] = sub_room
                    self.stats['dirs_imported'] += 1
                    
            except Exception as e:
                self.stats['errors'].append(f"{item}: {e}")
        
        return room
    
    def _import_file(self, filepath: Path, room_key: Optional[DoorKey]) -> RoomItem:
        """Import a single file."""
        with open(filepath, 'rb') as f:
            data = f.read()
        
        self.stats['bytes_processed'] += len(data)
        
        # Encrypt the file
        result = self.cascade.encrypt(data)
        
        return RoomItem(
            name=filepath.name,
            item_type='file',
            encrypted_result=result,
            metadata={
                'original_size': len(data),
                'original_name': filepath.name,
                'imported_at': time.time()
            }
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get import statistics."""
        return self.stats.copy()


class DirectoryExporter:
    """
    Exports castle rooms and files to local directories.
    """
    
    def __init__(self, cascade: CascadingDoorSystem, castle: CastleFile):
        self.cascade = cascade
        self.castle = castle
        self.stats = {
            'files_exported': 0,
            'dirs_created': 0,
            'bytes_written': 0,
            'errors': []
        }
    
    def export_room(self, room_path: str, dest_path: Path, recursive: bool = True) -> bool:
        """
        Export a room and its contents to a local directory.
        
        Args:
            room_path: Path to the room in the castle (e.g., "documents/work")
            dest_path: Local filesystem destination
            recursive: Whether to export subdirectories
        
        Returns:
            True if successful
        """
        dest_path = Path(dest_path)
        
        room = self.castle.get_room(room_path)
        if room is None:
            # Try root-level items
            parts = room_path.strip('/').split('/')
            if parts[0] in self.castle.rooms:
                room = self.castle.rooms[parts[0]]
                for part in parts[1:]:
                    if part in room.children:
                        room = room.children[part]
                    else:
                        return False
            else:
                return False
        
        return self._export_room_item(room, dest_path, recursive)
    
    def _export_room_item(self, room: RoomItem, dest_path: Path, recursive: bool) -> bool:
        """Export a room item recursively."""
        try:
            if room.item_type == 'file':
                # Decrypt and write file
                if room.encrypted_result:
                    data = self.cascade.decrypt(room.encrypted_result)
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(dest_path, 'wb') as f:
                        f.write(data)
                    self.stats['files_exported'] += 1
                    self.stats['bytes_written'] += len(data)
                return True
            
            elif room.item_type == 'directory':
                dest_path.mkdir(parents=True, exist_ok=True)
                self.stats['dirs_created'] += 1
                
                if recursive:
                    for child_name, child in room.children.items():
                        child_dest = dest_path / child_name
                        self._export_room_item(child, child_dest, recursive)
                
                return True
            
        except Exception as e:
            self.stats['errors'].append(f"{dest_path}: {e}")
            return False
        
        return True
    
    def export_file(self, item_name: str, dest_path: Path) -> bool:
        """Export a single encrypted item to a file."""
        result = self.castle.get_item(item_name)
        if result is None:
            return False
        
        try:
            data = self.cascade.decrypt(result)
            dest_path = Path(dest_path)
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(dest_path, 'wb') as f:
                f.write(data)
            
            self.stats['files_exported'] += 1
            self.stats['bytes_written'] += len(data)
            return True
            
        except Exception as e:
            self.stats['errors'].append(f"{item_name}: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get export statistics."""
        return self.stats.copy()


# =============================================================================
# SECTION 7: NOTES SYSTEM
# =============================================================================

class NotesManager:
    """
    Encrypted notes management system.
    
    Features:
    - Create, read, update, delete encrypted notes
    - Note listing with titles/previews
    - Search within decrypted notes
    """
    
    def __init__(self, cascade: CascadingDoorSystem, castle: CastleFile):
        self.cascade = cascade
        self.castle = castle
    
    def create_note(self, title: str, content: str) -> bool:
        """Create a new encrypted note."""
        if not self._is_unlocked():
            return False
        
        note_data = {
            'title': title,
            'content': content,
            'created_at': time.time(),
            'modified_at': time.time()
        }
        
        json_data = json.dumps(note_data).encode('utf-8')
        result = self.cascade.encrypt(json_data)
        
        self.castle.add_note(title, result)
        return True
    
    def read_note(self, title: str) -> Optional[Dict[str, Any]]:
        """Read and decrypt a note."""
        if not self._is_unlocked():
            return None
        
        result = self.castle.get_note(title)
        if result is None:
            return None
        
        try:
            json_data = self.cascade.decrypt(result)
            return json.loads(json_data.decode('utf-8'))
        except Exception:
            return None
    
    def update_note(self, title: str, new_content: str) -> bool:
        """Update an existing note."""
        if not self._is_unlocked():
            return False
        
        existing = self.read_note(title)
        if existing is None:
            return False
        
        existing['content'] = new_content
        existing['modified_at'] = time.time()
        
        json_data = json.dumps(existing).encode('utf-8')
        result = self.cascade.encrypt(json_data)
        
        self.castle.notes[title] = result
        return True
    
    def delete_note(self, title: str) -> bool:
        """Delete a note."""
        if title in self.castle.notes:
            del self.castle.notes[title]
            return True
        return False
    
    def list_notes(self) -> List[Dict[str, Any]]:
        """List all notes with metadata."""
        if not self._is_unlocked():
            return []
        
        notes_list = []
        for title in self.castle.get_note_names():
            note_data = self.read_note(title)
            if note_data:
                notes_list.append({
                    'title': note_data.get('title', title),
                    'preview': note_data.get('content', '')[:100] + '...' if len(note_data.get('content', '')) > 100 else note_data.get('content', ''),
                    'created_at': note_data.get('created_at', 0),
                    'modified_at': note_data.get('modified_at', 0)
                })
        
        return sorted(notes_list, key=lambda x: x['modified_at'], reverse=True)
    
    def search_notes(self, query: str) -> List[Dict[str, Any]]:
        """Search notes for a query string."""
        if not self._is_unlocked():
            return []
        
        results = []
        query_lower = query.lower()
        
        for title in self.castle.get_note_names():
            note_data = self.read_note(title)
            if note_data:
                content = note_data.get('content', '').lower()
                note_title = note_data.get('title', '').lower()
                
                if query_lower in content or query_lower in note_title:
                    results.append({
                        'title': note_data.get('title', title),
                        'content': note_data.get('content', ''),
                        'created_at': note_data.get('created_at', 0),
                        'modified_at': note_data.get('modified_at', 0)
                    })
        
        return results
    
    def _is_unlocked(self) -> bool:
        """Check if cascade is unlocked."""
        return self.cascade and all(d.is_unlocked for d in self.cascade.doors)


# =============================================================================
# SECTION 8: RECOMMENDED CASCADE COMBINATIONS
# =============================================================================

def create_rc1_cascade(password: str, salt: Optional[bytes] = None) -> CascadingDoorSystem:
    """RC1: Gemini Depth-Based + Fractal Permutation"""
    salt = salt or secrets.token_bytes(32)
    
    config = CascadeConfig(
        cascade_id="RC1_Gemini_Fractal",
        doors=[
            DoorConfig(
                door_id="entrance",
                door_type=DoorType.OPEN,
                key_derivation=KeyDerivationMethod.DEPTH_BASED,
                permutation_method=PermutationMethod.FRACTAL_MODULATED,
                fractal_type=FractalType.JULIA,
                block_size=512,
                depth=0
            ),
            DoorConfig(
                door_id="inner_gate",
                door_type=DoorType.SEQUENTIAL,
                key_derivation=KeyDerivationMethod.DEPTH_BASED,
                permutation_method=PermutationMethod.FRACTAL_MODULATED,
                fractal_type=FractalType.JULIA,
                block_size=512,
                depth=1
            ),
            DoorConfig(
                door_id="vault",
                door_type=DoorType.COMPOUND,
                required_external_keys=1,
                key_derivation=KeyDerivationMethod.DEPTH_BASED,
                permutation_method=PermutationMethod.FRACTAL_MODULATED,
                fractal_type=FractalType.LORENZ,
                block_size=512,
                depth=2
            )
        ],
        master_salt=salt
    )
    
    return CascadingDoorSystem(config)


def create_rc2_cascade(password: str, salt: Optional[bytes] = None) -> CascadingDoorSystem:
    """RC2: SHA256 Direct + Fractal Permutation"""
    salt = salt or secrets.token_bytes(32)
    
    config = CascadeConfig(
        cascade_id="RC2_SHA256_Fractal",
        doors=[
            DoorConfig(
                door_id="primary",
                door_type=DoorType.OPEN,
                key_derivation=KeyDerivationMethod.SHA256_DIRECT,
                permutation_method=PermutationMethod.FRACTAL_MODULATED,
                fractal_type=FractalType.JULIA,
                block_size=512,
                depth=0
            ),
            DoorConfig(
                door_id="secondary",
                door_type=DoorType.SEQUENTIAL,
                key_derivation=KeyDerivationMethod.SHA256_DIRECT,
                permutation_method=PermutationMethod.FRACTAL_MODULATED,
                fractal_type=FractalType.HENON,
                block_size=512,
                depth=1
            ),
            DoorConfig(
                door_id="external_lock",
                door_type=DoorType.EXTERNAL,
                required_external_keys=2,
                key_derivation=KeyDerivationMethod.SHA256_DIRECT,
                permutation_method=PermutationMethod.PASSWORD_SEEDED,
                block_size=512,
                depth=2
            )
        ],
        master_salt=salt
    )
    
    return CascadingDoorSystem(config)


def create_rc3_cascade(password: str, salt: Optional[bytes] = None) -> CascadingDoorSystem:
    """RC3: Blake2b Fractal + Password-Seeded Permutation"""
    salt = salt or secrets.token_bytes(32)
    
    config = CascadeConfig(
        cascade_id="RC3_Blake2b_Mixed",
        doors=[
            DoorConfig(
                door_id="gate_1",
                door_type=DoorType.OPEN,
                key_derivation=KeyDerivationMethod.BLAKE2B_FRACTAL,
                permutation_method=PermutationMethod.PASSWORD_SEEDED,
                fractal_type=FractalType.LOGISTIC_MAP,
                block_size=512,
                depth=0
            ),
            DoorConfig(
                door_id="gate_2",
                door_type=DoorType.SEQUENTIAL,
                key_derivation=KeyDerivationMethod.BLAKE2B_FRACTAL,
                permutation_method=PermutationMethod.PASSWORD_SEEDED,
                fractal_type=FractalType.JULIA,
                block_size=512,
                depth=1
            ),
            DoorConfig(
                door_id="gate_3",
                door_type=DoorType.COMPOUND,
                required_external_keys=1,
                key_derivation=KeyDerivationMethod.BLAKE2B_FRACTAL,
                permutation_method=PermutationMethod.FRACTAL_MODULATED,
                fractal_type=FractalType.LORENZ,
                block_size=512,
                depth=2
            ),
            DoorConfig(
                door_id="gate_4",
                door_type=DoorType.SEQUENTIAL,
                key_derivation=KeyDerivationMethod.BLAKE2B_FRACTAL,
                permutation_method=PermutationMethod.PASSWORD_SEEDED,
                fractal_type=FractalType.HENON,
                block_size=512,
                depth=3
            )
        ],
        master_salt=salt
    )
    
    return CascadingDoorSystem(config)


def create_simple_cascade(num_doors: int = 2, salt: Optional[bytes] = None) -> CascadingDoorSystem:
    """Create a simple cascade with specified number of doors."""
    salt = salt or secrets.token_bytes(32)
    
    doors = [
        DoorConfig(
            door_id="door_0",
            door_type=DoorType.OPEN,
            key_derivation=KeyDerivationMethod.BLAKE2B_FRACTAL,
            fractal_type=FractalType.JULIA,
            block_size=512,
            depth=0
        )
    ]
    
    for i in range(1, num_doors):
        doors.append(
            DoorConfig(
                door_id=f"door_{i}",
                door_type=DoorType.SEQUENTIAL,
                key_derivation=KeyDerivationMethod.BLAKE2B_FRACTAL,
                fractal_type=FractalType.JULIA,
                block_size=512,
                depth=i
            )
        )
    
    config = CascadeConfig(
        cascade_id=f"Simple_{num_doors}_Door",
        doors=doors,
        master_salt=salt
    )
    
    return CascadingDoorSystem(config)


# =============================================================================
# SECTION 9: INTERACTIVE CLI MENU SYSTEM
# =============================================================================

class CastleCLI:
    """Interactive CLI for CASTLEfs."""
    
    def __init__(self):
        self.current_castle: Optional[CastleFile] = None
        self.current_cascade: Optional[CascadingDoorSystem] = None
        self.current_keys: List[DoorKey] = []
        self.external_keys: Dict[str, List[DoorKey]] = {}
        self.notes_manager: Optional[NotesManager] = None
        self.running = True
    
    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self):
        """Print the application header."""
        print("╔══════════════════════════════════════════════════════════════════════╗")
        print("║            CASTLEfs - Cascading Door Filesystem Encryption          ║")
        print("║            Copyright (c) Brian Richard RAMOS - Apache 2.0           ║")
        print("╚══════════════════════════════════════════════════════════════════════╝")
        print()
    
    def print_status(self):
        """Print current status."""
        print("─" * 70)
        castle_status = "Loaded" if self.current_castle else "None"
        cascade_status = "Configured" if self.current_cascade else "None"
        keys_status = f"{len(self.current_keys)} key(s)"
        unlocked = "Yes" if (self.current_cascade and 
                            all(d.is_unlocked for d in self.current_cascade.doors)) else "No"
        items = len(self.current_castle.encrypted_items) if self.current_castle else 0
        notes = len(self.current_castle.notes) if self.current_castle else 0
        rooms = len(self.current_castle.rooms) if self.current_castle else 0
        
        print(f"  Castle: {castle_status} | Cascade: {cascade_status} | "
              f"Keys: {keys_status} | Unlocked: {unlocked}")
        print(f"  Items: {items} | Notes: {notes} | Rooms: {rooms}")
        print("─" * 70)
        print()
    
    def get_input(self, prompt: str, password: bool = False) -> str:
        """Get user input, optionally hiding it."""
        try:
            if password:
                return getpass.getpass(prompt)
            return input(prompt)
        except (EOFError, KeyboardInterrupt):
            print()
            return ""
    
    def get_int_input(self, prompt: str, min_val: int = 0, max_val: int = 100) -> Optional[int]:
        """Get integer input with validation."""
        try:
            value = int(self.get_input(prompt))
            if min_val <= value <= max_val:
                return value
            print(f"  Please enter a number between {min_val} and {max_val}")
            return None
        except ValueError:
            print("  Invalid number")
            return None
    
    def pause(self):
        """Pause for user acknowledgment."""
        self.get_input("\n  Press Enter to continue...")
    
    def main_menu(self):
        """Display the main menu."""
        self.clear_screen()
        self.print_header()
        self.print_status()
        
        print("  MAIN MENU")
        print("  ─────────")
        print()
        print("   1. Create New Castle")
        print("   2. Open Existing Castle")
        print("   3. Key Management")
        print("   4. Encrypt Data")
        print("   5. Decrypt Data")
        print("   6. Import Directory to Room")
        print("   7. Export Room/File to Directory")
        print("   8. Notes Reader")
        print("   9. Export Castle to File")
        print("  10. Import Castle from File")
        print("  11. View Castle Contents")
        print("  12. Run Test Suite")
        print("   0. Exit")
        print()
        
        choice = self.get_input("  Enter choice: ").strip()
        
        actions = {
            '1': self.create_castle_menu,
            '2': self.open_castle_menu,
            '3': self.key_management_menu,
            '4': self.encrypt_menu,
            '5': self.decrypt_menu,
            '6': self.import_directory_menu,
            '7': self.export_menu,
            '8': self.notes_menu,
            '9': self.export_castle_menu,
            '10': self.import_castle_menu,
            '11': self.view_castle_menu,
            '12': self.run_tests,
            '0': self.exit_app
        }
        
        if choice in actions:
            actions[choice]()
    
    def create_castle_menu(self):
        """Menu for creating a new castle."""
        self.clear_screen()
        self.print_header()
        
        print("  CREATE NEW CASTLE")
        print("  ─────────────────")
        print()
        print("  Select cascade type:")
        print()
        print("  1. RC1 - Gemini Depth-Based (3 doors)")
        print("  2. RC2 - SHA256 Fractal (3 doors)")
        print("  3. RC3 - Blake2b Mixed (4 doors)")
        print("  4. Simple Custom (N doors)")
        print("  0. Back to Main Menu")
        print()
        
        choice = self.get_input("  Enter choice: ").strip()
        
        if choice == '0':
            return
        
        print()
        num_keys = self.get_int_input("  Number of keys required to protect castle (1-10): ", 1, 10)
        if num_keys is None:
            self.pause()
            return
        
        print()
        print(f"  Enter {num_keys} password(s) to protect this castle:")
        keys = []
        for i in range(num_keys):
            password = self.get_input(f"    Key {i+1}: ", password=True)
            if not password:
                print("  Empty password not allowed")
                self.pause()
                return
            keys.append(DoorKey.from_password(password, f"castle_key_{i}"))
        
        self.current_keys = keys
        salt = secrets.token_bytes(32)
        
        try:
            if choice == '1':
                self.current_cascade = create_rc1_cascade("", salt)
            elif choice == '2':
                self.current_cascade = create_rc2_cascade("", salt)
            elif choice == '3':
                self.current_cascade = create_rc3_cascade("", salt)
            elif choice == '4':
                num_doors = self.get_int_input("  Number of doors (2-10): ", 2, 10)
                if num_doors is None:
                    return
                self.current_cascade = create_simple_cascade(num_doors, salt)
            else:
                print("  Invalid choice")
                self.pause()
                return
            
            self.current_castle = CastleFile(required_keys=num_keys)
            self.current_castle.set_cascade_config(self.current_cascade.config)
            
            self._collect_external_keys()
            
            master_key = self.current_keys[0] if self.current_keys else None
            if self.current_cascade.unlock_cascade(master_key, self.external_keys):
                self.notes_manager = NotesManager(self.current_cascade, self.current_castle)
                print()
                print("  ✓ Castle created successfully!")
                print(f"  ✓ Cascade unlocked with {len(self.current_cascade.doors)} doors")
            else:
                print("  ✗ Failed to unlock cascade")
            
        except Exception as e:
            print(f"  Error: {e}")
        
        self.pause()
    
    def _collect_external_keys(self):
        """Collect external keys for doors that require them."""
        if not self.current_cascade:
            return
        
        self.external_keys = {}
        
        for door in self.current_cascade.doors:
            if door.config.required_external_keys > 0:
                print()
                print(f"  Door '{door.config.door_id}' requires {door.config.required_external_keys} external key(s)")
                ext_keys = []
                for i in range(door.config.required_external_keys):
                    password = self.get_input(f"    External key {i+1}: ", password=True)
                    if password:
                        ext_keys.append(DoorKey.from_password(password, f"ext_{door.config.door_id}_{i}"))
                if ext_keys:
                    self.external_keys[door.config.door_id] = ext_keys
    
    def open_castle_menu(self):
        """Menu for opening/unlocking current castle."""
        self.clear_screen()
        self.print_header()
        
        print("  OPEN CASTLE")
        print("  ───────────")
        print()
        
        if not self.current_castle:
            print("  No castle loaded. Create or import one first.")
            self.pause()
            return
        
        if not self.current_cascade:
            if self.current_castle.cascade_config:
                self.current_cascade = CascadingDoorSystem(self.current_castle.cascade_config)
            else:
                print("  No cascade configuration in castle.")
                self.pause()
                return
        
        required = self.current_castle.required_keys
        print(f"  This castle requires {required} key(s) to open.")
        print()
        
        keys = []
        for i in range(required):
            password = self.get_input(f"  Enter key {i+1}: ", password=True)
            if not password:
                print("  Opening cancelled.")
                self.pause()
                return
            keys.append(DoorKey.from_password(password, f"open_key_{i}"))
        
        self.current_keys = keys
        self._collect_external_keys()
        
        master_key = keys[0] if keys else None
        if self.current_cascade.unlock_cascade(master_key, self.external_keys):
            self.notes_manager = NotesManager(self.current_cascade, self.current_castle)
            print()
            print("  ✓ Castle opened successfully!")
        else:
            print()
            print("  ✗ Failed to open castle. Check your keys.")
        
        self.pause()
    
    def key_management_menu(self):
        """Menu for managing keys."""
        self.clear_screen()
        self.print_header()
        
        print("  KEY MANAGEMENT")
        print("  ──────────────")
        print()
        print("  1. Add Key from Password")
        print("  2. Generate Random Key")
        print("  3. Clear All Keys")
        print("  4. View Current Keys (IDs only)")
        print("  0. Back to Main Menu")
        print()
        
        choice = self.get_input("  Enter choice: ").strip()
        
        if choice == '1':
            password = self.get_input("  Enter password: ", password=True)
            if password:
                key = DoorKey.from_password(password, f"key_{len(self.current_keys)}")
                self.current_keys.append(key)
                print(f"  ✓ Added key: {key.key_id}")
        elif choice == '2':
            key = DoorKey(
                key_id=f"random_{len(self.current_keys)}",
                key_material=secrets.token_bytes(64)
            )
            self.current_keys.append(key)
            print(f"  ✓ Generated key: {key.key_id}")
        elif choice == '3':
            self.current_keys.clear()
            self.external_keys.clear()
            print("  ✓ All keys cleared")
        elif choice == '4':
            print()
            print("  Current keys:")
            for i, key in enumerate(self.current_keys):
                print(f"    {i+1}. {key.key_id}")
            if not self.current_keys:
                print("    (none)")
        elif choice == '0':
            return
        
        self.pause()
    
    def encrypt_menu(self):
        """Menu for encrypting data."""
        self.clear_screen()
        self.print_header()
        
        print("  ENCRYPT DATA")
        print("  ────────────")
        print()
        
        if not self._check_unlocked():
            return
        
        print("  1. Encrypt Text")
        print("  2. Encrypt File")
        print("  0. Back")
        print()
        
        choice = self.get_input("  Enter choice: ").strip()
        
        if choice == '1':
            print()
            text = self.get_input("  Enter text to encrypt: ")
            if not text:
                return
            
            name = self.get_input("  Name for this item: ").strip() or "unnamed"
            
            try:
                result = self.current_cascade.encrypt(text.encode('utf-8'))
                if self.current_castle:
                    self.current_castle.add_encrypted_item(name, result)
                
                print()
                print(f"  ✓ Encrypted successfully!")
                print(f"    Name: {name}")
                print(f"    Size: {len(result.encrypted_data)} coefficients")
                print(f"    Entropy: {result.entropy_achieved:.2f} bits")
                print(f"    Time: {result.encryption_time_ms:.2f} ms")
            except Exception as e:
                print(f"  ✗ Error: {e}")
        
        elif choice == '2':
            print()
            filepath = self.get_input("  Enter file path: ").strip()
            if not filepath or not Path(filepath).exists():
                print("  File not found.")
                self.pause()
                return
            
            name = self.get_input("  Name for this item: ").strip() or Path(filepath).name
            
            try:
                with open(filepath, 'rb') as f:
                    data = f.read()
                
                result = self.current_cascade.encrypt(data)
                if self.current_castle:
                    self.current_castle.add_encrypted_item(name, result)
                    self.current_castle.metadata[f'original_filename_{name}'] = Path(filepath).name
                
                print()
                print(f"  ✓ Encrypted successfully!")
                print(f"    Name: {name}")
                print(f"    Original size: {len(data)} bytes")
                print(f"    Entropy: {result.entropy_achieved:.2f} bits")
            except Exception as e:
                print(f"  ✗ Error: {e}")
        
        self.pause()
    
    def decrypt_menu(self):
        """Menu for decrypting data."""
        self.clear_screen()
        self.print_header()
        
        print("  DECRYPT DATA")
        print("  ────────────")
        print()
        
        if not self._check_unlocked():
            return
        
        if not self.current_castle or not self.current_castle.encrypted_items:
            print("  No encrypted items in castle.")
            self.pause()
            return
        
        print("  Available items:")
        items = list(self.current_castle.encrypted_items.keys())
        for i, name in enumerate(items, 1):
            print(f"    {i}. {name}")
        print("    0. Back")
        print()
        
        choice = self.get_int_input("  Select item: ", 0, len(items))
        if choice is None or choice == 0:
            return
        
        name = items[choice - 1]
        result = self.current_castle.encrypted_items[name]
        
        try:
            decrypted = self.current_cascade.decrypt(result)
            
            print()
            print(f"  ✓ Decrypted successfully!")
            print()
            print("  1. Display as text")
            print("  2. Save to file")
            print()
            
            action = self.get_input("  Choice: ").strip()
            
            if action == '1':
                try:
                    text = decrypted.decode('utf-8')
                    print()
                    print("  Content:")
                    print("  " + "─" * 50)
                    for line in text.split('\n'):
                        print(f"  {line}")
                    print("  " + "─" * 50)
                except:
                    print("  (Binary data, cannot display as text)")
            elif action == '2':
                orig_name = self.current_castle.metadata.get(f'original_filename_{name}', f'{name}.dat')
                filepath = self.get_input(f"  Save as [{orig_name}]: ").strip() or orig_name
                
                with open(filepath, 'wb') as f:
                    f.write(decrypted)
                print(f"  ✓ Saved to: {filepath}")
        
        except Exception as e:
            print(f"  ✗ Error: {e}")
        
        self.pause()
    
    def import_directory_menu(self):
        """Menu for importing a directory as a room."""
        self.clear_screen()
        self.print_header()
        
        print("  IMPORT DIRECTORY TO ROOM")
        print("  ─────────────────────────")
        print()
        
        if not self._check_unlocked():
            return
        
        source_path = self.get_input("  Source directory path: ").strip()
        if not source_path or not Path(source_path).is_dir():
            print("  Directory not found.")
            self.pause()
            return
        
        room_name = self.get_input(f"  Room name [{Path(source_path).name}]: ").strip()
        room_name = room_name or Path(source_path).name
        
        print()
        print("  Import mode:")
        print("    1. Passthrough - Use single key for entire tree")
        print("    2. Fine-grained - Prompt for each subdirectory")
        print()
        
        mode_choice = self.get_input("  Choice [1]: ").strip() or '1'
        mode = ImportMode.FINE_GRAINED if mode_choice == '2' else ImportMode.PASSTHROUGH
        
        try:
            importer = DirectoryImporter(
                self.current_cascade,
                self.current_castle,
                self.get_input,
                lambda p: self.get_input(p, password=True)
            )
            
            print()
            print("  Importing...")
            
            room = importer.import_directory(Path(source_path), room_name, mode)
            self.current_castle.rooms[room_name] = room
            
            stats = importer.get_stats()
            print()
            print("  ✓ Import complete!")
            print(f"    Files: {stats['files_imported']}")
            print(f"    Directories: {stats['dirs_imported']}")
            print(f"    Bytes processed: {stats['bytes_processed']:,}")
            
            if stats['errors']:
                print(f"    Errors: {len(stats['errors'])}")
                for err in stats['errors'][:5]:
                    print(f"      - {err}")
            
        except Exception as e:
            print(f"  ✗ Error: {e}")
        
        self.pause()
    
    def export_menu(self):
        """Menu for exporting rooms/files to local directory."""
        self.clear_screen()
        self.print_header()
        
        print("  EXPORT TO LOCAL DIRECTORY")
        print("  ──────────────────────────")
        print()
        
        if not self._check_unlocked():
            return
        
        print("  1. Export Room (with subdirectories)")
        print("  2. Export Single File")
        print("  0. Back")
        print()
        
        choice = self.get_input("  Enter choice: ").strip()
        
        if choice == '1':
            # List available rooms
            print()
            print("  Available rooms:")
            rooms = list(self.current_castle.rooms.keys())
            for i, name in enumerate(rooms, 1):
                room = self.current_castle.rooms[name]
                file_count = sum(1 for c in room.children.values() if c.item_type == 'file')
                dir_count = sum(1 for c in room.children.values() if c.item_type == 'directory')
                print(f"    {i}. {name} ({file_count} files, {dir_count} subdirs)")
            
            if not rooms:
                print("    (no rooms)")
                self.pause()
                return
            
            print("    0. Back")
            print()
            
            room_choice = self.get_int_input("  Select room: ", 0, len(rooms))
            if room_choice is None or room_choice == 0:
                return
            
            room_name = rooms[room_choice - 1]
            dest_path = self.get_input(f"  Export to [{room_name}]: ").strip() or room_name
            
            try:
                exporter = DirectoryExporter(self.current_cascade, self.current_castle)
                
                # Export the selected room
                room = self.current_castle.rooms[room_name]
                success = exporter._export_room_item(room, Path(dest_path), recursive=True)
                
                stats = exporter.get_stats()
                print()
                if success:
                    print("  ✓ Export complete!")
                    print(f"    Files: {stats['files_exported']}")
                    print(f"    Directories: {stats['dirs_created']}")
                    print(f"    Bytes written: {stats['bytes_written']:,}")
                else:
                    print("  ✗ Export failed")
                
                if stats['errors']:
                    print(f"    Errors: {len(stats['errors'])}")
                    for err in stats['errors'][:5]:
                        print(f"      - {err}")
                
            except Exception as e:
                print(f"  ✗ Error: {e}")
        
        elif choice == '2':
            # List available items
            print()
            print("  Available items:")
            items = list(self.current_castle.encrypted_items.keys())
            for i, name in enumerate(items, 1):
                result = self.current_castle.encrypted_items[name]
                size = result.metadata.get('original_len', '?')
                print(f"    {i}. {name} ({size} bytes)")
            
            if not items:
                print("    (no items)")
                self.pause()
                return
            
            print("    0. Back")
            print()
            
            item_choice = self.get_int_input("  Select item: ", 0, len(items))
            if item_choice is None or item_choice == 0:
                return
            
            item_name = items[item_choice - 1]
            orig_name = self.current_castle.metadata.get(f'original_filename_{item_name}', f'{item_name}.dat')
            dest_path = self.get_input(f"  Export to [{orig_name}]: ").strip() or orig_name
            
            try:
                exporter = DirectoryExporter(self.current_cascade, self.current_castle)
                success = exporter.export_file(item_name, Path(dest_path))
                
                if success:
                    stats = exporter.get_stats()
                    print()
                    print(f"  ✓ Exported to: {dest_path}")
                    print(f"    Bytes written: {stats['bytes_written']:,}")
                else:
                    print("  ✗ Export failed")
                
            except Exception as e:
                print(f"  ✗ Error: {e}")
        
        self.pause()
    
    def notes_menu(self):
        """Notes reader/writer menu."""
        while True:
            self.clear_screen()
            self.print_header()
            
            print("  NOTES READER")
            print("  ────────────")
            print()
            
            if not self._check_unlocked(pause=False):
                self.pause()
                return
            
            print("  1. List Notes")
            print("  2. Read Note")
            print("  3. Create Note")
            print("  4. Edit Note")
            print("  5. Delete Note")
            print("  6. Search Notes")
            print("  0. Back to Main Menu")
            print()
            
            choice = self.get_input("  Enter choice: ").strip()
            
            if choice == '0':
                return
            elif choice == '1':
                self._list_notes()
            elif choice == '2':
                self._read_note()
            elif choice == '3':
                self._create_note()
            elif choice == '4':
                self._edit_note()
            elif choice == '5':
                self._delete_note()
            elif choice == '6':
                self._search_notes()
    
    def _list_notes(self):
        """List all notes."""
        print()
        print("  Notes:")
        print("  " + "─" * 60)
        
        notes = self.notes_manager.list_notes()
        if not notes:
            print("    (no notes)")
        else:
            for i, note in enumerate(notes, 1):
                modified = time.strftime('%Y-%m-%d %H:%M', time.localtime(note['modified_at']))
                print(f"    {i}. {note['title']}")
                print(f"       Modified: {modified}")
                print(f"       Preview: {note['preview']}")
                print()
        
        self.pause()
    
    def _read_note(self):
        """Read a specific note."""
        notes = self.notes_manager.list_notes()
        if not notes:
            print("  No notes found.")
            self.pause()
            return
        
        print()
        print("  Available notes:")
        for i, note in enumerate(notes, 1):
            print(f"    {i}. {note['title']}")
        print()
        
        choice = self.get_int_input("  Select note: ", 1, len(notes))
        if choice is None:
            return
        
        title = notes[choice - 1]['title']
        note_data = self.notes_manager.read_note(title)
        
        if note_data:
            print()
            print(f"  Title: {note_data['title']}")
            print(f"  Created: {time.ctime(note_data['created_at'])}")
            print(f"  Modified: {time.ctime(note_data['modified_at'])}")
            print()
            print("  Content:")
            print("  " + "─" * 60)
            for line in note_data['content'].split('\n'):
                print(f"  {line}")
            print("  " + "─" * 60)
        else:
            print("  ✗ Failed to read note")
        
        self.pause()
    
    def _create_note(self):
        """Create a new note."""
        print()
        title = self.get_input("  Note title: ").strip()
        if not title:
            print("  Title is required.")
            self.pause()
            return
        
        print("  Enter note content (empty line to finish):")
        lines = []
        while True:
            line = self.get_input("  ")
            if not line:
                break
            lines.append(line)
        
        content = '\n'.join(lines)
        
        if self.notes_manager.create_note(title, content):
            print()
            print(f"  ✓ Note '{title}' created successfully!")
        else:
            print("  ✗ Failed to create note")
        
        self.pause()
    
    def _edit_note(self):
        """Edit an existing note."""
        notes = self.notes_manager.list_notes()
        if not notes:
            print("  No notes found.")
            self.pause()
            return
        
        print()
        print("  Available notes:")
        for i, note in enumerate(notes, 1):
            print(f"    {i}. {note['title']}")
        print()
        
        choice = self.get_int_input("  Select note to edit: ", 1, len(notes))
        if choice is None:
            return
        
        title = notes[choice - 1]['title']
        note_data = self.notes_manager.read_note(title)
        
        if not note_data:
            print("  ✗ Failed to read note")
            self.pause()
            return
        
        print()
        print("  Current content:")
        print("  " + "─" * 40)
        for line in note_data['content'].split('\n'):
            print(f"  {line}")
        print("  " + "─" * 40)
        print()
        print("  Enter new content (empty line to finish):")
        
        lines = []
        while True:
            line = self.get_input("  ")
            if not line:
                break
            lines.append(line)
        
        new_content = '\n'.join(lines)
        
        if self.notes_manager.update_note(title, new_content):
            print()
            print(f"  ✓ Note '{title}' updated successfully!")
        else:
            print("  ✗ Failed to update note")
        
        self.pause()
    
    def _delete_note(self):
        """Delete a note."""
        notes = self.notes_manager.list_notes()
        if not notes:
            print("  No notes found.")
            self.pause()
            return
        
        print()
        print("  Available notes:")
        for i, note in enumerate(notes, 1):
            print(f"    {i}. {note['title']}")
        print()
        
        choice = self.get_int_input("  Select note to delete: ", 1, len(notes))
        if choice is None:
            return
        
        title = notes[choice - 1]['title']
        confirm = self.get_input(f"  Delete '{title}'? [y/N]: ").strip().lower()
        
        if confirm == 'y':
            if self.notes_manager.delete_note(title):
                print(f"  ✓ Note '{title}' deleted")
            else:
                print("  ✗ Failed to delete note")
        else:
            print("  Cancelled")
        
        self.pause()
    
    def _search_notes(self):
        """Search notes."""
        print()
        query = self.get_input("  Search query: ").strip()
        if not query:
            return
        
        results = self.notes_manager.search_notes(query)
        
        print()
        print(f"  Found {len(results)} result(s):")
        print("  " + "─" * 60)
        
        for note in results:
            print(f"    • {note['title']}")
            # Show context around match
            content = note['content']
            idx = content.lower().find(query.lower())
            if idx >= 0:
                start = max(0, idx - 30)
                end = min(len(content), idx + len(query) + 30)
                context = content[start:end]
                if start > 0:
                    context = "..." + context
                if end < len(content):
                    context = context + "..."
                print(f"      {context}")
            print()
        
        self.pause()
    
    def export_castle_menu(self):
        """Menu for exporting castle to file."""
        self.clear_screen()
        self.print_header()
        
        print("  EXPORT CASTLE TO FILE")
        print("  ──────────────────────")
        print()
        
        if not self.current_castle:
            print("  No castle to export. Create one first.")
            self.pause()
            return
        
        if not self.current_keys:
            print("  No keys configured. Add keys first.")
            self.pause()
            return
        
        if len(self.current_keys) < self.current_castle.required_keys:
            print(f"  Need {self.current_castle.required_keys} keys, have {len(self.current_keys)}")
            self.pause()
            return
        
        default_name = "my_castle.castle"
        filepath = self.get_input(f"  Export path [{default_name}]: ").strip() or default_name
        
        try:
            self.current_castle.export_to_file(Path(filepath), self.current_keys)
            print()
            print(f"  ✓ Castle exported to: {filepath}")
            print(f"    Items: {len(self.current_castle.encrypted_items)}")
            print(f"    Rooms: {len(self.current_castle.rooms)}")
            print(f"    Notes: {len(self.current_castle.notes)}")
            print(f"    Required keys: {self.current_castle.required_keys}")
        except Exception as e:
            print(f"  ✗ Error: {e}")
        
        self.pause()
    
    def import_castle_menu(self):
        """Menu for importing castle from file."""
        self.clear_screen()
        self.print_header()
        
        print("  IMPORT CASTLE FROM FILE")
        print("  ────────────────────────")
        print()
        
        filepath = self.get_input("  Castle file path: ").strip()
        if not filepath:
            return
        
        if not Path(filepath).exists():
            print("  File not found.")
            self.pause()
            return
        
        try:
            with open(filepath, 'rb') as f:
                magic = f.read(8)
                if magic not in (b'CASTLE01', b'CASTLE02'):
                    print("  Invalid castle file.")
                    self.pause()
                    return
                f.read(1)  # version
                required_keys = struct.unpack('<B', f.read(1))[0]
            
            print(f"  This castle requires {required_keys} key(s).")
            print()
            
            keys = []
            for i in range(required_keys):
                password = self.get_input(f"  Enter key {i+1}: ", password=True)
                if not password:
                    print("  Import cancelled.")
                    self.pause()
                    return
                keys.append(DoorKey.from_password(password, f"import_key_{i}"))
            
            self.current_castle = CastleFile.import_from_file(Path(filepath), keys)
            self.current_keys = keys
            
            if self.current_castle.cascade_config:
                self.current_cascade = CascadingDoorSystem(self.current_castle.cascade_config)
            
            print()
            print("  ✓ Castle imported successfully!")
            print(f"    Items: {len(self.current_castle.encrypted_items)}")
            print(f"    Rooms: {len(self.current_castle.rooms)}")
            print(f"    Notes: {len(self.current_castle.notes)}")
            
            self._collect_external_keys()
            master_key = keys[0] if keys else None
            if self.current_cascade and self.current_cascade.unlock_cascade(master_key, self.external_keys):
                self.notes_manager = NotesManager(self.current_cascade, self.current_castle)
                print("  ✓ Cascade unlocked")
            
        except ValueError as e:
            print(f"  ✗ {e}")
        except Exception as e:
            print(f"  ✗ Error: {e}")
        
        self.pause()
    
    def view_castle_menu(self):
        """View contents of current castle."""
        self.clear_screen()
        self.print_header()
        
        print("  CASTLE CONTENTS")
        print("  ───────────────")
        print()
        
        if not self.current_castle:
            print("  No castle loaded.")
            self.pause()
            return
        
        print(f"  Required keys: {self.current_castle.required_keys}")
        print(f"  Created: {time.ctime(self.current_castle.metadata.get('created_at', 0))}")
        print(f"  Version: {self.current_castle.metadata.get('version', 'unknown')}")
        print()
        
        if self.current_castle.cascade_config:
            print("  Cascade Configuration:")
            print(f"    ID: {self.current_castle.cascade_config.cascade_id}")
            print(f"    Doors: {len(self.current_castle.cascade_config.doors)}")
            for door in self.current_castle.cascade_config.doors:
                print(f"      - {door.door_id} ({door.door_type.name})")
        print()
        
        print("  Encrypted Items:")
        if self.current_castle.encrypted_items:
            for name, result in self.current_castle.encrypted_items.items():
                size = result.metadata.get('original_len', '?')
                print(f"    - {name} ({size} bytes)")
        else:
            print("    (none)")
        print()
        
        print("  Rooms:")
        if self.current_castle.rooms:
            self._print_room_tree(self.current_castle.rooms, indent=4)
        else:
            print("    (none)")
        print()
        
        print("  Notes:")
        if self.current_castle.notes:
            for name in self.current_castle.notes.keys():
                print(f"    - {name}")
        else:
            print("    (none)")
        
        self.pause()
    
    def _print_room_tree(self, rooms: Dict[str, RoomItem], indent: int = 0):
        """Print room tree structure."""
        prefix = " " * indent
        for name, room in rooms.items():
            if room.item_type == 'directory':
                child_count = len(room.children)
                print(f"{prefix}📁 {name}/ ({child_count} items)")
                if room.children:
                    self._print_room_tree(room.children, indent + 2)
            else:
                size = room.metadata.get('original_size', '?')
                print(f"{prefix}📄 {name} ({size} bytes)")
    
    def _check_unlocked(self, pause: bool = True) -> bool:
        """Check if cascade is unlocked."""
        if not self.current_cascade:
            print("  No cascade configured. Create a castle first.")
            if pause:
                self.pause()
            return False
        
        if not all(d.is_unlocked for d in self.current_cascade.doors):
            print("  Cascade is locked. Open the castle first.")
            if pause:
                self.pause()
            return False
        
        return True
    
    def run_tests(self):
        """Run the test suite."""
        self.clear_screen()
        self.print_header()
        
        print("  RUNNING TEST SUITE")
        print("  ──────────────────")
        print()
        
        suite = CascadingDoorTestSuite(verbose=True)
        results = suite.run_all_tests()
        
        self.pause()
    
    def exit_app(self):
        """Exit the application."""
        self.clear_screen()
        print()
        print(f"  Thank you for using {__name_full__}!")
        print(f"  Copyright (c) {__author__} - {__license__}")
        print()
        self.running = False
    
    def run(self):
        """Main run loop."""
        while self.running:
            try:
                self.main_menu()
            except KeyboardInterrupt:
                print()
                print("  Use menu option 0 to exit properly.")
                self.pause()
            except Exception as e:
                print(f"  Unexpected error: {e}")
                self.pause()


# =============================================================================
# SECTION 10: TEST SUITE
# =============================================================================

class CascadingDoorTestSuite:
    """Test suite for validating cascading door implementations."""
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.results: Dict[str, Dict[str, Any]] = {}
    
    def log(self, msg: str):
        if self.verbose:
            print(msg)
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run complete test suite."""
        self.log("\n" + "=" * 70)
        self.log("CASCADING DOOR TEST SUITE")
        self.log("=" * 70)
        
        for rc_name, rc_creator in [
            ("RC1_Gemini_Fractal", create_rc1_cascade),
            ("RC2_SHA256_Fractal", create_rc2_cascade),
            ("RC3_Blake2b_Mixed", create_rc3_cascade)
        ]:
            self.log(f"\n--- Testing {rc_name} ---")
            self._test_cascade(rc_name, rc_creator)
        
        self.log("\n--- Testing Castle Export/Import ---")
        self._test_castle_file()
        
        self.log("\n--- Testing Notes System ---")
        self._test_notes()
        
        self.log("\n--- Testing Directory Import/Export ---")
        self._test_directory_operations()
        
        self.log("\n" + "=" * 70)
        self.log("TEST SUMMARY")
        self.log("=" * 70)
        
        for name, results in self.results.items():
            passed = sum(1 for v in results.values() if v.get('passed', False))
            total = len(results)
            self.log(f"\n{name}: {passed}/{total} tests passed")
            for test, result in results.items():
                status = "✓" if result.get('passed', False) else "✗"
                self.log(f"  {status} {test}: {result.get('details', '')}")
        
        return self.results
    
    def _test_cascade(self, name: str, creator: Callable):
        """Test a specific cascade configuration."""
        self.results[name] = {}
        
        password = "TestPassword123!"
        salt = secrets.token_bytes(32)
        
        try:
            cascade = creator(password, salt)
            self.results[name]['creation'] = {
                'passed': True,
                'details': f"{len(cascade.doors)} doors created"
            }
        except Exception as e:
            self.results[name]['creation'] = {
                'passed': False,
                'details': str(e)
            }
            return
        
        initial_key = DoorKey(
            key_id="master",
            key_material=hashlib.sha256(password.encode()).digest()
        )
        
        external_keys = {}
        for door in cascade.doors:
            if door.config.required_external_keys > 0:
                ext_list = [
                    DoorKey(
                        key_id=f"external_{door.config.door_id}_{i}",
                        key_material=secrets.token_bytes(32)
                    )
                    for i in range(door.config.required_external_keys)
                ]
                external_keys[door.config.door_id] = ext_list
        
        try:
            unlocked = cascade.unlock_cascade(initial_key, external_keys)
            self.results[name]['unlock'] = {
                'passed': unlocked,
                'details': "All doors unlocked" if unlocked else "Unlock failed"
            }
        except Exception as e:
            self.results[name]['unlock'] = {
                'passed': False,
                'details': str(e)
            }
            return
        
        if not unlocked:
            return
        
        test_data = b"The spectral braid weaves through cascading doors of light and shadow." * 20
        
        try:
            result = cascade.encrypt(test_data)
            decrypted = cascade.decrypt(result)
            
            match = (decrypted == test_data)
            self.results[name]['round_trip'] = {
                'passed': match,
                'details': f"Match={match}, entropy={result.entropy_achieved:.2f}"
            }
        except Exception as e:
            self.results[name]['round_trip'] = {
                'passed': False,
                'details': str(e)
            }
        
        edge_cases = [
            (b"X", "single_byte"),
            (bytes([0] * 100), "all_zeros"),
            (bytes(range(256)), "all_bytes"),
        ]
        
        edge_passed = 0
        for data, case_name in edge_cases:
            try:
                result = cascade.encrypt(data)
                decrypted = cascade.decrypt(result)
                if decrypted == data:
                    edge_passed += 1
            except Exception:
                pass
        
        self.results[name]['edge_cases'] = {
            'passed': edge_passed == len(edge_cases),
            'details': f"{edge_passed}/{len(edge_cases)} passed"
        }
        
        cascade.lock_cascade()
        try:
            relocked = not any(d.is_unlocked for d in cascade.doors)
            cascade.unlock_cascade(initial_key, external_keys)
            reunlocked = all(d.is_unlocked for d in cascade.doors)
            
            self.results[name]['lock_cycle'] = {
                'passed': relocked and reunlocked,
                'details': f"Lock={relocked}, Reopen={reunlocked}"
            }
        except Exception as e:
            self.results[name]['lock_cycle'] = {
                'passed': False,
                'details': str(e)
            }
        
        large_data = secrets.token_bytes(10000)
        try:
            start = time.perf_counter()
            result = cascade.encrypt(large_data)
            encrypt_time = time.perf_counter() - start
            
            start = time.perf_counter()
            cascade.decrypt(result)
            decrypt_time = time.perf_counter() - start
            
            throughput = len(large_data) / (encrypt_time * 1024 * 1024)
            
            self.results[name]['performance'] = {
                'passed': throughput > 0.1,
                'details': f"{throughput:.2f} MB/s encrypt, {len(large_data)/(decrypt_time*1024*1024):.2f} MB/s decrypt"
            }
        except Exception as e:
            self.results[name]['performance'] = {
                'passed': False,
                'details': str(e)
            }
    
    def _test_castle_file(self):
        """Test castle file export/import."""
        self.results['CastleFile'] = {}
        
        try:
            import tempfile
            
            castle = CastleFile(required_keys=2)
            cascade = create_simple_cascade(2)
            castle.set_cascade_config(cascade.config)
            
            key1 = DoorKey.from_password("password1", "key1")
            key2 = DoorKey.from_password("password2", "key2")
            keys = [key1, key2]
            
            cascade.unlock_cascade(key1)
            result = cascade.encrypt(b"Test data for castle")
            castle.add_encrypted_item("test_item", result)
            
            with tempfile.NamedTemporaryFile(suffix='.castle', delete=False) as f:
                castle_path = f.name
            
            castle.export_to_file(Path(castle_path), keys)
            
            self.results['CastleFile']['export'] = {
                'passed': Path(castle_path).exists(),
                'details': f"Exported to {castle_path}"
            }
            
            imported = CastleFile.import_from_file(Path(castle_path), keys)
            
            self.results['CastleFile']['import'] = {
                'passed': len(imported.encrypted_items) == 1,
                'details': f"Imported {len(imported.encrypted_items)} items"
            }
            
            imported_cascade = CascadingDoorSystem(imported.cascade_config)
            imported_cascade.unlock_cascade(key1)
            decrypted = imported_cascade.decrypt(imported.get_item("test_item"))
            
            self.results['CastleFile']['verify'] = {
                'passed': decrypted == b"Test data for castle",
                'details': f"Data matches: {decrypted == b'Test data for castle'}"
            }
            
            try:
                wrong_key = DoorKey.from_password("wrong", "wrong")
                CastleFile.import_from_file(Path(castle_path), [wrong_key, wrong_key])
                self.results['CastleFile']['security'] = {
                    'passed': False,
                    'details': "Should have rejected wrong keys"
                }
            except ValueError:
                self.results['CastleFile']['security'] = {
                    'passed': True,
                    'details': "Correctly rejected wrong keys"
                }
            
            Path(castle_path).unlink()
            
        except Exception as e:
            self.results['CastleFile']['error'] = {
                'passed': False,
                'details': str(e)
            }
    
    def _test_notes(self):
        """Test notes system."""
        self.results['NotesSystem'] = {}
        
        try:
            castle = CastleFile(required_keys=1)
            cascade = create_simple_cascade(2)
            castle.set_cascade_config(cascade.config)
            
            key = DoorKey.from_password("password", "key")
            cascade.unlock_cascade(key)
            
            notes = NotesManager(cascade, castle)
            
            # Test create
            created = notes.create_note("Test Note", "This is test content")
            self.results['NotesSystem']['create'] = {
                'passed': created,
                'details': "Note created" if created else "Failed"
            }
            
            # Test read
            read_data = notes.read_note("Test Note")
            self.results['NotesSystem']['read'] = {
                'passed': read_data is not None and read_data['content'] == "This is test content",
                'details': f"Read successful: {read_data is not None}"
            }
            
            # Test update
            updated = notes.update_note("Test Note", "Updated content")
            read_updated = notes.read_note("Test Note")
            self.results['NotesSystem']['update'] = {
                'passed': updated and read_updated['content'] == "Updated content",
                'details': f"Update successful"
            }
            
            # Test list
            notes_list = notes.list_notes()
            self.results['NotesSystem']['list'] = {
                'passed': len(notes_list) == 1,
                'details': f"Listed {len(notes_list)} notes"
            }
            
            # Test search
            notes.create_note("Searchable", "This contains keyword")
            results = notes.search_notes("keyword")
            self.results['NotesSystem']['search'] = {
                'passed': len(results) == 1,
                'details': f"Found {len(results)} results"
            }
            
            # Test delete
            deleted = notes.delete_note("Test Note")
            self.results['NotesSystem']['delete'] = {
                'passed': deleted and notes.read_note("Test Note") is None,
                'details': f"Delete successful"
            }
            
        except Exception as e:
            self.results['NotesSystem']['error'] = {
                'passed': False,
                'details': str(e)
            }
    
    def _test_directory_operations(self):
        """Test directory import/export."""
        self.results['DirectoryOps'] = {}
        
        try:
            import tempfile
            
            castle = CastleFile(required_keys=1)
            cascade = create_simple_cascade(2)
            castle.set_cascade_config(cascade.config)
            
            key = DoorKey.from_password("password", "key")
            cascade.unlock_cascade(key)
            
            with tempfile.TemporaryDirectory() as tmpdir:
                # Create test directory structure
                test_dir = Path(tmpdir) / "test_import"
                test_dir.mkdir()
                (test_dir / "file1.txt").write_text("Content 1")
                (test_dir / "file2.txt").write_text("Content 2")
                subdir = test_dir / "subdir"
                subdir.mkdir()
                (subdir / "nested.txt").write_text("Nested content")
                
                # Test import
                importer = DirectoryImporter(cascade, castle)
                room = importer.import_directory(test_dir, "test_room", ImportMode.PASSTHROUGH)
                castle.rooms["test_room"] = room
                
                stats = importer.get_stats()
                self.results['DirectoryOps']['import'] = {
                    'passed': stats['files_imported'] == 3 and stats['dirs_imported'] == 1,
                    'details': f"Files: {stats['files_imported']}, Dirs: {stats['dirs_imported']}"
                }
                
                # Test export
                export_dir = Path(tmpdir) / "test_export"
                exporter = DirectoryExporter(cascade, castle)
                exporter._export_room_item(room, export_dir, recursive=True)
                
                stats = exporter.get_stats()
                exported_files = list(export_dir.rglob("*"))
                exported_files = [f for f in exported_files if f.is_file()]
                
                self.results['DirectoryOps']['export'] = {
                    'passed': len(exported_files) == 3,
                    'details': f"Exported {len(exported_files)} files"
                }
                
                # Verify content
                content = (export_dir / "file1.txt").read_text()
                self.results['DirectoryOps']['verify'] = {
                    'passed': content == "Content 1",
                    'details': f"Content matches: {content == 'Content 1'}"
                }
            
        except Exception as e:
            self.results['DirectoryOps']['error'] = {
                'passed': False,
                'details': str(e)
            }


# =============================================================================
# SECTION 11: MAIN EXECUTION
# =============================================================================

def main():
    """Main entry point."""
    if len(sys.argv) > 1:
        if sys.argv[1] == '--test':
            print("╔══════════════════════════════════════════════════════════════════════╗")
            print("║            CASTLEfs - Cascading Door Filesystem Encryption          ║")
            print("║            Copyright (c) Brian Richard RAMOS - Apache 2.0           ║")
            print("║            Release Candidate Testing Suite                           ║")
            print("╚══════════════════════════════════════════════════════════════════════╝")
            
            suite = CascadingDoorTestSuite(verbose=True)
            suite.run_all_tests()
            return
        elif sys.argv[1] == '--help':
            print(f"{__name_full__} v{__version__} - Cascading Door Filesystem Encryption")
            print()
            print("Usage:")
            print("  python CASTLEfs.py          - Interactive CLI mode")
            print("  python CASTLEfs.py --test   - Run test suite")
            print("  python CASTLEfs.py --help   - Show this help")
            return
        elif sys.argv[1] == '--version':
            print(f"{__name_full__} v{__version__}")
            print(f"Copyright (c) {__author__}")
            print(f"License: {__license__}")
            return
    
    cli = CastleCLI()
    cli.run()


if __name__ == "__main__":
    main()
