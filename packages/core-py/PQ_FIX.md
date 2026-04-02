# core-py: ML-DSA-65 (liboqs) Fix

## Current State

28/31 vectors pass. The 3 failing tests are all hybrid ML-DSA-65-ES256 vectors.

## Problem

The `oqs` Python package (`liboqs-python`) requires a **shared library** (`liboqs.dylib`) at runtime via `ctypes`. Homebrew's `liboqs` bottle only installs the **static library** (`liboqs.a`), which `ctypes` can't load.

```
RuntimeError: No oqs shared libraries found
```

The library is at `/opt/homebrew/opt/liboqs/lib/liboqs.a` — no `.dylib` exists.

## Why `brew reinstall --build-from-source` Doesn't Work

The brew formula builds with `BUILD_SHARED_LIBS=OFF` by default, and building from source currently fails due to outdated Command Line Tools.

## Fix Options

### Option A: Build liboqs from source with shared libs (recommended)

```bash
git clone https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
cd /tmp/liboqs
mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=$HOME/_oqs ..
make -j$(sysctl -n hw.ncpu)
make install
```

Then the `oqs` Python package will find it at `$HOME/_oqs/lib/liboqs.dylib` (its default search path).

Alternatively, set the env var:
```bash
export OQS_INSTALL_PATH=/path/to/install
```

### Option B: Switch from `oqs` to a pure-Python ML-DSA library

Replace `oqs.Signature("ML-DSA-65")` with a pure-Python implementation (e.g., a `dilithium` or `ml-dsa` package) that doesn't need a C shared library. Would need to verify FIPS 204 compatibility.

### Option C: Update Xcode CLT, then rebuild via brew

```bash
sudo rm -rf /Library/Developer/CommandLineTools
sudo xcode-select --install
# Then:
brew reinstall --build-from-source liboqs
```

## Files

- `open_passkey/mldsa65.py` — uses `oqs.Signature("ML-DSA-65")` for verification
- `open_passkey/composite.py` — calls `verify_mldsa65_raw()` for hybrid composite
- `pyproject.toml` — `oqs` is in the `[pq]` extras group

## Verify After Fix

```bash
cd packages/core-py
source .venv/bin/activate
pytest -v
# Expect: 31/31 pass
```
