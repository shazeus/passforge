<p align="center">
  <h1 align="center">passforge</h1>
  <p align="center">Secure password and secret generator for the terminal.</p>
  <p align="center">
    <a href="https://pypi.org/project/passforge-cli/"><img src="https://img.shields.io/pypi/v/passforge-cli.svg" alt="PyPI"></a>
    <a href="https://pypi.org/project/passforge-cli/"><img src="https://img.shields.io/pypi/pyversions/passforge-cli.svg" alt="Python"></a>
    <a href="https://github.com/shazeus/passforge/blob/main/LICENSE"><img src="https://img.shields.io/github/license/shazeus/passforge" alt="License"></a>
    <a href="https://github.com/shazeus/passforge/stargazers"><img src="https://img.shields.io/github/stars/shazeus/passforge" alt="Stars"></a>
  </p>
</p>

---

**passforge** is a fast, cryptographically secure password and secret generator for the terminal. Generate strong passwords, memorable passphrases, numeric PINs, API tokens, and UUIDs — all from a single CLI tool. Analyze password strength with entropy metrics, estimate crack times, and check against the Have I Been Pwned breach database without ever sending your password over the network.

- **Password generation** — Configurable length, character sets, exclusions, and required character minimums
- **Passphrase generation** — Memorable word-based passphrases using a curated 2000-word list
- **PIN generation** — Numeric PINs of any length using a CSPRNG
- **Token generation** — API keys, secrets, and UUIDs in hex, base64, URL-safe, alphanumeric, or UUID format
- **Strength analysis** — Entropy calculation, crack time estimation, character-type breakdown, and pattern detection
- **Breach checking** — k-Anonymity HIBP lookup that never exposes your full password hash
- **Bulk generation** — Generate hundreds of passwords at once and save to file
- **Security profiles** — Preset recipes for common use cases (web, API keys, WiFi, admin, etc.)
- **Clipboard support** — Optionally copy the result directly to clipboard
- **Bare mode** — Clean output for scripting and piping to other tools

## Installation

```bash
pip install passforge-cli
```

## Usage

```bash
# Generate a 16-character password
passforge gen

# Generate a 24-character password, no symbols
passforge gen -l 24 --no-symbols

# Generate 5 passwords and copy the first to clipboard
passforge gen -n 5 -c

# Generate a 4-word passphrase
passforge passphrase

# Generate a passphrase with custom separator
passforge passphrase -s "_" --capitalize

# Generate a 6-digit PIN
passforge pin

# Generate a secure hex token (API key)
passforge token -f hex -l 32

# Generate a UUID
passforge token -f uuid

# Analyze password strength
passforge analyze "MyP@ssw0rd123"

# Check against Have I Been Pwned
passforge analyze "password123" --hibp

# Bulk generate 20 passwords with strength info
passforge bulk -n 20 --with-strength

# Save 100 passwords to file
passforge bulk -n 100 -o passwords.txt

# Show entropy reference table
passforge strength -l 16

# Use a security profile
passforge recipe --profile secure
passforge recipe --profile api
passforge recipe --profile wifi
```

## Commands

| Command | Description |
|---------|-------------|
| `gen` | Generate cryptographically secure passwords |
| `passphrase` | Generate memorable word-based passphrases |
| `pin` | Generate numeric PINs |
| `token` | Generate API keys, secrets, and UUIDs |
| `analyze` | Analyze password strength and entropy |
| `bulk` | Bulk-generate secrets and save to file |
| `strength` | Show entropy reference table for configurations |
| `recipe` | Generate passwords using curated security profiles |

### `gen` Options

| Flag | Description |
|------|-------------|
| `-l, --length` | Password length (default: 16) |
| `-n, --count` | Number of passwords |
| `--no-upper` | Exclude uppercase letters |
| `--no-lower` | Exclude lowercase letters |
| `--no-digits` | Exclude digits |
| `--no-symbols` | Exclude symbols |
| `--no-ambiguous` | Exclude `0`, `O`, `1`, `l`, `I` |
| `--exclude` | Custom characters to exclude |
| `--min-upper/lower/digits/symbols` | Require at least N of each type |
| `-c, --copy` | Copy to clipboard |
| `--bare` | Clean output for scripting |

### `token` Formats

| Format | Example |
|--------|---------|
| `hex` | `a3f9b2c1...` |
| `urlsafe` | `xZ_Abc123...` |
| `base64` | `YWJjZGVm...` |
| `alphanumeric` | `Abc123XyZ...` |
| `uuid` | `550e8400-e29b-41d4-...` |

### `recipe` Profiles

| Profile | Use Case |
|---------|----------|
| `basic` | Social media, low-risk accounts (12 chars) |
| `secure` | Email, banking, work accounts (20 chars) |
| `max` | Admin, root, vault passwords (32 chars) |
| `web` | Web services, avoids special symbols (16 chars) |
| `api` | API keys and service tokens |
| `wifi` | WiFi passwords, easy to type |
| `pin` | 6-digit numeric PIN |
| `passphrase` | 4-word memorable passphrase |

## Configuration

passforge uses Python's `secrets` module, which sources randomness from the OS CSPRNG (`/dev/urandom` on Linux/macOS, `CryptGenRandom` on Windows). No configuration file is needed.

For scripting, use `--bare` to get clean output:

```bash
# Generate and use a password in a script
NEW_PASS=$(passforge gen -l 20 --no-symbols --bare)

# Bulk generate and pipe
passforge bulk -n 10 --bare | grep -v "^#"
```

## License

MIT — see [LICENSE](LICENSE) for details.
