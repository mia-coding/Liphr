#!/usr/bin/env python3
"""
vault.py - a simple command-line password manager built on Loom, a custom cipher.

THE LOOM CIPHER
    Loom is a 256-bit block cipher designed for this project. It's a Feistel
    network, the same skeleton behind DES and Blowfish: each 32-byte block is
    split into a left and a right half, and the halves are woven together over
    8 rounds:

        L, R  =  R,  L XOR F(round_key[i], R)

    The round function F is HMAC-SHA256 (cut to 16 bytes), and every round has
    its own key. A Feistel network can always be run backwards no matter what F
    is, and with a pseudorandom F and 4+ rounds it is provably a strong
    pseudorandom permutation (the Luby-Rackoff theorem). Loom uses 8 rounds.

HOW THE VAULT IS PROTECTED
    1. Key stretching: the master password goes through scrypt with a random
       salt. scrypt is memory-hard, so every guess costs an attacker ~128 MiB
       of RAM, which keeps GPU cracking slow. (If your Python build has no
       scrypt, it falls back to PBKDF2-SHA256 with 600,000 iterations.)
    2. Key separation: the stretched key is split into an encryption key and a
       MAC key by HMAC-ing two different labels.
    3. Encryption: the whole vault (as JSON) is encrypted with Loom in counter
       mode, under a fresh random nonce every time it's saved.
    4. Authentication: an HMAC-SHA256 tag covers the header, nonce and
       ciphertext, and it's checked in constant time BEFORE anything is
       decrypted. A wrong password or an edited file is rejected instead of
       decrypting to junk.

    Honest caveat: Loom is built from well-studied parts, but the design itself
    hasn't been reviewed by anyone. Great for learning; for passwords that
    really matter, use an audited manager or swap Loom for AES-GCM.

USAGE
    python3 vault.py                    open (or create) ~/.loom_vault.json
    python3 vault.py --vault work.json  use a different vault file
    python3 vault.py --selftest         run the cipher self-tests

    Standard library only. Python 3.8+.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import difflib
import getpass
import hashlib
import hmac
import json
import os
import secrets
import string
import sys
import unicodedata
from pathlib import Path

DEFAULT_VAULT = Path.home() / ".loom_vault.json"
FORMAT = "loom-vault-1"

BLOCK_SIZE = 32          # Loom encrypts 32-byte (256-bit) blocks
HALF = BLOCK_SIZE // 2   # each Feistel half is 16 bytes
ROUNDS = 8
NONCE_SIZE = 16          # counter block = 16-byte nonce + 16-byte counter
MIN_MASTER_LENGTH = 12


class VaultError(Exception):
    """The vault file is unreadable or uses settings this script can't handle."""


class WrongPassword(VaultError):
    """The MAC didn't verify: wrong master password, or the file was modified."""


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


# ---------------------------------------------------------------------------
# The Loom cipher
# ---------------------------------------------------------------------------

class Loom:
    """A 256-bit Feistel block cipher with HMAC-SHA256 as its round function."""

    def __init__(self, key: bytes, rounds: int = ROUNDS):
        if len(key) != 32:
            raise ValueError("Loom needs a 32-byte key")
        if rounds < 4:
            raise ValueError("a Feistel cipher needs at least 4 rounds (Luby-Rackoff)")
        # Key schedule: derive an independent-looking key for every round.
        self.round_keys = [
            hmac.digest(key, b"loom round key " + bytes([i]), "sha256")
            for i in range(rounds)
        ]

    @staticmethod
    def _split(block: bytes) -> tuple[bytes, bytes]:
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"Loom blocks are {BLOCK_SIZE} bytes")
        return block[:HALF], block[HALF:]

    @staticmethod
    def _f(round_key: bytes, half: bytes) -> bytes:
        """Round function: a keyed pseudorandom function of one half-block."""
        return hmac.digest(round_key, half, "sha256")[:HALF]

    def encrypt_block(self, block: bytes) -> bytes:
        left, right = self._split(block)
        for key in self.round_keys:
            left, right = right, xor(left, self._f(key, right))
        return left + right

    def decrypt_block(self, block: bytes) -> bytes:
        # Run the rounds backwards. F never has to be inverted, which is the
        # whole trick of the Feistel structure.
        left, right = self._split(block)
        for key in reversed(self.round_keys):
            left, right = xor(right, self._f(key, left)), left
        return left + right

    def ctr(self, nonce: bytes, data: bytes) -> bytes:
        """Counter mode: XOR the data with Loom(nonce||0), Loom(nonce||1), ...

        Encrypting and decrypting are the same operation, so counter mode only
        needs encrypt_block. decrypt_block is there to show the Feistel network
        unwinding (the self-test checks it).
        """
        if len(nonce) != NONCE_SIZE:
            raise ValueError(f"nonce must be {NONCE_SIZE} bytes")
        keystream = bytearray()
        counter = 0
        while len(keystream) < len(data):
            counter_block = nonce + counter.to_bytes(BLOCK_SIZE - NONCE_SIZE, "big")
            keystream += self.encrypt_block(counter_block)
            counter += 1
        return xor(data, keystream)


# ---------------------------------------------------------------------------
# Keys from the master password
# ---------------------------------------------------------------------------

def new_kdf_params() -> dict:
    """Fresh key-stretching settings with a random salt (saved in the vault header)."""
    salt = b64e(secrets.token_bytes(16))
    if hasattr(hashlib, "scrypt"):
        return {"name": "scrypt", "salt": salt, "n": 2**17, "r": 8, "p": 1}
    return {"name": "pbkdf2-sha256", "salt": salt, "iterations": 600_000}


def derive_keys(master_password: str, kdf: dict) -> tuple[bytes, bytes]:
    """Stretch the master password, then split it into (encryption key, MAC key)."""
    # Normalize so an accent typed as one character or as two gives the same key.
    password = unicodedata.normalize("NFC", master_password).encode("utf-8")
    salt = b64d(kdf["salt"])
    if kdf["name"] == "scrypt":
        if not hasattr(hashlib, "scrypt"):
            raise VaultError("this vault uses scrypt, which your Python build doesn't support")
        # maxmem allows up to 256 MiB; the default settings need about 128 MiB.
        stretched = hashlib.scrypt(password, salt=salt, n=kdf["n"], r=kdf["r"], p=kdf["p"],
                                   maxmem=2**28, dklen=32)
    elif kdf["name"] == "pbkdf2-sha256":
        stretched = hashlib.pbkdf2_hmac("sha256", password, salt, kdf["iterations"], dklen=32)
    else:
        raise VaultError(f"unknown key-derivation function {kdf['name']!r}")
    enc_key = hmac.digest(stretched, b"loom encryption key", "sha256")
    mac_key = hmac.digest(stretched, b"loom mac key", "sha256")
    return enc_key, mac_key


# ---------------------------------------------------------------------------
# Authenticated encryption: encrypt with Loom, then MAC
# ---------------------------------------------------------------------------

def _mac_input(header: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    # Length-prefix the header so nobody can shift bytes between fields.
    return len(header).to_bytes(8, "big") + header + nonce + ciphertext


def seal(enc_key: bytes, mac_key: bytes, plaintext: bytes,
         header: bytes) -> tuple[bytes, bytes, bytes]:
    nonce = secrets.token_bytes(NONCE_SIZE)  # fresh for every save; never reuse one
    ciphertext = Loom(enc_key).ctr(nonce, plaintext)
    tag = hmac.digest(mac_key, _mac_input(header, nonce, ciphertext), "sha256")
    return nonce, ciphertext, tag


def unseal(enc_key: bytes, mac_key: bytes, nonce: bytes, ciphertext: bytes,
           tag: bytes, header: bytes) -> bytes:
    expected = hmac.digest(mac_key, _mac_input(header, nonce, ciphertext), "sha256")
    if not hmac.compare_digest(expected, tag):  # constant time: no timing leaks
        raise WrongPassword("wrong master password, or the vault file was modified")
    return Loom(enc_key).ctr(nonce, ciphertext)


# ---------------------------------------------------------------------------
# The vault file
# ---------------------------------------------------------------------------

def header_bytes(kdf: dict) -> bytes:
    """Canonical bytes of the unencrypted header, so the MAC can cover it too."""
    header = {"format": FORMAT, "kdf": kdf}
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode()


def atomic_write(path: Path, data: bytes) -> None:
    """Write a temp file, then swap it in, so a crash can't leave a half-written vault."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)  # owner read/write only
    os.replace(tmp, path)


class Vault:
    def __init__(self, path: Path, kdf: dict, keys: tuple[bytes, bytes], entries: dict):
        self.path = path
        self.kdf = kdf
        self.enc_key, self.mac_key = keys
        # normalized service name -> {"service", "username", "password", "updated"}
        self.entries = entries

    @classmethod
    def create(cls, path: Path, master_password: str) -> Vault:
        kdf = new_kdf_params()
        vault = cls(path, kdf, derive_keys(master_password, kdf), {})
        vault.save()
        return vault

    @classmethod
    def load(cls, path: Path, master_password: str) -> Vault:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            if doc["format"] != FORMAT:
                raise VaultError(f"unsupported vault format {doc['format']!r}")
            kdf = doc["kdf"]
            nonce, ciphertext, tag = (b64d(doc[name]) for name in ("nonce", "ciphertext", "tag"))
            if len(nonce) != NONCE_SIZE:
                raise ValueError("bad nonce length")
            keys = derive_keys(master_password, kdf)
        except (ValueError, KeyError, TypeError) as exc:
            raise VaultError(f"{path} isn't a valid vault file ({exc})") from exc
        plaintext = unseal(*keys, nonce, ciphertext, tag, header_bytes(kdf))
        return cls(path, kdf, keys, json.loads(plaintext)["entries"])

    def save(self) -> None:
        plaintext = json.dumps({"entries": self.entries}).encode("utf-8")
        nonce, ciphertext, tag = seal(self.enc_key, self.mac_key, plaintext,
                                      header_bytes(self.kdf))
        doc = {"format": FORMAT, "kdf": self.kdf,
               "nonce": b64e(nonce), "ciphertext": b64e(ciphertext), "tag": b64e(tag)}
        atomic_write(self.path, json.dumps(doc, indent=2).encode("utf-8"))

    def check_password(self, master_password: str) -> bool:
        enc_key, mac_key = derive_keys(master_password, self.kdf)
        return hmac.compare_digest(enc_key + mac_key, self.enc_key + self.mac_key)

    def change_master_password(self, new_password: str) -> None:
        self.kdf = new_kdf_params()  # new salt too
        self.enc_key, self.mac_key = derive_keys(new_password, self.kdf)
        self.save()


# ---------------------------------------------------------------------------
# Password generator
# ---------------------------------------------------------------------------

SYMBOLS = "!@#$%^&*-_=+?"


def generate_password(length: int = 20) -> str:
    """A random password from the OS's secure RNG, with every character type."""
    if length < 4:
        raise ValueError("length must be at least 4")
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits, SYMBOLS]
    alphabet = "".join(pools)
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(ch in pool for ch in candidate) for pool in pools):
            return candidate


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------

HELP = """\
Commands:
  add [service]     save a login (leave the password blank to generate one)
  get <service>     show a login (partial names work)
  list              list saved logins
  delete <service>  remove a login
  gen [length]      generate a strong password (default: 20 characters)
  passwd            change the master password
  help              show this list
  quit              lock the vault and exit"""


def ask(prompt: str) -> str:
    return input(prompt).strip()


def confirm(question: str) -> bool:
    return ask(f"{question} [y/N] ").lower() in ("y", "yes")


def normalize(service: str) -> str:
    """Lookup key for a service: ignores case and extra spaces."""
    return " ".join(service.split()).lower()


def ask_new_master_password() -> str:
    while True:
        password = getpass.getpass(f"New master password ({MIN_MASTER_LENGTH}+ characters): ")
        if len(password) < MIN_MASTER_LENGTH:
            print("Too short. A few random words strung together works well.")
        elif getpass.getpass("Type it again: ") != password:
            print("Those didn't match. Try again.")
        else:
            return password


def find(vault: Vault, name: str) -> str | None:
    """Return the key of the entry matching `name`, or None after saying why."""
    key = normalize(name)
    if not key:
        print("Which service?")
        return None
    if key in vault.entries:
        return key
    matches = [k for k in vault.entries if key in k]
    if not matches:
        matches = difflib.get_close_matches(key, list(vault.entries), n=3)
    if len(matches) == 1:
        return matches[0]
    if matches:
        names = ", ".join(vault.entries[k]["service"] for k in sorted(matches))
        print(f"Did you mean: {names}?")
    else:
        print(f"No login saved for {name!r}.")
    return None


def cmd_add(vault: Vault, arg: str) -> None:
    service = " ".join((arg or ask("Service (e.g. GitHub): ")).split())
    if not service:
        print("The service name can't be empty.")
        return
    key = normalize(service)
    if key in vault.entries and not confirm(
            f"{vault.entries[key]['service']} is already saved. Replace it?"):
        return
    username = ask("Username or email: ")
    password = getpass.getpass("Password (leave blank to generate one): ")
    if not password:
        password = generate_password()
        print(f"Generated password: {password}")
    vault.entries[key] = {
        "service": service,
        "username": username,
        "password": password,
        "updated": datetime.date.today().isoformat(),
    }
    vault.save()
    print(f"Saved {service}.")


def cmd_get(vault: Vault, arg: str) -> None:
    key = find(vault, arg or ask("Service: "))
    if key:
        entry = vault.entries[key]
        print(f"  Service:  {entry['service']}")
        print(f"  Username: {entry['username']}")
        print(f"  Password: {entry['password']}")


def cmd_list(vault: Vault, arg: str) -> None:
    if not vault.entries:
        print("Your vault is empty. Use 'add' to save your first login.")
        return
    rows = [vault.entries[k] for k in sorted(vault.entries)]
    w1 = max(len("SERVICE"), *(len(e["service"]) for e in rows))
    w2 = max(len("USERNAME"), *(len(e["username"]) for e in rows))
    print(f"  {'SERVICE':<{w1}}  {'USERNAME':<{w2}}  UPDATED")
    for e in rows:
        print(f"  {e['service']:<{w1}}  {e['username']:<{w2}}  {e['updated']}")


def cmd_delete(vault: Vault, arg: str) -> None:
    key = find(vault, arg or ask("Service to delete: "))
    if key and confirm(f"Delete {vault.entries[key]['service']}?"):
        del vault.entries[key]
        vault.save()
        print("Deleted.")


def cmd_gen(vault: Vault, arg: str) -> None:
    try:
        length = int(arg) if arg else 20
    except ValueError:
        length = 0
    if not 8 <= length <= 128:
        print("Length must be a number from 8 to 128.")
        return
    print(generate_password(length))


def cmd_passwd(vault: Vault, arg: str) -> None:
    if not vault.check_password(getpass.getpass("Current master password: ")):
        print("That's not the current master password.")
        return
    vault.change_master_password(ask_new_master_password())
    print("Master password changed. The vault was re-encrypted with a new salt.")


def cmd_help(vault: Vault, arg: str) -> None:
    print(HELP)


COMMANDS = {
    "add": cmd_add,
    "get": cmd_get,
    "list": cmd_list,
    "delete": cmd_delete,
    "gen": cmd_gen,
    "passwd": cmd_passwd,
    "help": cmd_help,
}


def repl(vault: Vault) -> None:
    print(f"Unlocked. {len(vault.entries)} login(s) saved.\n")
    print(HELP)
    while True:
        try:
            line = input("\nvault> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        command, _, arg = line.partition(" ")
        command = command.lower()
        if not command:
            continue
        if command in ("quit", "exit", "q"):
            break
        handler = COMMANDS.get(command)
        if handler is None:
            print(f"Unknown command {command!r}. Type 'help' to see the commands.")
            continue
        try:
            handler(vault, arg.strip())
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
        except OSError as exc:
            print(f"Couldn't save the vault: {exc}")
    print("Vault locked. Bye!")


def unlock(path: Path) -> Vault:
    if not path.exists():
        print(f"No vault at {path} yet, so let's create one.")
        vault = Vault.create(path, ask_new_master_password())
        print("Vault created.")
        return vault
    print(f"Opening {path}")
    for _ in range(3):
        try:
            return Vault.load(path, getpass.getpass("Master password: "))
        except WrongPassword:
            print("Wrong master password.")
    sys.exit("Too many wrong attempts. (If you're sure the password is right, "
             "the vault file may have been modified.)")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def self_test() -> None:
    """Sanity checks you can run yourself: python3 vault.py --selftest"""

    def check(passed: bool, label: str) -> None:
        if not passed:
            sys.exit(f"FAIL  {label}")
        print(f"ok    {label}")

    loom = Loom(secrets.token_bytes(32))
    blocks = [secrets.token_bytes(BLOCK_SIZE) for _ in range(500)]
    check(all(loom.decrypt_block(loom.encrypt_block(b)) == b for b in blocks),
          "decrypt_block undoes encrypt_block (Loom is a permutation)")

    # Avalanche effect: flipping one input bit should flip about half the output bits.
    changed = 0
    for block in blocks:
        bit = secrets.randbelow(BLOCK_SIZE * 8)
        neighbor = bytearray(block)
        neighbor[bit // 8] ^= 1 << (bit % 8)
        a, b = loom.encrypt_block(block), loom.encrypt_block(bytes(neighbor))
        changed += sum(bin(x ^ y).count("1") for x, y in zip(a, b))
    avalanche = changed / (len(blocks) * BLOCK_SIZE * 8)
    check(0.45 < avalanche < 0.55,
          f"avalanche: flipping 1 input bit changes {avalanche:.1%} of output bits")

    enc_key, mac_key = secrets.token_bytes(32), secrets.token_bytes(32)
    message = b"correct horse battery staple " * 20
    nonce, ciphertext, tag = seal(enc_key, mac_key, message, b"header")
    check(unseal(enc_key, mac_key, nonce, ciphertext, tag, b"header") == message,
          "encrypt -> decrypt round-trip")
    check(seal(enc_key, mac_key, message, b"header")[1] != ciphertext,
          "fresh nonce: the same vault encrypts differently on every save")

    def rejected(*args: bytes) -> bool:
        try:
            unseal(*args)
        except WrongPassword:
            return True
        return False

    flipped = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    check(rejected(enc_key, mac_key, nonce, flipped, tag, b"header"),
          "a flipped ciphertext bit is caught")
    check(rejected(enc_key, mac_key, nonce, ciphertext, tag, b"HEADER"),
          "an edited header is caught")
    check(rejected(enc_key, secrets.token_bytes(32), nonce, ciphertext, tag, b"header"),
          "the wrong key is rejected")
    print("All self-tests passed.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="A simple password manager built on the Loom cipher.")
    parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT,
                        help="vault file to use (default: %(default)s)")
    parser.add_argument("--selftest", action="store_true",
                        help="run the cipher self-tests and exit")
    args = parser.parse_args()

    if args.selftest:
        self_test()
        return
    try:
        vault = unlock(args.vault.expanduser())
    except (VaultError, OSError) as exc:
        sys.exit(f"Error: {exc}")
    except (EOFError, KeyboardInterrupt):
        sys.exit("\nCancelled.")
    repl(vault)


if __name__ == "__main__":
    main()
