#!/usr/bin/env python3
"""Decrypt an encrypted Vaultwarden snapshot written by Backup-Vaultwarden.ps1.

Independent reference implementation of stage 2 (the KeePass plugin does the same in C#).
Use it to check a snapshot, or as an emergency restore path that needs neither KeePass
nor the Bitwarden CLI.

    python decrypt_snapshot.py SNAPSHOT_OR_FOLDER                 # check only, prints counts
    python decrypt_snapshot.py SNAPSHOT_OR_FOLDER --out vault.json # unencrypted Bitwarden JSON

WARNING: --out writes ALL passwords in plain text. Import the file into KeePassXC
(Database > Import > Bitwarden JSON) and delete it securely afterwards.

Requires: pip install cryptography
Supports PBKDF2-SHA256 accounts (Argon2id needs the optional package argon2-cffi).
"""
import argparse
import base64
import getpass
import glob
import hashlib
import hmac
import json
import os
import re
import sys

from cryptography.hazmat.primitives import hashes, padding as sympadding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class WrongPassword(Exception):
    pass


# The iteration count comes from the snapshot file. Limits keep a damaged or
# modified file from making the import run (almost) forever.
MIN_PBKDF2_ITERATIONS = 5000
MAX_PBKDF2_ITERATIONS = 10000000


# ----------------------------------------------------------------------------
# Key derivation
# ----------------------------------------------------------------------------

def derive_master_key(password, salt, kdf_type, iterations, memory=None, parallelism=None):
    salt_bytes = salt.strip().lower().encode("utf-8")
    pw = password.encode("utf-8")
    if kdf_type == 0:
        return hashlib.pbkdf2_hmac("sha256", pw, salt_bytes, iterations, 32)
    if kdf_type == 1:
        try:
            from argon2.low_level import hash_secret_raw, Type
        except ImportError:
            sys.exit("This account uses Argon2id. Install it with: pip install argon2-cffi")
        return hash_secret_raw(pw, hashlib.sha256(salt_bytes).digest(), time_cost=iterations,
                               memory_cost=(memory or 64) * 1024, parallelism=parallelism or 4,
                               hash_len=32, type=Type.ID)
    raise ValueError("Unknown KDF type %r" % kdf_type)


def hkdf_expand_one_block(prk, info):
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def stretch(master_key):
    return hkdf_expand_one_block(master_key, b"enc") + hkdf_expand_one_block(master_key, b"mac")


# ----------------------------------------------------------------------------
# EncStrings
# ----------------------------------------------------------------------------

def parse_enc(value):
    dot = value.find(".")
    if dot < 1 or dot > 2 or not value[:dot].isdigit():
        raise ValueError("unknown format of an encrypted value")
    enc_type = int(value[:dot])
    parts = value[dot + 1:].split("|")
    b64 = lambda x: base64.b64decode(x, validate=True)
    if enc_type == 2 and len(parts) == 3:
        return enc_type, b64(parts[0]), b64(parts[1]), b64(parts[2])
    if enc_type == 0 and len(parts) == 2:
        return enc_type, b64(parts[0]), b64(parts[1]), None
    if enc_type == 4 and len(parts) >= 1:
        return enc_type, None, b64(parts[0]), None
    raise ValueError("unsupported encrypted value (type %d)" % enc_type)


def decrypt_bytes(value, key):
    """key: 64 bytes (enc + mac) or 32 bytes (enc only)."""
    enc_type, iv, data, mac = parse_enc(value)
    if enc_type not in (0, 2):
        raise ValueError("unsupported symmetric type %d" % enc_type)
    enc_key, mac_key = key[:32], (key[32:] if len(key) == 64 else None)
    if enc_type == 0 and mac_key is not None:
        # Type 0 has no MAC. Accepting it under a key that has a MAC key would let a
        # modified snapshot bypass the integrity check.
        raise ValueError("unauthenticated value (type 0) is not accepted for this key")
    if enc_type == 2:
        if mac_key is None:
            raise ValueError("a MAC key is required")
        expected = hmac.new(mac_key, iv + data, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, mac):
            raise ValueError("MAC mismatch (wrong key or damaged data)")
    dec = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    padded = dec.update(data) + dec.finalize()
    unpadder = sympadding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def decrypt_string(value, key):
    if not value:
        return None
    return decrypt_bytes(value, key).decode("utf-8")


def decrypt_rsa(value, pkcs8_der):
    enc_type, _, data, _ = parse_enc(value)
    if enc_type != 4:
        raise ValueError("unsupported RSA type %d" % enc_type)
    private_key = serialization.load_der_private_key(pkcs8_der, password=None)
    return private_key.decrypt(
        data, asympadding.OAEP(mgf=asympadding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None))


# ----------------------------------------------------------------------------
# Snapshot
# ----------------------------------------------------------------------------

def resolve(path):
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "vaultwarden-snapshot-*.json")))
        # Prefer names with a timestamp; manual copies only if there is nothing else
        stamped = [f for f in files if re.match(r"vaultwarden-snapshot-\d{8}-\d{6}\.json$", os.path.basename(f))]
        files = stamped or files
        if not files:
            sys.exit("No vaultwarden-snapshot-*.json in " + path)
        return files[-1]
    return path


def decrypt_snapshot(doc, password):
    if doc.get("format") != "vaultwarden-encrypted-snapshot" or doc.get("version") != 1:
        raise ValueError("not a version 1 Vaultwarden snapshot")
    sync = doc["sync"]
    profile = sync["profile"]
    unlock = (sync.get("userDecryption") or {}).get("masterPasswordUnlock") or {}
    pre = doc.get("prelogin") or {}

    kdf = unlock.get("kdf") or {}
    kdf_type = kdf.get("kdfType", pre.get("kdf", 0))
    iterations = kdf.get("iterations") or pre.get("kdfIterations") or 600000
    memory = kdf.get("memory") or pre.get("kdfMemory")
    parallelism = kdf.get("parallelism") or pre.get("kdfParallelism")
    salt = unlock.get("salt") or doc.get("email") or profile.get("email")
    wrapped = profile.get("key") or unlock.get("masterKeyWrappedUserKey")

    if kdf_type == 0 and not (MIN_PBKDF2_ITERATIONS <= iterations <= MAX_PBKDF2_ITERATIONS):
        raise ValueError("implausible number of PBKDF2 iterations in the snapshot: %r" % iterations)
    if kdf_type == 1:
        iterations = kdf.get("iterations") or pre.get("kdfIterations") or 3
        if not (1 <= iterations <= 100 and 15 <= (memory or 64) <= 4096 and 1 <= (parallelism or 4) <= 64):
            raise ValueError("implausible Argon2id settings in the snapshot")
    master_key = derive_master_key(password, salt, kdf_type, iterations, memory, parallelism)
    wrap_type = parse_enc(wrapped)[0]
    wrapping_key = stretch(master_key) if wrap_type == 2 else master_key
    try:
        user_key = decrypt_bytes(wrapped, wrapping_key)
    except Exception:
        raise WrongPassword("The master password is wrong (or does not belong to this snapshot).")

    org_keys, orgs, private_key = {}, [], None
    for org in profile.get("organizations") or []:
        if org.get("status") not in (None, 2) or not org.get("key"):
            continue
        if private_key is None:
            private_key = decrypt_bytes(profile["privateKey"], user_key)
        org_keys[org["id"]] = decrypt_rsa(org["key"], private_key)
        orgs.append({"id": org["id"], "name": org.get("name")})

    folders = [{"id": f["id"], "name": decrypt_string(f["name"], user_key)}
               for f in sync.get("folders") or []]

    items = []
    for c in sync["ciphers"]:
        if c.get("deletedDate"):
            continue
        item = {"id": c["id"], "organizationId": c.get("organizationId"), "folderId": c.get("folderId"),
                "type": c["type"], "reprompt": c.get("reprompt", 0), "favorite": bool(c.get("favorite")),
                "collectionIds": c.get("collectionIds")}
        if c["type"] in (1, 2):
            owner = user_key
            if c.get("organizationId"):
                owner = org_keys[c["organizationId"]]
            key = decrypt_bytes(c["key"], owner) if c.get("key") else owner
            item["name"] = decrypt_string(c.get("name"), key)
            item["notes"] = decrypt_string(c.get("notes"), key)
            item["fields"] = [{"name": decrypt_string(f.get("name"), key),
                               "value": decrypt_string(f.get("value"), key),
                               "type": f.get("type") or 0} for f in c.get("fields") or []]
            if c["type"] == 1 and c.get("login"):
                lg = c["login"]
                uris = lg.get("uris") or ([{"uri": lg["uri"]}] if lg.get("uri") else [])
                item["login"] = {
                    "username": decrypt_string(lg.get("username"), key),
                    "password": decrypt_string(lg.get("password"), key),
                    "totp": decrypt_string(lg.get("totp"), key),
                    "uris": [{"match": None, "uri": decrypt_string(u["uri"], key)} for u in uris],
                }
            if c["type"] == 2:
                item["secureNote"] = {"type": 0}
        items.append(item)
    return {"encrypted": False, "folders": folders, "items": items}, orgs


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("snapshot", help="snapshot file, or the backup folder (newest snapshot)")
    ap.add_argument("--out", help="write unencrypted Bitwarden JSON to this file")
    ap.add_argument("--yes", action="store_true", help="do not ask before writing the unencrypted file")
    args = ap.parse_args()

    path = resolve(args.snapshot)
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    print("Snapshot:", path, "created", doc.get("createdUtc"))
    password = getpass.getpass("Master password: ")
    try:
        vault, orgs = decrypt_snapshot(doc, password)
    except WrongPassword as exc:
        sys.exit(str(exc))
    kinds = {}
    for it in vault["items"]:
        kinds[it["type"]] = kinds.get(it["type"], 0) + 1
    print("OK: %d items %s, %d folders, %d organizations" % (len(vault["items"]), kinds, len(vault["folders"]), len(orgs)))
    if args.out:
        if not args.yes:
            print("\n%s will contain ALL passwords in plain text. File permissions do not protect it on Windows,"
                  "\nand deleting it later does not wipe it from the disk. Prefer an encrypted drive." % args.out)
            if input("Type YES to write it: ").strip() != "YES":
                sys.exit("Nothing was written.")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        with os.fdopen(os.open(args.out, flags, 0o600), "w", encoding="utf-8") as fh:
            json.dump(vault, fh, ensure_ascii=False, indent=1)
        print("Wrote", args.out, "- contains ALL passwords in plain text, delete it after the import!")


if __name__ == "__main__":
    main()
