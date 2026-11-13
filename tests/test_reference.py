#!/usr/bin/env python3
"""Checks the snapshot decryption against independently built test data.

The snapshot is built here with its own encryption code (written from the Bitwarden format
description), so the decryption in tools/decrypt_snapshot.py is not tested against itself.
The DER parser and the PBKDF2 / HKDF loops of src/VaultCrypto.cs are transcribed 1:1 below,
so that their logic is checked as well.

    python tests/test_reference.py          (needs: pip install cryptography)
"""
import base64
import hashlib
import hmac
import os
import sys

from cryptography.hazmat.primitives import hashes, padding as sympadding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asympadding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import decrypt_snapshot as ref  # noqa: E402

b64 = lambda b: base64.b64encode(b).decode()


# --------------------------------------------------------------------------
# Test-data builder (encrypting side)
# --------------------------------------------------------------------------

def enc2(plain, key64):
    iv = os.urandom(16)
    padder = sympadding.PKCS7(128).padder()
    data = padder.update(plain) + padder.finalize()
    e = Cipher(algorithms.AES(key64[:32]), modes.CBC(iv)).encryptor()
    ct = e.update(data) + e.finalize()
    mac = hmac.new(key64[32:], iv + ct, hashlib.sha256).digest()
    return "2.%s|%s|%s" % (b64(iv), b64(ct), b64(mac))


def enc2s(text, key64):
    return None if text is None else enc2(text.encode("utf-8"), key64)


def build_snapshot(password, email, iterations=5000):
    master = hashlib.pbkdf2_hmac("sha256", password.encode(), email.lower().encode(), iterations, 32)
    # HKDF-Expand according to RFC 5869 (T(1) = HMAC(PRK, info | 0x01))
    stretched = hmac.new(master, b"enc\x01", hashlib.sha256).digest() + hmac.new(master, b"mac\x01", hashlib.sha256).digest()

    user_key = os.urandom(64)
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pkcs8 = rsa_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
    org_key = os.urandom(64)
    org_key_enc = "4." + b64(rsa_key.public_key().encrypt(
        org_key, asympadding.OAEP(mgf=asympadding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)))
    item_key = os.urandom(64)

    def cipher(cid, ctype, name, name_key, **kw):
        c = {"id": cid, "type": ctype, "name": enc2s(name, name_key), "notes": None, "folderId": None,
             "organizationId": None, "key": None, "deletedDate": None, "login": None, "fields": [],
             "collectionIds": []}
        c.update(kw)
        return c

    ciphers = [
        cipher("c-plain", 1, "Plain login", user_key, folderId="f1",
               notes=enc2s("a note\nwith umlauts äöü", user_key),
               login={"username": enc2s("alice", user_key), "password": enc2s("p@ss €", user_key),
                      "totp": enc2s("JBSWY3DPEHPK3PXP", user_key), "uri": enc2s("https://a.example", user_key),
                      "uris": [{"uri": enc2s("https://a.example", user_key)}, {"uri": enc2s("https://b.example", user_key)}]},
               fields=[{"name": enc2s("pin", user_key), "value": enc2s("1234", user_key), "type": 1}]),
        # personal item with its own item key: name etc. are encrypted with the item key
        cipher("c-itemkey", 1, "Item key login", item_key, key=enc2(item_key, user_key),
               login={"username": enc2s("bob", item_key), "password": None, "totp": None, "uri": None, "uris": None}),
        # organization item
        cipher("c-org", 1, "Org login", org_key, organizationId="o1",
               login={"username": enc2s("carol", org_key), "password": enc2s("orgpw", org_key), "totp": None,
                      "uri": None, "uris": None}),
        # organization item with its own item key (protected by the organization key)
        cipher("c-org-itemkey", 2, "Org note", item_key, organizationId="o1", key=enc2(item_key, org_key),
               notes=enc2s("secret note", item_key)),
        cipher("c-trash", 1, "Trashed", user_key, deletedDate="2026-01-01T00:00:00Z",
               login={"username": None, "password": None, "totp": None, "uri": None, "uris": None}),
        cipher("c-card", 3, "A card", user_key),
    ]

    return {
        "format": "vaultwarden-encrypted-snapshot", "version": 1, "createdUtc": "2026-11-12T00:00:00Z",
        "server": "https://vault.example", "email": email,
        "prelogin": {"kdf": 0, "kdfIterations": iterations, "kdfMemory": None, "kdfParallelism": None},
        "sync": {
            "profile": {"email": email, "key": enc2(user_key, stretched), "privateKey": enc2(pkcs8, user_key),
                        "organizations": [{"id": "o1", "name": "Family", "key": org_key_enc, "status": 2},
                                          {"id": "o2", "name": "Invited only", "key": org_key_enc, "status": 0}]},
            "userDecryption": {"masterPasswordUnlock": {
                "kdf": {"iterations": iterations, "kdfType": 0, "memory": None, "parallelism": None},
                "masterKeyWrappedUserKey": enc2(user_key, stretched), "salt": email}},
            "folders": [{"id": "f1", "name": enc2s("Work ä", user_key)}],
            "ciphers": ciphers,
        },
    }, pkcs8


# --------------------------------------------------------------------------
# 1:1 transcriptions of the helpers in src/VaultCrypto.cs
# --------------------------------------------------------------------------

def cs_pbkdf2_sha256(password, salt, iterations, out_len):
    block_count = (out_len + 31) // 32
    out = b""
    for block in range(1, block_count + 1):
        first = salt + bytes([(block >> 24) & 255, (block >> 16) & 255, (block >> 8) & 255, block & 255])
        u = hmac.new(password, first, hashlib.sha256).digest()
        t = bytearray(u)
        for _ in range(1, iterations):
            u = hmac.new(password, u, hashlib.sha256).digest()
            for j in range(len(t)):
                t[j] ^= u[j]
        out += bytes(t)
    return out[:out_len]


def cs_read_length(data, pos):
    first = data[pos]; pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    assert 1 <= count <= 4 and pos + count <= len(data)
    length = 0
    for _ in range(count):
        length = (length << 8) | data[pos]; pos += 1
    return length, pos


def cs_enter_tag(data, pos, tag):
    assert pos < len(data) and data[pos] == tag, "unexpected structure"
    return cs_read_length(data, pos + 1)


def cs_skip_tag(data, pos, tag):
    length, pos = cs_enter_tag(data, pos, tag)
    assert pos + length <= len(data)
    return pos + length


def cs_read_integer(data, pos):
    length, pos = cs_enter_tag(data, pos, 0x02)
    assert pos + length <= len(data)
    return data[pos:pos + length], pos + length


def cs_trim(value):
    start = 0
    while start < len(value) - 1 and value[start] == 0:
        start += 1
    return value[start:]


def cs_pad_left(value, length):
    assert len(value) <= length
    return bytes(length - len(value)) + value


def cs_parse_pkcs8(der):
    pos = 0
    _, pos = cs_enter_tag(der, pos, 0x30)
    pos = cs_skip_tag(der, pos, 0x02)
    pos = cs_skip_tag(der, pos, 0x30)
    _, pos = cs_enter_tag(der, pos, 0x04)
    _, pos = cs_enter_tag(der, pos, 0x30)
    pos = cs_skip_tag(der, pos, 0x02)
    ints = []
    for _ in range(8):
        v, pos = cs_read_integer(der, pos)
        ints.append(v)
    n, e, d, p, q, dp, dq, iq = ints
    n, e = cs_trim(n), cs_trim(e)
    half = len(n) // 2
    return {"n": n, "e": e, "d": cs_pad_left(cs_trim(d), len(n)), "p": cs_pad_left(cs_trim(p), half),
            "q": cs_pad_left(cs_trim(q), half), "dp": cs_pad_left(cs_trim(dp), half),
            "dq": cs_pad_left(cs_trim(dq), half), "iq": cs_pad_left(cs_trim(iq), half)}


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------

def test_pbkdf2_matches_reference():
    for iterations in (1, 2, 1000):
        for out_len in (32, 64, 40):
            assert cs_pbkdf2_sha256(b"password", b"salt", iterations, out_len) == \
                hashlib.pbkdf2_hmac("sha256", b"password", b"salt", iterations, out_len)
    # PBKDF2-HMAC-SHA256 test vector (RFC 7914, section 11)
    assert cs_pbkdf2_sha256(b"passwd", b"salt", 1, 64).hex().startswith("55ac046e56e3089fec1691c22544b605")


def test_hkdf_expand_rfc5869_case_1_first_block():
    # RFC 5869, test case 1: T(1) = HMAC(PRK, info | 0x01)
    prk = bytes.fromhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    t1 = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    assert t1.hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"


def test_der_parser_matches_cryptography():
    for _ in range(40):  # many keys: also covers values with a leading zero byte / shorter primes
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        got = cs_parse_pkcs8(der)
        nums = key.private_numbers()
        half = 128
        assert int.from_bytes(got["n"], "big") == nums.public_numbers.n and len(got["n"]) == 256
        assert int.from_bytes(got["e"], "big") == nums.public_numbers.e
        assert int.from_bytes(got["d"], "big") == nums.d and len(got["d"]) == 256
        for name, expected in (("p", nums.p), ("q", nums.q), ("dp", nums.dmp1), ("dq", nums.dmq1), ("iq", nums.iqmp)):
            assert int.from_bytes(got[name], "big") == expected and len(got[name]) == half, name


def test_roundtrip_and_all_item_kinds():
    snap, _ = build_snapshot("correct horse", "Alice@Example.com")
    vault, orgs = ref.decrypt_snapshot(snap, "correct horse")
    items = {i["id"]: i for i in vault["items"]}
    assert set(items) == {"c-plain", "c-itemkey", "c-org", "c-org-itemkey", "c-card"}  # trash is dropped
    assert items["c-plain"]["name"] == "Plain login"
    assert items["c-plain"]["notes"] == "a note\nwith umlauts äöü"
    assert items["c-plain"]["login"]["password"] == "p@ss €"
    assert items["c-plain"]["login"]["totp"] == "JBSWY3DPEHPK3PXP"
    assert [u["uri"] for u in items["c-plain"]["login"]["uris"]] == ["https://a.example", "https://b.example"]
    assert items["c-plain"]["fields"] == [{"name": "pin", "value": "1234", "type": 1}]
    assert items["c-itemkey"]["login"]["username"] == "bob" and items["c-itemkey"]["login"]["password"] is None
    assert items["c-org"]["name"] == "Org login" and items["c-org"]["login"]["password"] == "orgpw"
    assert items["c-org-itemkey"]["notes"] == "secret note"
    assert "name" not in items["c-card"]  # unsupported types are passed on undecrypted
    assert vault["folders"] == [{"id": "f1", "name": "Work ä"}]
    assert [o["id"] for o in orgs] == ["o1"]  # the unconfirmed membership is ignored


def test_wrong_password_is_reported():
    snap, _ = build_snapshot("correct horse", "alice@example.com")
    try:
        ref.decrypt_snapshot(snap, "wrong")
    except ref.WrongPassword:
        return
    raise AssertionError("a wrong password was accepted")


def test_damaged_data_is_detected():
    snap, _ = build_snapshot("pw", "alice@example.com")
    c = snap["sync"]["ciphers"][0]
    iv, ct, mac = c["name"][2:].split("|")
    raw = bytearray(base64.b64decode(ct)); raw[0] ^= 1
    c["name"] = "2.%s|%s|%s" % (iv, b64(bytes(raw)), mac)
    try:
        ref.decrypt_snapshot(snap, "pw")
    except ValueError as exc:
        assert "MAC" in str(exc)
        return
    raise AssertionError("a modified value was accepted")


def test_value_without_mac_is_rejected():
    # A modified snapshot must not be able to switch a value to type 0 (no MAC)
    snap, _ = build_snapshot("pw", "alice@example.com")
    c = snap["sync"]["ciphers"][0]
    iv, ct, _mac = c["name"][2:].split("|")
    c["name"] = "0.%s|%s" % (iv, ct)
    try:
        ref.decrypt_snapshot(snap, "pw")
    except ValueError as exc:
        assert "type 0" in str(exc)
        return
    raise AssertionError("a value without MAC was accepted")


def test_implausible_iterations_are_rejected():
    for bad in (1, 4999, 10000001):
        snap, _ = build_snapshot("pw", "alice@example.com")
        snap["prelogin"]["kdfIterations"] = bad
        unlock = (snap["sync"].get("userDecryption") or {}).get("masterPasswordUnlock")
        if unlock and unlock.get("kdf"):
            unlock["kdf"]["iterations"] = bad
        try:
            ref.decrypt_snapshot(snap, "pw")
        except ValueError as exc:
            assert "iterations" in str(exc)
            continue
        raise AssertionError("%d iterations were accepted" % bad)


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("PASS", name)
            except Exception as exc:  # noqa: BLE001
                failed += 1
                print("FAIL", name, "-", repr(exc))
    sys.exit(1 if failed else 0)
