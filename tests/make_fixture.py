#!/usr/bin/env python3
"""Writes test data for the C# and PowerShell tests into a folder.

    python tests/make_fixture.py <folder>

  <folder>/snapshot/vaultwarden-snapshot-20261112-000000.json   a finished snapshot
  <folder>/server/sync.json, prelogin.json                      what the mock server returns
  <folder>/expected.json                                        password and decrypted content
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_reference as t  # noqa: E402

PASSWORD = "correct horse battery staple äöü"
EMAIL = "Alice@Example.com"


def main():
    out = sys.argv[1]
    snap, _ = t.build_snapshot(PASSWORD, EMAIL)
    vault, orgs = t.ref.decrypt_snapshot(snap, PASSWORD)

    for sub in ("snapshot", "server"):
        os.makedirs(os.path.join(out, sub), exist_ok=True)

    def write(rel, obj):
        with open(os.path.join(out, rel), "w", encoding="utf-8") as fh:
            json.dump(obj, fh, ensure_ascii=False)

    write(os.path.join("snapshot", "vaultwarden-snapshot-20261112-000000.json"), snap)
    write(os.path.join("server", "sync.json"), snap["sync"])
    write(os.path.join("server", "prelogin.json"), snap["prelogin"])

    items = {}
    for it in vault["items"]:
        if it["type"] not in (1, 2):
            continue
        login = it.get("login") or {}
        items[it["id"]] = {
            "type": it["type"],
            "name": it.get("name"),
            "notes": it.get("notes"),
            "username": login.get("username"),
            "password": login.get("password"),
            "totp": login.get("totp"),
            "uris": [u["uri"] for u in login.get("uris") or []],
            "fields": [[f["name"], f["value"], f["type"]] for f in it.get("fields") or []],
            "organizationId": it.get("organizationId"),
            "folderId": it.get("folderId"),
        }
    write("expected.json", {
        "password": PASSWORD,
        "email": EMAIL,
        "accountId": snap["sync"]["profile"]["id"],
        "itemCount": len(vault["items"]),
        "items": items,
        "folders": {f["id"]: f["name"] for f in vault["folders"]},
        "organizations": {o["id"]: o["name"] for o in orgs},
    })
    print("Fixture written to", out)


if __name__ == "__main__":
    main()
