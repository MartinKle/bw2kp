using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using KeePassLib;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Serialization;
using VaultwardenSync;

/// <summary>
/// Tests merging decrypted vault data into a KeePass database (SyncEngine.Preview and
/// ApplyToDatabase) with an in-memory database. KeePass itself is not started.
/// </summary>
public static class MergeTest
{
    private const string TargetGroup = "Vaultwarden Sync";

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }

    private static void CheckEqual(object expected, object actual, string what)
    {
        string e = expected == null ? null : expected.ToString();
        string a = actual == null ? null : actual.ToString();
        if (e != a) throw new Exception(what + ": expected '" + e + "' but got '" + a + "'");
    }

    private static PwDatabase NewDatabase()
    {
        PwDatabase db = new PwDatabase();
        string path = Path.Combine(Path.GetTempPath(), "merge-test-" + Guid.NewGuid().ToString("N") + ".kdbx");
        db.New(IOConnectionInfo.FromPath(path), new CompositeKey()); // never saved
        return db;
    }

    private static SyncEngine NewEngine(PwDatabase db)
    {
        // The constructor of SyncConfiguration needs a running KeePass (plugin host). The merge
        // only reads the target group name, so an instance without constructor call is enough.
        SyncConfiguration config = (SyncConfiguration)FormatterServices.GetUninitializedObject(typeof(SyncConfiguration));
        config.TargetGroupName = TargetGroup;
        return new SyncEngine(config, db);
    }

    private static PwGroup FindGroup(PwGroup parent, string name)
    {
        foreach (PwGroup group in parent.Groups)
        {
            if (group.Name == name) return group;
        }
        return null;
    }

    private static PwEntry FindEntry(PwGroup group, string title)
    {
        foreach (PwEntry entry in group.Entries)
        {
            if (entry.Strings.ReadSafe(PwDefs.TitleField) == title) return entry;
        }
        foreach (PwGroup sub in group.Groups)
        {
            PwEntry found = FindEntry(sub, title);
            if (found != null) return found;
        }
        return null;
    }

    private static BwCipher FindCipher(VaultData data, string id)
    {
        foreach (BwCipher cipher in data.Ciphers)
        {
            if (cipher.id == id) return cipher;
        }
        throw new Exception("test data has no item " + id);
    }

    /// <summary>One scenario from the first import to the refusal of another account.</summary>
    public static void Scenario(string snapshotPath, string password)
    {
        PwDatabase db = NewDatabase();
        SyncEngine engine = NewEngine(db);
        VaultData data = new SnapshotSource(snapshotPath).Decrypt(password);

        // --- first import ---------------------------------------------------
        ImportPreview preview = engine.Preview(data);
        Check(!preview.TargetGroupExists, "the target group must not exist yet");
        CheckEqual(4, preview.Added, "preview: added");
        CheckEqual(2, preview.Skipped, "preview: skipped");
        CheckEqual(0, preview.Removed, "preview: removed");
        Check(FindGroup(db.RootGroup, TargetGroup) == null, "the preview must not create the target group");

        SyncResult result = engine.ApplyToDatabase(data);
        CheckEqual(4, result.Added, "first import: added");
        CheckEqual(2, result.Skipped, "first import: skipped");
        Check(result.DatabaseModified, "first import must modify the database");

        PwGroup target = FindGroup(db.RootGroup, TargetGroup);
        Check(target != null, "target group missing");
        PwGroup folder = FindGroup(target, "Work ä");
        Check(folder != null, "folder group missing");
        PwGroup org = FindGroup(target, "Family");
        Check(org != null, "organization group missing");
        Check(FindGroup(target, "Invited only") == null, "an unconfirmed organization must not get a group");

        PwEntry plain = FindEntry(folder, "Plain login");
        Check(plain != null, "'Plain login' must be in its folder");
        CheckEqual("alice", plain.Strings.ReadSafe(PwDefs.UserNameField), "user name");
        CheckEqual("p@ss €", plain.Strings.ReadSafe(PwDefs.PasswordField), "password");
        Check(plain.Strings.Get(PwDefs.PasswordField).IsProtected, "the password must be protected in memory");
        CheckEqual("https://a.example", plain.Strings.ReadSafe(PwDefs.UrlField), "URL");
        CheckEqual("a note\nwith umlauts äöü", plain.Strings.ReadSafe(PwDefs.NotesField).Replace("\r\n", "\n"), "notes");
        Check(plain.Strings.ReadSafe("otp").Contains("JBSWY3DPEHPK3PXP"), "TOTP secret missing");
        CheckEqual("1234", plain.Strings.ReadSafe("pin"), "custom field");
        CheckEqual("c-plain", plain.Strings.ReadSafe("VW_ID"), "item id");

        Check(FindEntry(org, "Org login") != null, "'Org login' must be in the organization group");
        Check(FindEntry(org, "Org note") != null, "'Org note' must be in the organization group");
        Check(FindEntry(target, "Item key login") != null, "'Item key login' missing");
        Check(FindEntry(db.RootGroup, "A card") == null, "cards must not be imported");
        Check(FindEntry(db.RootGroup, "Trashed") == null, "trashed items must not be imported");

        // --- same data again: nothing changes --------------------------------
        preview = engine.Preview(data);
        Check(preview.TargetGroupExists, "the target group exists now");
        CheckEqual(data.AccountId, preview.StoredAccountId, "account bound to the group");
        CheckEqual(data.SnapshotCreatedUtc, preview.LastSnapshotUtc, "snapshot time stored in the group");
        CheckEqual(0, preview.Added + preview.Updated + preview.Removed, "preview of unchanged data");
        CheckEqual(4, preview.Unchanged, "preview: unchanged");

        result = engine.ApplyToDatabase(data);
        CheckEqual(4, result.Unchanged, "second import: unchanged");
        Check(!result.DatabaseModified, "an import without changes must not modify the database");

        // --- a field added by the user survives, a changed password is updated --
        plain.Strings.Set("MyOwnField", new ProtectedString(false, "keep me"));
        FindCipher(data, "c-plain").login.password = "new password";

        preview = engine.Preview(data);
        CheckEqual(1, preview.Updated, "preview: updated");
        CheckEqual("Plain login", preview.UpdatedTitles[0], "preview: title of the updated entry");
        CheckEqual("p@ss €", plain.Strings.ReadSafe(PwDefs.PasswordField), "the preview must not change the entry");

        result = engine.ApplyToDatabase(data);
        CheckEqual(1, result.Updated, "third import: updated");
        CheckEqual(3, result.Unchanged, "third import: unchanged");
        CheckEqual("new password", plain.Strings.ReadSafe(PwDefs.PasswordField), "updated password");
        CheckEqual("keep me", plain.Strings.ReadSafe("MyOwnField"), "field added by the user");
        CheckEqual(1, plain.History.UCount, "the old state must be kept in the history");
        CheckEqual("p@ss €", plain.History.GetAt(0).Strings.ReadSafe(PwDefs.PasswordField), "password in the history");

        // --- a custom field removed in Vaultwarden disappears -----------------
        FindCipher(data, "c-plain").fields.Clear();
        result = engine.ApplyToDatabase(data);
        CheckEqual(1, result.Updated, "fourth import: updated");
        Check(plain.Strings.Get("pin") == null, "a field removed in Vaultwarden must be removed");
        CheckEqual("keep me", plain.Strings.ReadSafe("MyOwnField"), "field added by the user (after field removal)");

        // --- an item deleted in Vaultwarden goes to the recycle bin ------------
        data.Ciphers.Remove(FindCipher(data, "c-org"));
        preview = engine.Preview(data);
        CheckEqual(1, preview.Removed, "preview: removed");
        CheckEqual("Org login", preview.RemovedTitles[0], "preview: title of the removed entry");
        Check(FindEntry(org, "Org login") != null, "the preview must not remove the entry");

        result = engine.ApplyToDatabase(data);
        CheckEqual(1, result.Removed, "fifth import: removed");
        Check(FindEntry(target, "Org login") == null, "the removed entry must leave the target group");
        PwEntry binned = FindEntry(db.RootGroup, "Org login");
        Check(binned != null, "the removed entry must be kept in the recycle bin");
        Check(binned.ParentGroup.Uuid.Equals(db.RecycleBinUuid), "the removed entry must be in the recycle bin");

        // --- a snapshot without logins or notes removes nothing ----------------
        VaultData empty = new VaultData();
        empty.AccountId = data.AccountId;
        preview = engine.Preview(empty);
        Check(preview.RemovalSuppressed, "preview: an empty snapshot must not remove anything");
        CheckEqual(0, preview.Removed, "preview of an empty snapshot: removed");
        result = engine.ApplyToDatabase(empty);
        CheckEqual(0, result.Removed, "empty snapshot: removed");
        Check(FindEntry(target, "Plain login") != null, "entries must survive an empty snapshot");

        // --- another account is refused ----------------------------------------
        VaultData other = new SnapshotSource(snapshotPath).Decrypt(password);
        other.AccountId = "99999999-0000-0000-0000-000000000000";
        other.Ciphers.Clear();
        other.Ciphers.Add(new BwCipher { id = "x-1", type = 2, name = "Foreign note" });
        try
        {
            engine.ApplyToDatabase(other);
            throw new Exception("the data of another account was merged");
        }
        catch (InvalidOperationException)
        {
            // expected
        }
        Check(FindEntry(db.RootGroup, "Foreign note") == null, "nothing of the other account may be imported");
        Check(FindEntry(target, "Plain login") != null, "entries must survive the refused import");
    }
}
