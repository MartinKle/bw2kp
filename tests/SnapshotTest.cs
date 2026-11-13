using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using VaultwardenSync;

/// <summary>
/// Tests the C# side of stage 2 (VaultCrypto and SnapshotSource) without KeePass:
///   SnapshotTest.exe [snapshot file or folder] [expected.json]
/// Exit code 0 = all tests passed.
/// </summary>
public static class SnapshotTest
{
    private static int _failed;

    public static int Main(string[] args)
    {
        if (args.Length != 2)
        {
            Console.WriteLine("Usage: SnapshotTest.exe <snapshot file or folder> <expected.json>");
            return 2;
        }

        string snapshotPath = args[0];
        Dictionary<string, object> expected;
        try
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            serializer.MaxJsonLength = int.MaxValue;
            expected = (Dictionary<string, object>)serializer.DeserializeObject(File.ReadAllText(args[1], Encoding.UTF8));
        }
        catch (Exception ex)
        {
            Console.WriteLine("Cannot read " + args[1] + ": " + ex.Message);
            return 2;
        }
        string password = (string)expected["password"];

        Run("PBKDF2-HMAC-SHA256 test vectors", delegate { TestPbkdf2(); });
        Run("Value without MAC is rejected under a key with MAC key", delegate { TestType0Rejected(); });
        Run("Snapshot decrypts to the expected content", delegate { TestDecrypt(snapshotPath, password, expected); });
        Run("Wrong master password is reported", delegate { TestWrongPassword(snapshotPath, password); });
        Run("Modified value is detected", delegate { TestTamper(snapshotPath, password); });
        Run("Implausible iteration count is rejected", delegate { TestIterations(snapshotPath, password); });
        Run("Merge into a KeePass database (preview, import, update, removal, other account)", delegate { MergeTest.Scenario(snapshotPath, password); });

        Console.WriteLine(_failed == 0 ? "ALL TESTS PASSED" : (_failed + " TEST(S) FAILED"));
        return _failed == 0 ? 0 : 1;
    }

    private static void Run(string name, Action test)
    {
        try
        {
            test();
            Console.WriteLine("PASS " + name);
        }
        catch (Exception ex)
        {
            _failed++;
            Console.WriteLine("FAIL " + name + " - " + ex.GetType().Name + ": " + ex.Message);
        }
    }

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

    private static string Hex(byte[] bytes)
    {
        StringBuilder sb = new StringBuilder();
        foreach (byte b in bytes) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    private static void TestPbkdf2()
    {
        byte[] pw = Encoding.ASCII.GetBytes("password");
        byte[] salt = Encoding.ASCII.GetBytes("salt");
        CheckEqual("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b", Hex(VaultCrypto.Pbkdf2Sha256(pw, salt, 1, 32)), "1 iteration");
        CheckEqual("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43", Hex(VaultCrypto.Pbkdf2Sha256(pw, salt, 2, 32)), "2 iterations");
        CheckEqual("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a", Hex(VaultCrypto.Pbkdf2Sha256(pw, salt, 4096, 32)), "4096 iterations");
        CheckEqual(
            "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9",
            Hex(VaultCrypto.Pbkdf2Sha256(Encoding.ASCII.GetBytes("passwordPASSWORDpassword"),
                Encoding.ASCII.GetBytes("saltSALTsaltSALTsaltSALTsaltSALTsalt"), 4096, 40)),
            "two output blocks");
    }

    private static void TestType0Rejected()
    {
        SymmetricKey key = new SymmetricKey(new byte[64]);
        string value = "0." + Convert.ToBase64String(new byte[16]) + "|" + Convert.ToBase64String(new byte[16]);
        try
        {
            VaultCrypto.DecryptBytes(value, key);
        }
        catch (CryptographicException ex)
        {
            Check(ex.Message.Contains("type 0"), "unexpected message: " + ex.Message);
            return;
        }
        throw new Exception("a value without MAC was accepted");
    }

    private static void TestDecrypt(string snapshotPath, string password, Dictionary<string, object> expected)
    {
        VaultData data = new SnapshotSource(snapshotPath).Decrypt(password);

        CheckEqual(expected["accountId"], data.AccountId, "account id");
        CheckEqual(expected["email"], data.AccountEmail, "account e-mail");
        CheckEqual(expected["itemCount"], data.Ciphers.Count, "number of items (trash excluded)");

        Dictionary<string, object> folders = (Dictionary<string, object>)expected["folders"];
        CheckEqual(folders.Count, data.Folders.Count, "number of folders");
        foreach (BwFolder folder in data.Folders)
        {
            CheckEqual(folders[folder.id], folder.name, "folder " + folder.id);
        }

        Dictionary<string, object> orgs = (Dictionary<string, object>)expected["organizations"];
        CheckEqual(orgs.Count, data.Organizations.Count, "number of organizations");
        foreach (BwOrganization org in data.Organizations)
        {
            CheckEqual(orgs[org.id], org.name, "organization " + org.id);
        }

        Dictionary<string, object> items = (Dictionary<string, object>)expected["items"];
        int compared = 0;
        foreach (BwCipher cipher in data.Ciphers)
        {
            if (cipher.type != 1 && cipher.type != 2)
            {
                Check(cipher.name == null, "item " + cipher.id + " of an unsupported type must not be decrypted");
                continue;
            }

            Check(items.ContainsKey(cipher.id), "unexpected item " + cipher.id);
            Dictionary<string, object> item = (Dictionary<string, object>)items[cipher.id];
            string id = "item " + cipher.id + " ";

            CheckEqual(item["name"], cipher.name, id + "name");
            CheckEqual(item["notes"], cipher.notes, id + "notes");
            CheckEqual(item["organizationId"], cipher.organizationId, id + "organization");
            CheckEqual(item["folderId"], cipher.folderId, id + "folder");

            BwLogin login = cipher.login;
            CheckEqual(item["username"], login == null ? null : login.username, id + "username");
            CheckEqual(item["password"], login == null ? null : login.password, id + "password");
            CheckEqual(item["totp"], login == null ? null : login.totp, id + "totp");

            object[] uris = (object[])item["uris"];
            int uriCount = (login == null || login.uris == null) ? 0 : login.uris.Count;
            CheckEqual(uris.Length, uriCount, id + "number of URIs");
            for (int i = 0; i < uris.Length; i++)
            {
                CheckEqual(uris[i], login.uris[i].uri, id + "URI " + i);
            }

            object[] fields = (object[])item["fields"];
            int fieldCount = cipher.fields == null ? 0 : cipher.fields.Count;
            CheckEqual(fields.Length, fieldCount, id + "number of fields");
            for (int i = 0; i < fields.Length; i++)
            {
                object[] field = (object[])fields[i];
                CheckEqual(field[0], cipher.fields[i].name, id + "field name " + i);
                CheckEqual(field[1], cipher.fields[i].value, id + "field value " + i);
                CheckEqual(field[2], cipher.fields[i].type, id + "field type " + i);
            }
            compared++;
        }
        CheckEqual(items.Count, compared, "number of logins and notes");
    }

    private static void TestWrongPassword(string snapshotPath, string password)
    {
        try
        {
            new SnapshotSource(snapshotPath).Decrypt(password + "x");
        }
        catch (WrongPasswordException)
        {
            return;
        }
        throw new Exception("a wrong password was accepted");
    }

    private static void TestTamper(string snapshotPath, string password)
    {
        // Flip one character inside the first encrypted item name
        string source = SnapshotSource.ResolvePath(snapshotPath);
        string text = File.ReadAllText(source, Encoding.UTF8);
        int name = text.IndexOf("\"name\"", text.IndexOf("\"c-plain\""), StringComparison.Ordinal);
        int start = text.IndexOf("|", name, StringComparison.Ordinal) + 1; // start of the data part
        char original = text[start + 2];
        char changed = original == 'A' ? 'B' : 'A';
        string modified = text.Substring(0, start + 2) + changed + text.Substring(start + 3);

        string target = Path.Combine(Path.GetTempPath(), "snapshot-test-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(target, modified, new UTF8Encoding(false));
        try
        {
            new SnapshotSource(target).Decrypt(password);
        }
        catch (InvalidDataException ex)
        {
            Check(ex.Message.Contains("c-plain"), "unexpected message: " + ex.Message);
            return;
        }
        finally
        {
            File.Delete(target);
        }
        throw new Exception("a modified value was accepted");
    }

    private static void TestIterations(string snapshotPath, string password)
    {
        string source = SnapshotSource.ResolvePath(snapshotPath);
        string text = File.ReadAllText(source, Encoding.UTF8);
        // Both writers of the test data are covered: Python ("x": 5000) and the backup script ("x":5000)
        string modified = text.Replace("\"iterations\": 5000", "\"iterations\": 1").Replace("\"iterations\":5000", "\"iterations\":1")
                              .Replace("\"kdfIterations\": 5000", "\"kdfIterations\": 1").Replace("\"kdfIterations\":5000", "\"kdfIterations\":1");
        Check(modified != text, "the test data does not contain the iteration count");

        string target = Path.Combine(Path.GetTempPath(), "snapshot-test-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(target, modified, new UTF8Encoding(false));
        try
        {
            new SnapshotSource(target).Decrypt(password);
        }
        catch (InvalidDataException ex)
        {
            Check(ex.Message.Contains("iterations"), "unexpected message: " + ex.Message);
            return;
        }
        finally
        {
            File.Delete(target);
        }
        throw new Exception("an implausible iteration count was accepted");
    }
}
