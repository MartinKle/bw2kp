using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;

namespace VaultwardenSync
{
    #region Snapshot file (JSON) models

    // Only the members that are needed are declared; everything else in the file is ignored.

    [DataContract]
    public class SnapDocument
    {
        [DataMember]
        public string format { get; set; }
        [DataMember]
        public int version { get; set; }
        [DataMember]
        public string createdUtc { get; set; }
        [DataMember]
        public string server { get; set; }
        [DataMember]
        public string email { get; set; }
        [DataMember]
        public SnapPrelogin prelogin { get; set; }
        [DataMember]
        public SnapSync sync { get; set; }
    }

    [DataContract]
    public class SnapPrelogin
    {
        [DataMember]
        public int? kdf { get; set; }
        [DataMember]
        public int? kdfIterations { get; set; }
    }

    [DataContract]
    public class SnapSync
    {
        [DataMember]
        public SnapProfile profile { get; set; }
        [DataMember]
        public List<SnapFolder> folders { get; set; }
        [DataMember]
        public List<SnapCipher> ciphers { get; set; }
        [DataMember]
        public SnapUserDecryption userDecryption { get; set; }
    }

    [DataContract]
    public class SnapUserDecryption
    {
        [DataMember]
        public SnapMasterPasswordUnlock masterPasswordUnlock { get; set; }
    }

    [DataContract]
    public class SnapMasterPasswordUnlock
    {
        [DataMember]
        public SnapKdf kdf { get; set; }
        [DataMember]
        public string masterKeyWrappedUserKey { get; set; }
        [DataMember]
        public string salt { get; set; }
    }

    [DataContract]
    public class SnapKdf
    {
        [DataMember]
        public int? kdfType { get; set; }
        [DataMember]
        public int? iterations { get; set; }
    }

    [DataContract]
    public class SnapProfile
    {
        [DataMember]
        public string email { get; set; }
        [DataMember]
        public string key { get; set; }
        [DataMember]
        public string privateKey { get; set; }
        [DataMember]
        public List<SnapOrganization> organizations { get; set; }
    }

    [DataContract]
    public class SnapOrganization
    {
        [DataMember]
        public string id { get; set; }
        [DataMember]
        public string name { get; set; }
        [DataMember]
        public string key { get; set; }
        [DataMember]
        public int? status { get; set; }
    }

    [DataContract]
    public class SnapFolder
    {
        [DataMember]
        public string id { get; set; }
        [DataMember]
        public string name { get; set; }
    }

    [DataContract]
    public class SnapCipher
    {
        [DataMember]
        public string id { get; set; }
        [DataMember]
        public string folderId { get; set; }
        [DataMember]
        public string organizationId { get; set; }
        [DataMember]
        public int type { get; set; }
        [DataMember]
        public string name { get; set; }
        [DataMember]
        public string notes { get; set; }
        [DataMember]
        public string key { get; set; }
        [DataMember]
        public string deletedDate { get; set; }
        [DataMember]
        public SnapLogin login { get; set; }
        [DataMember]
        public List<SnapField> fields { get; set; }
    }

    [DataContract]
    public class SnapLogin
    {
        [DataMember]
        public string username { get; set; }
        [DataMember]
        public string password { get; set; }
        [DataMember]
        public string totp { get; set; }
        [DataMember]
        public string uri { get; set; }
        [DataMember]
        public List<SnapUri> uris { get; set; }
    }

    [DataContract]
    public class SnapUri
    {
        [DataMember]
        public string uri { get; set; }
    }

    [DataContract]
    public class SnapField
    {
        [DataMember]
        public string name { get; set; }
        [DataMember]
        public string value { get; set; }
        [DataMember]
        public int? type { get; set; }
    }

    #endregion

    /// <summary>
    /// Stage 2: reads an encrypted snapshot written by Backup-Vaultwarden.ps1, decrypts it with the
    /// master password and returns the same VaultData that the live sync produces, so the rest of
    /// the sync (merge into KeePass, history, recycle bin) is shared. No network and no
    /// Bitwarden CLI is involved. Does not touch the KeePass database, so it may run on a worker thread.
    /// </summary>
    public sealed class SnapshotSource
    {
        public const string SnapshotFormat = "vaultwarden-encrypted-snapshot";
        public const string SnapshotFilePattern = "vaultwarden-snapshot-*.json";

        // The iteration count comes from the snapshot file. Limits keep a damaged or
        // modified file from making the import run (almost) forever.
        public const int MinPbkdf2Iterations = 5000;
        public const int MaxPbkdf2Iterations = 10000000;

        private readonly string _path;

        public event Action<string> OnLogMessage;

        public SnapshotSource(string pathOrFolder)
        {
            _path = pathOrFolder;
        }

        private void Log(string message)
        {
            Action<string> handler = OnLogMessage;
            if (handler == null) return;
            try
            {
                handler(message);
            }
            catch (Exception)
            {
                // Logging must never abort the import
            }
        }

        /// <summary>
        /// Returns the snapshot file. A folder stands for the newest snapshot in it.
        /// </summary>
        public static string ResolvePath(string pathOrFolder)
        {
            string path = (pathOrFolder ?? string.Empty).Trim().Trim('"');
            if (path.Length == 0) throw new InvalidOperationException("Please select a snapshot file or the backup folder.");

            if (Directory.Exists(path))
            {
                string newest = null;
                foreach (string file in Directory.GetFiles(path, SnapshotFilePattern))
                {
                    // The names contain a UTC timestamp, so the newest one sorts last
                    if (newest == null || string.CompareOrdinal(Path.GetFileName(file), Path.GetFileName(newest)) > 0)
                    {
                        newest = file;
                    }
                }
                if (newest == null)
                {
                    throw new FileNotFoundException("The folder does not contain a " + SnapshotFilePattern + " file.");
                }
                return newest;
            }

            if (!File.Exists(path)) throw new FileNotFoundException("The snapshot file was not found: " + path);
            return path;
        }

        private static SnapDocument ReadDocument(string file)
        {
            SnapDocument doc;
            try
            {
                byte[] bytes = File.ReadAllBytes(file);
                DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(SnapDocument));
                using (MemoryStream stream = new MemoryStream(bytes))
                {
                    doc = (SnapDocument)serializer.ReadObject(stream);
                }
            }
            catch (SerializationException ex)
            {
                throw new InvalidDataException("The file is not a valid snapshot: " + ex.Message);
            }

            if (doc == null || doc.format != SnapshotFormat)
            {
                throw new InvalidDataException("The file is not a Vaultwarden snapshot (unknown format).");
            }
            if (doc.version != 1)
            {
                throw new InvalidDataException("Unsupported snapshot version " + doc.version + ". Please update the plugin.");
            }
            if (doc.sync == null || doc.sync.profile == null || doc.sync.ciphers == null)
            {
                throw new InvalidDataException("The snapshot is incomplete (no profile or items).");
            }
            return doc;
        }

        /// <summary>
        /// Decrypts the snapshot. Throws WrongPasswordException for a wrong master password.
        /// Any other failure aborts the import, so that nothing in KeePass is changed or removed
        /// on the basis of partly decrypted data.
        /// </summary>
        public VaultData Decrypt(string masterPassword)
        {
            if (string.IsNullOrEmpty(masterPassword)) throw new ArgumentException("The master password is empty.", "masterPassword");

            string file = ResolvePath(_path);
            Log("Reading snapshot: " + file);
            SnapDocument doc = ReadDocument(file);
            Log(string.Format("Snapshot of {0} created {1} (UTC).", doc.server, doc.createdUtc));

            SnapProfile profile = doc.sync.profile;
            SnapMasterPasswordUnlock unlock = null;
            if (doc.sync.userDecryption != null) unlock = doc.sync.userDecryption.masterPasswordUnlock;

            // Key derivation settings: the account's own settings first, then the prelogin response
            int kdfType = 0;
            int iterations = 600000;
            if (doc.prelogin != null)
            {
                kdfType = doc.prelogin.kdf ?? kdfType;
                iterations = doc.prelogin.kdfIterations ?? iterations;
            }
            if (unlock != null && unlock.kdf != null)
            {
                kdfType = unlock.kdf.kdfType ?? kdfType;
                iterations = unlock.kdf.iterations ?? iterations;
            }
            if (kdfType != 0)
            {
                throw new NotSupportedException(
                    "This account derives its key with Argon2id. Importing snapshots is only supported for PBKDF2-SHA256 so far.");
            }

            if (iterations < MinPbkdf2Iterations || iterations > MaxPbkdf2Iterations)
            {
                throw new InvalidDataException(
                    "The snapshot contains an implausible number of PBKDF2 iterations (" + iterations + ").");
            }

            string salt = (unlock != null && !string.IsNullOrEmpty(unlock.salt)) ? unlock.salt : (doc.email ?? profile.email);
            string wrappedUserKey = !string.IsNullOrEmpty(profile.key)
                ? profile.key
                : (unlock != null ? unlock.masterKeyWrappedUserKey : null);
            if (string.IsNullOrEmpty(wrappedUserKey))
            {
                throw new InvalidDataException("The snapshot does not contain the encrypted user key.");
            }

            byte[] masterKey = null;
            byte[] privateKey = null;
            SymmetricKey userKey = null;
            Dictionary<string, SymmetricKey> orgKeys = new Dictionary<string, SymmetricKey>();

            try
            {
                Log(string.Format("Deriving the master key ({0} PBKDF2 iterations)...", iterations));
                masterKey = VaultCrypto.DeriveMasterKey(masterPassword, salt, iterations);

                Log("Unlocking the vault key...");
                userKey = VaultCrypto.UnwrapUserKey(wrappedUserKey, masterKey);
                Log("Master password accepted.");

                VaultData data = new VaultData();

                // Organization keys (RSA, protected by the user's private key)
                if (profile.organizations != null)
                {
                    foreach (SnapOrganization org in profile.organizations)
                    {
                        if (org == null || string.IsNullOrEmpty(org.id) || string.IsNullOrEmpty(org.key)) continue;
                        // Only confirmed memberships (status 2) can decrypt anything
                        if (org.status.HasValue && org.status.Value != 2) continue;

                        try
                        {
                            if (privateKey == null)
                            {
                                if (string.IsNullOrEmpty(profile.privateKey))
                                {
                                    throw new InvalidDataException("The snapshot does not contain the private key.");
                                }
                                privateKey = VaultCrypto.DecryptBytes(profile.privateKey, userKey);
                            }
                            byte[] rawOrgKey = VaultCrypto.DecryptRsa(org.key, privateKey);
                            try
                            {
                                orgKeys[org.id] = new SymmetricKey(rawOrgKey);
                            }
                            finally
                            {
                                Array.Clear(rawOrgKey, 0, rawOrgKey.Length);
                            }
                        }
                        catch (Exception ex)
                        {
                            throw new InvalidDataException("The key of the organization '" + org.name + "' cannot be decrypted: " + ex.Message, ex);
                        }

                        data.Organizations.Add(new BwOrganization { id = org.id, name = org.name });
                    }
                }

                // Folders
                if (doc.sync.folders != null)
                {
                    foreach (SnapFolder folder in doc.sync.folders)
                    {
                        if (folder == null || string.IsNullOrEmpty(folder.id)) continue;

                        string folderName;
                        try
                        {
                            folderName = VaultCrypto.DecryptString(folder.name, userKey);
                        }
                        catch (Exception ex)
                        {
                            throw new InvalidDataException("A folder name cannot be decrypted: " + ex.Message, ex);
                        }
                        data.Folders.Add(new BwFolder { id = folder.id, name = folderName });
                    }
                }

                // Items
                int total = doc.sync.ciphers.Count;
                Log(string.Format("Decrypting {0} items...", total));
                foreach (SnapCipher snap in doc.sync.ciphers)
                {
                    if (snap == null || string.IsNullOrEmpty(snap.id)) continue;

                    // Items in the Bitwarden trash are treated as deleted, like the live sync does
                    if (!string.IsNullOrEmpty(snap.deletedDate)) continue;

                    try
                    {
                        data.Ciphers.Add(DecryptCipher(snap, userKey, orgKeys));
                    }
                    catch (Exception ex)
                    {
                        throw new InvalidDataException("Item " + snap.id + " cannot be decrypted: " + ex.Message, ex);
                    }
                }

                Log(string.Format("Decrypted {0} folders, {1} items and {2} organizations.",
                    data.Folders.Count, data.Ciphers.Count, data.Organizations.Count));
                return data;
            }
            finally
            {
                if (masterKey != null) Array.Clear(masterKey, 0, masterKey.Length);
                if (privateKey != null) Array.Clear(privateKey, 0, privateKey.Length);
                if (userKey != null) userKey.Clear();
                foreach (SymmetricKey key in orgKeys.Values)
                {
                    key.Clear();
                }
            }
        }

        private static BwCipher DecryptCipher(SnapCipher snap, SymmetricKey userKey, Dictionary<string, SymmetricKey> orgKeys)
        {
            BwCipher cipher = new BwCipher();
            cipher.id = snap.id;
            cipher.folderId = snap.folderId;
            cipher.organizationId = snap.organizationId;
            cipher.type = snap.type;

            // Only logins (1) and secure notes (2) are imported. Other types are passed on
            // without being decrypted, so that they are counted as skipped.
            if (snap.type != 1 && snap.type != 2) return cipher;

            SymmetricKey ownerKey = userKey;
            if (!string.IsNullOrEmpty(snap.organizationId))
            {
                if (!orgKeys.TryGetValue(snap.organizationId, out ownerKey))
                {
                    throw new InvalidDataException("the organization key is not available");
                }
            }

            // Newer items carry their own key, which is protected by the owner's key
            SymmetricKey itemKey = ownerKey;
            byte[] rawItemKey = null;
            try
            {
                if (!string.IsNullOrEmpty(snap.key))
                {
                    rawItemKey = VaultCrypto.DecryptBytes(snap.key, ownerKey);
                    itemKey = new SymmetricKey(rawItemKey);
                }

                cipher.name = VaultCrypto.DecryptString(snap.name, itemKey);
                cipher.notes = VaultCrypto.DecryptString(snap.notes, itemKey);

                if (snap.type == 1 && snap.login != null)
                {
                    BwLogin login = new BwLogin();
                    login.username = VaultCrypto.DecryptString(snap.login.username, itemKey);
                    login.password = VaultCrypto.DecryptString(snap.login.password, itemKey);
                    login.totp = VaultCrypto.DecryptString(snap.login.totp, itemKey);
                    login.uris = new List<BwUri>();

                    if (snap.login.uris != null && snap.login.uris.Count > 0)
                    {
                        foreach (SnapUri uri in snap.login.uris)
                        {
                            if (uri == null) continue;
                            login.uris.Add(new BwUri { uri = VaultCrypto.DecryptString(uri.uri, itemKey) });
                        }
                    }
                    else if (!string.IsNullOrEmpty(snap.login.uri))
                    {
                        login.uris.Add(new BwUri { uri = VaultCrypto.DecryptString(snap.login.uri, itemKey) });
                    }

                    cipher.login = login;
                }

                if (snap.fields != null && snap.fields.Count > 0)
                {
                    cipher.fields = new List<BwField>();
                    foreach (SnapField field in snap.fields)
                    {
                        if (field == null) continue;
                        BwField decrypted = new BwField();
                        decrypted.name = VaultCrypto.DecryptString(field.name, itemKey);
                        decrypted.value = VaultCrypto.DecryptString(field.value, itemKey);
                        decrypted.type = field.type ?? 0;
                        cipher.fields.Add(decrypted);
                    }
                }
            }
            finally
            {
                if (itemKey != ownerKey) itemKey.Clear();
                if (rawItemKey != null) Array.Clear(rawItemKey, 0, rawItemKey.Length);
            }

            return cipher;
        }
    }
}
