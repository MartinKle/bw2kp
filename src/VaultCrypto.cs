using System;
using System.Security.Cryptography;
using System.Text;

namespace VaultwardenSync
{
    /// <summary>
    /// The master password does not match the snapshot (the user key cannot be decrypted).
    /// </summary>
    public class WrongPasswordException : Exception
    {
        public WrongPasswordException(string message) : base(message)
        {
        }
    }

    /// <summary>
    /// The authentication code (MAC) of an encrypted value is wrong: wrong key or damaged data.
    /// </summary>
    public class MacMismatchException : CryptographicException
    {
        public MacMismatchException()
            : base("The authentication code of an encrypted value does not match (wrong key or damaged data).")
        {
        }
    }

    /// <summary>
    /// An AES-256 encryption key plus, for current keys, the HMAC-SHA256 key.
    /// </summary>
    public sealed class SymmetricKey
    {
        public readonly byte[] EncKey;
        public readonly byte[] MacKey; // null for legacy 32-byte keys

        public SymmetricKey(byte[] enc, byte[] mac)
        {
            if (enc == null || enc.Length != 32) throw new CryptographicException("Invalid encryption key length.");
            if (mac != null && mac.Length != 32) throw new CryptographicException("Invalid MAC key length.");
            EncKey = enc;
            MacKey = mac;
        }

        /// <summary>
        /// Builds a key from its serialized form: 64 bytes (enc + mac) or 32 bytes (enc only).
        /// </summary>
        public SymmetricKey(byte[] raw)
        {
            if (raw == null) throw new ArgumentNullException("raw");

            if (raw.Length == 64)
            {
                EncKey = new byte[32];
                MacKey = new byte[32];
                Buffer.BlockCopy(raw, 0, EncKey, 0, 32);
                Buffer.BlockCopy(raw, 32, MacKey, 0, 32);
            }
            else if (raw.Length == 32)
            {
                EncKey = (byte[])raw.Clone();
                MacKey = null;
            }
            else
            {
                throw new CryptographicException("Unexpected key length (" + raw.Length + " bytes).");
            }
        }

        public void Clear()
        {
            Array.Clear(EncKey, 0, EncKey.Length);
            if (MacKey != null) Array.Clear(MacKey, 0, MacKey.Length);
        }
    }

    /// <summary>
    /// The cryptography of the Bitwarden / Vaultwarden vault format, using only .NET Framework classes:
    ///   master key   = PBKDF2-HMAC-SHA256(password, e-mail as salt)
    ///   stretched    = HKDF-Expand(master key, "enc") + HKDF-Expand(master key, "mac")
    ///   user key     = decrypt(profile.key, stretched key)
    ///   private key  = decrypt(profile.privateKey, user key)           (RSA, PKCS#8)
    ///   org key      = RSA-OAEP-SHA1 decrypt(organization.key, private key)
    ///   item values  = AES-256-CBC + HMAC-SHA256 ("2.iv|data|mac"), with the item key if the item has one
    /// </summary>
    public static class VaultCrypto
    {
        private sealed class EncString
        {
            public int Type;
            public byte[] Iv;
            public byte[] Data;
            public byte[] Mac;
        }

        #region Key derivation

        public static byte[] DeriveMasterKey(string password, string salt, int iterations)
        {
            if (string.IsNullOrEmpty(password)) throw new ArgumentException("The master password is empty.", "password");
            if (string.IsNullOrEmpty(salt)) throw new ArgumentException("The salt (e-mail address) is empty.", "salt");
            if (iterations < 1) throw new ArgumentException("Invalid number of KDF iterations.", "iterations");

            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt.Trim().ToLowerInvariant());
            try
            {
                return Pbkdf2Sha256(passwordBytes, saltBytes, iterations, 32);
            }
            finally
            {
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
            }
        }

        public static SymmetricKey StretchMasterKey(byte[] masterKey)
        {
            return new SymmetricKey(HkdfExpandOneBlock(masterKey, "enc"), HkdfExpandOneBlock(masterKey, "mac"));
        }

        /// <summary>
        /// HKDF-Expand (RFC 5869) with SHA-256 for an output of exactly one block (32 bytes).
        /// </summary>
        private static byte[] HkdfExpandOneBlock(byte[] prk, string info)
        {
            byte[] infoBytes = Encoding.UTF8.GetBytes(info);
            byte[] input = new byte[infoBytes.Length + 1];
            Buffer.BlockCopy(infoBytes, 0, input, 0, infoBytes.Length);
            input[infoBytes.Length] = 1;

            using (HMACSHA256 hmac = new HMACSHA256(prk))
            {
                return hmac.ComputeHash(input);
            }
        }

        /// <summary>
        /// PBKDF2 with HMAC-SHA256 (RFC 8018). Written out so that it does not depend on the
        /// .NET Framework version (Rfc2898DeriveBytes only supports SHA-256 since 4.7.2).
        /// </summary>
        public static byte[] Pbkdf2Sha256(byte[] password, byte[] salt, int iterations, int outputLength)
        {
            int blockCount = (outputLength + 31) / 32;
            byte[] output = new byte[blockCount * 32];

            using (HMACSHA256 hmac = new HMACSHA256(password))
            {
                for (int block = 1; block <= blockCount; block++)
                {
                    byte[] first = new byte[salt.Length + 4];
                    Buffer.BlockCopy(salt, 0, first, 0, salt.Length);
                    first[salt.Length] = (byte)(block >> 24);
                    first[salt.Length + 1] = (byte)(block >> 16);
                    first[salt.Length + 2] = (byte)(block >> 8);
                    first[salt.Length + 3] = (byte)block;

                    byte[] u = hmac.ComputeHash(first);
                    byte[] t = (byte[])u.Clone();
                    for (int i = 1; i < iterations; i++)
                    {
                        u = hmac.ComputeHash(u);
                        for (int j = 0; j < t.Length; j++)
                        {
                            t[j] ^= u[j];
                        }
                    }

                    Buffer.BlockCopy(t, 0, output, (block - 1) * 32, 32);
                }
            }

            if (output.Length == outputLength) return output;

            byte[] trimmed = new byte[outputLength];
            Buffer.BlockCopy(output, 0, trimmed, 0, outputLength);
            Array.Clear(output, 0, output.Length);
            return trimmed;
        }

        #endregion

        #region Symmetric decryption

        /// <summary>
        /// Decrypts the user key. A failure here almost always means a wrong master password.
        /// </summary>
        public static SymmetricKey UnwrapUserKey(string wrappedUserKey, byte[] masterKey)
        {
            SymmetricKey wrappingKey;
            if (GetEncType(wrappedUserKey) == 2)
            {
                wrappingKey = StretchMasterKey(masterKey);
            }
            else
            {
                // Very old accounts: the master key itself is used, without MAC
                wrappingKey = new SymmetricKey(masterKey);
            }

            byte[] raw = null;
            try
            {
                raw = DecryptBytes(wrappedUserKey, wrappingKey);
                return new SymmetricKey(raw);
            }
            catch (CryptographicException)
            {
                throw new WrongPasswordException("The master password is wrong (or does not belong to this snapshot).");
            }
            finally
            {
                wrappingKey.Clear();
                if (raw != null) Array.Clear(raw, 0, raw.Length);
            }
        }

        public static int GetEncType(string encString)
        {
            return ParseEncString(encString).Type;
        }

        /// <summary>
        /// Decrypts an encrypted value ("2.iv|data|mac", or "0.iv|data" for very old data).
        /// </summary>
        public static byte[] DecryptBytes(string encString, SymmetricKey key)
        {
            EncString e = ParseEncString(encString);

            if (e.Type != 0 && e.Type != 2)
            {
                throw new CryptographicException("Unsupported encryption type " + e.Type + ".");
            }
            if (e.Iv == null || e.Iv.Length != 16)
            {
                throw new CryptographicException("Invalid initialization vector.");
            }

            if (e.Type == 2)
            {
                if (key.MacKey == null) throw new CryptographicException("This value needs a key with a MAC key.");

                byte[] macInput = new byte[e.Iv.Length + e.Data.Length];
                Buffer.BlockCopy(e.Iv, 0, macInput, 0, e.Iv.Length);
                Buffer.BlockCopy(e.Data, 0, macInput, e.Iv.Length, e.Data.Length);

                byte[] expected;
                using (HMACSHA256 hmac = new HMACSHA256(key.MacKey))
                {
                    expected = hmac.ComputeHash(macInput);
                }

                if (!FixedTimeEquals(expected, e.Mac)) throw new MacMismatchException();
            }

            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key.EncKey;
                aes.IV = e.Iv;
                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(e.Data, 0, e.Data.Length);
                }
            }
        }

        /// <summary>
        /// Decrypts a text value. Returns null for an empty or missing value.
        /// </summary>
        public static string DecryptString(string encString, SymmetricKey key)
        {
            if (string.IsNullOrEmpty(encString)) return null;
            return Encoding.UTF8.GetString(DecryptBytes(encString, key));
        }

        private static EncString ParseEncString(string value)
        {
            if (string.IsNullOrEmpty(value)) throw new FormatException("An encrypted value is empty.");

            int dot = value.IndexOf('.');
            int type;
            if (dot < 1 || dot > 2 || !int.TryParse(value.Substring(0, dot), out type))
            {
                throw new FormatException("Unknown format of an encrypted value.");
            }

            string[] parts = value.Substring(dot + 1).Split('|');
            EncString result = new EncString();
            result.Type = type;

            bool supported = (type == 2 && parts.Length == 3)
                || (type == 0 && parts.Length == 2)
                || (type == 4 && parts.Length >= 1);
            if (!supported)
            {
                throw new FormatException("Unsupported encrypted value (type " + type + ").");
            }

            try
            {
                if (type == 2)
                {
                    result.Iv = Convert.FromBase64String(parts[0]);
                    result.Data = Convert.FromBase64String(parts[1]);
                    result.Mac = Convert.FromBase64String(parts[2]);
                }
                else if (type == 0)
                {
                    result.Iv = Convert.FromBase64String(parts[0]);
                    result.Data = Convert.FromBase64String(parts[1]);
                }
                else
                {
                    result.Data = Convert.FromBase64String(parts[0]);
                }
            }
            catch (FormatException)
            {
                throw new FormatException("An encrypted value is not valid Base64 (type " + type + ").");
            }

            return result;
        }

        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int difference = 0;
            for (int i = 0; i < a.Length; i++)
            {
                difference |= a[i] ^ b[i];
            }
            return difference == 0;
        }

        #endregion

        #region RSA (organization keys)

        /// <summary>
        /// Decrypts an RSA-encrypted key ("4.base64", RSA-OAEP with SHA-1) with the user's private key.
        /// </summary>
        public static byte[] DecryptRsa(string encString, byte[] pkcs8PrivateKey)
        {
            EncString e = ParseEncString(encString);
            if (e.Type != 4)
            {
                throw new CryptographicException("Unsupported RSA encryption type " + e.Type + ".");
            }

            RSAParameters parameters = ParsePkcs8RsaPrivateKey(pkcs8PrivateKey);
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(parameters);
                return rsa.Decrypt(e.Data, true); // true = OAEP (SHA-1)
            }
        }

        /// <summary>
        /// Reads an unencrypted PKCS#8 RSA private key (DER). .NET Framework has no built-in importer for it.
        /// </summary>
        public static RSAParameters ParsePkcs8RsaPrivateKey(byte[] der)
        {
            int pos = 0;
            EnterTag(der, ref pos, 0x30);               // PrivateKeyInfo
            SkipTag(der, ref pos, 0x02);                // version
            SkipTag(der, ref pos, 0x30);                // algorithm identifier
            EnterTag(der, ref pos, 0x04);               // privateKey (OCTET STRING)
            EnterTag(der, ref pos, 0x30);               // RSAPrivateKey
            SkipTag(der, ref pos, 0x02);                // version

            byte[] modulus = TrimLeadingZeros(ReadInteger(der, ref pos));
            byte[] exponent = TrimLeadingZeros(ReadInteger(der, ref pos));
            byte[] d = ReadInteger(der, ref pos);
            byte[] p = ReadInteger(der, ref pos);
            byte[] q = ReadInteger(der, ref pos);
            byte[] dp = ReadInteger(der, ref pos);
            byte[] dq = ReadInteger(der, ref pos);
            byte[] inverseQ = ReadInteger(der, ref pos);

            int half = modulus.Length / 2;

            RSAParameters result = new RSAParameters();
            result.Modulus = modulus;
            result.Exponent = exponent;
            result.D = PadLeft(TrimLeadingZeros(d), modulus.Length);
            result.P = PadLeft(TrimLeadingZeros(p), half);
            result.Q = PadLeft(TrimLeadingZeros(q), half);
            result.DP = PadLeft(TrimLeadingZeros(dp), half);
            result.DQ = PadLeft(TrimLeadingZeros(dq), half);
            result.InverseQ = PadLeft(TrimLeadingZeros(inverseQ), half);
            return result;
        }

        private static int ReadLength(byte[] data, ref int pos)
        {
            if (pos >= data.Length) throw new CryptographicException("The private key is truncated.");

            int first = data[pos++];
            if (first < 0x80) return first;

            int count = first & 0x7F;
            if (count < 1 || count > 4 || pos + count > data.Length)
            {
                throw new CryptographicException("The private key has an invalid length field.");
            }

            int length = 0;
            for (int i = 0; i < count; i++)
            {
                length = (length << 8) | data[pos++];
            }
            if (length < 0) throw new CryptographicException("The private key has an invalid length field.");
            return length;
        }

        /// <summary>
        /// Checks the tag, reads the length and leaves pos at the start of the content.
        /// </summary>
        private static int EnterTag(byte[] data, ref int pos, byte tag)
        {
            if (pos >= data.Length || data[pos] != tag)
            {
                throw new CryptographicException("The private key has an unexpected structure.");
            }
            pos++;
            return ReadLength(data, ref pos);
        }

        private static void SkipTag(byte[] data, ref int pos, byte tag)
        {
            int length = EnterTag(data, ref pos, tag);
            if (pos + length > data.Length) throw new CryptographicException("The private key is truncated.");
            pos += length;
        }

        private static byte[] ReadInteger(byte[] data, ref int pos)
        {
            int length = EnterTag(data, ref pos, 0x02);
            if (pos + length > data.Length) throw new CryptographicException("The private key is truncated.");

            byte[] value = new byte[length];
            Buffer.BlockCopy(data, pos, value, 0, length);
            pos += length;
            return value;
        }

        private static byte[] TrimLeadingZeros(byte[] value)
        {
            int start = 0;
            while (start < value.Length - 1 && value[start] == 0) start++;
            if (start == 0) return value;

            byte[] trimmed = new byte[value.Length - start];
            Buffer.BlockCopy(value, start, trimmed, 0, trimmed.Length);
            return trimmed;
        }

        private static byte[] PadLeft(byte[] value, int length)
        {
            if (value.Length > length) throw new CryptographicException("The private key has an unexpected size.");
            if (value.Length == length) return value;

            byte[] padded = new byte[length];
            Buffer.BlockCopy(value, 0, padded, length - value.Length, value.Length);
            return padded;
        }

        #endregion
    }
}
