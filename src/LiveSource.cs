using System;
using System.IO;
using System.Net;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Text.RegularExpressions;

namespace VaultwardenSync
{
    [DataContract]
    public class SnapToken
    {
        [DataMember]
        public string access_token { get; set; }
    }

    /// <summary>
    /// Live sync: downloads the encrypted vault directly from the server with the personal API
    /// key and decrypts it with the same code as a snapshot. No Bitwarden CLI is involved.
    /// Does not touch the KeePass database, so it may run on a worker thread.
    /// </summary>
    public sealed class LiveSource
    {
        private const int TimeoutMs = 120000;

        private readonly string _serverUrl;
        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly string _deviceId;

        public event Action<string> OnLogMessage;

        public LiveSource(string serverUrl, string clientId, string clientSecret, string deviceId)
        {
            _serverUrl = (serverUrl ?? string.Empty).Trim().TrimEnd('/');
            _clientId = (clientId ?? string.Empty).Trim();
            _clientSecret = clientSecret ?? string.Empty;
            _deviceId = string.IsNullOrEmpty(deviceId) ? Guid.NewGuid().ToString() : deviceId;
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
                // Logging must never abort the sync
            }
        }

        /// <summary>
        /// Downloads and decrypts the vault. Throws WrongPasswordException for a wrong master password.
        /// </summary>
        public VaultData Fetch(string masterPassword)
        {
            if (string.IsNullOrEmpty(masterPassword)) throw new ArgumentException("The master password is empty.", "masterPassword");
            if (!SyncConfiguration.IsValidServerUrl(_serverUrl))
            {
                throw new InvalidOperationException("The server URL must be a full https:// address.");
            }
            if (_clientId.Length == 0 || _clientSecret.Length == 0)
            {
                throw new InvalidOperationException("The API key (client_id and client_secret) is missing.");
            }

            try
            {
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            }
            catch (NotSupportedException)
            {
                // The platform decides
            }

            // 1. Log in with the API key
            Log("Logging in with the API key...");
            string form = "grant_type=client_credentials&scope=api"
                + "&client_id=" + Uri.EscapeDataString(_clientId)
                + "&client_secret=" + Uri.EscapeDataString(_clientSecret)
                + "&deviceType=23"
                + "&deviceIdentifier=" + Uri.EscapeDataString(_deviceId)
                + "&deviceName=VaultwardenSync";
            string tokenJson = Request("POST", "/identity/connect/token", form, "application/x-www-form-urlencoded", null, "Login");
            SnapToken token = Deserialize<SnapToken>(tokenJson);
            if (token == null || string.IsNullOrEmpty(token.access_token))
            {
                throw new InvalidOperationException("The server did not return an access token.");
            }

            // 2. Download the encrypted vault
            Log("Downloading the encrypted vault...");
            string syncJson = Request("GET", "/api/sync?excludeDomains=true", null, null, token.access_token, "Download");
            SnapSync sync = Deserialize<SnapSync>(syncJson);
            if (sync == null || sync.profile == null || sync.ciphers == null)
            {
                throw new InvalidDataException("The server returned incomplete vault data (no profile or items).");
            }
            string email = sync.profile.email;
            if (string.IsNullOrEmpty(email) || email.IndexOf('@') < 1)
            {
                throw new InvalidDataException("The vault data does not contain the account e-mail address.");
            }

            // 3. Key derivation settings: newer servers send them with the vault, older ones need a second request
            SnapPrelogin prelogin = null;
            bool hasKdf = sync.userDecryption != null
                && sync.userDecryption.masterPasswordUnlock != null
                && sync.userDecryption.masterPasswordUnlock.kdf != null
                && sync.userDecryption.masterPasswordUnlock.kdf.kdfType.HasValue;
            if (!hasKdf)
            {
                Log("Downloading the KDF settings...");
                string body = "{\"email\":" + ToJsonString(email) + "}";
                foreach (string path in new string[] { "/identity/accounts/prelogin", "/api/accounts/prelogin" })
                {
                    try
                    {
                        prelogin = Deserialize<SnapPrelogin>(Request("POST", path, body, "application/json", null, "KDF settings"));
                        if (prelogin != null && prelogin.kdf.HasValue) break;
                        prelogin = null;
                    }
                    catch (Exception)
                    {
                        prelogin = null;
                    }
                }
                if (prelogin == null)
                {
                    throw new InvalidDataException("The KDF settings could not be downloaded.");
                }
            }

            SnapDocument doc = new SnapDocument();
            doc.format = SnapshotSource.SnapshotFormat;
            doc.version = 1;
            doc.createdUtc = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
            doc.server = _serverUrl;
            doc.email = email;
            doc.prelogin = prelogin;
            doc.sync = sync;

            SnapshotSource decryptor = new SnapshotSource(null);
            decryptor.OnLogMessage += Log;
            return decryptor.DecryptDocument(doc, masterPassword);
        }

        private string Request(string method, string path, string body, string contentType, string bearerToken, string what)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(_serverUrl + path);
            request.Method = method;
            request.Timeout = TimeoutMs;
            request.ReadWriteTimeout = TimeoutMs;
            request.UserAgent = "VaultwardenSync";
            request.Accept = "application/json";
            request.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            // Never follow redirects: the API secret and the vault must only go to the configured address
            request.AllowAutoRedirect = false;
            if (bearerToken != null)
            {
                request.Headers.Add("Authorization", "Bearer " + bearerToken);
            }

            int status;
            string text;
            string location;
            try
            {
                if (body != null)
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(body);
                    request.ContentType = contentType;
                    request.ContentLength = bytes.Length;
                    using (Stream stream = request.GetRequestStream())
                    {
                        stream.Write(bytes, 0, bytes.Length);
                    }
                }

                HttpWebResponse response;
                try
                {
                    response = (HttpWebResponse)request.GetResponse();
                }
                catch (WebException ex)
                {
                    response = ex.Response as HttpWebResponse;
                    if (response == null) throw;
                }

                using (response)
                {
                    status = (int)response.StatusCode;
                    location = response.Headers["Location"];
                    using (StreamReader reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8))
                    {
                        text = reader.ReadToEnd();
                    }
                }
            }
            catch (WebException ex)
            {
                throw new InvalidOperationException("The server cannot be reached: " + ex.Message, ex);
            }

            if (status >= 300 && status < 400)
            {
                throw new InvalidOperationException(string.Format(
                    "The server answered with a redirect (HTTP {0}) to \"{1}\". Redirects are not followed; enter the final server URL.",
                    status, location));
            }
            if (status != 200)
            {
                throw new InvalidOperationException(string.Format("{0} failed (HTTP {1}). {2}", what, status, ErrorHint(text)));
            }
            return text;
        }

        /// <summary>
        /// A short, secret-free hint from an error response of the server.
        /// </summary>
        private static string ErrorHint(string text)
        {
            if (string.IsNullOrEmpty(text)) return "(empty response)";
            foreach (string name in new string[] { "error_description", "message", "error" })
            {
                Match match = Regex.Match(text, "\"" + name + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"", RegexOptions.IgnoreCase);
                if (match.Success && match.Groups[1].Value.Length > 0)
                {
                    return name + ": " + match.Groups[1].Value;
                }
            }
            string flat = Regex.Replace(text, "\\s+", " ");
            if (flat.Length > 300) flat = flat.Substring(0, 300) + "...";
            return "Response: " + flat;
        }

        private static T Deserialize<T>(string json) where T : class
        {
            if (string.IsNullOrEmpty(json)) return null;
            try
            {
                DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(T));
                using (MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
                {
                    return (T)serializer.ReadObject(stream);
                }
            }
            catch (SerializationException ex)
            {
                throw new InvalidDataException("The server returned data that cannot be read: " + ex.Message);
            }
        }

        private static string ToJsonString(string value)
        {
            DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(string));
            using (MemoryStream stream = new MemoryStream())
            {
                serializer.WriteObject(stream, value);
                return Encoding.UTF8.GetString(stream.ToArray());
            }
        }
    }
}
