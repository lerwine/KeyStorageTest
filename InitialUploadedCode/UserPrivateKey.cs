using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Xml.Serialization;

namespace KeyStorageTest
{
    public class UserPrivateKey
    {
        public const string KeyCreationTest = "62DF691857014486A8357C7964572B74-";
        public const string KeyContainerPrefix = "62DF691857014486A8357C7964572B74-";
        public static readonly CngProvider KeyStorageProvider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
        public const CngKeyOpenOptions KeyStorageOption = CngKeyOpenOptions.UserKey;

        private string _name = "";
        private string _uniqueName = "";
        private bool? _isUserPrivateKey = null;
        private CngKey _key = null;
        private object _exportPolicy = null;
        private object _usages = null;

        [XmlAttribute("Name")]
        public string Name
        {
            get { return (this._name == null) ? "" : this._name; }
            set { this.SetKey(null, value, false); }
        }

        [XmlIgnore()]
        public string FullName { get { return UserPrivateKey.ToFullName(this.Name, this.IsUserPrivateKey); } }

        [XmlIgnore()]
        public string UniqueName
        {
            get
            {
                if (this._uniqueName.Length == 0 && this.Name.Length > 0)
                    this.LoadKey();

                return this._uniqueName;
            }
            private set { this._uniqueName = value; }
        }

        [XmlAttribute("IsUserPrivateKey")]
        public bool IsUserPrivateKey
        {
            get
            {
                if (!this._isUserPrivateKey.HasValue && this.Name.Length > 0)
                    this.LoadKey();
                
                return (this._isUserPrivateKey.HasValue) ? this._isUserPrivateKey.Value : this._key == null;
            }
            set
            {
                if (this._isUserPrivateKey.HasValue)
                    throw new InvalidOperationException("IsUserPrivateKey cannot be changed once has been initialized.");

                this._isUserPrivateKey = value;
            }
        }

        [XmlIgnore()]
        public CngExportPolicies? ExportPolicy
        {
            get
            {
                if (this._exportPolicy == null && this.Name.Length > 0)
                    this.LoadKey();

                return this._exportPolicy as CngExportPolicies?;
            }
            set
            {
                if (this._exportPolicy != null)
                    throw new InvalidOperationException("ExportPolicy cannot be changed once has been initialized.");

                this._exportPolicy = (value.HasValue) ? (object)(value) : new object();
            }
        }

        [XmlIgnore]
        public CngKeyUsages? Usages
        {
            get
            {
                if (this._usages == null && this.Name.Length > 0)
                    this.LoadKey();

                return this._usages as CngKeyUsages?;
            }
            set
            {
                if (this._usages != null)
                    throw new InvalidOperationException("Usages cannot be changed once it has been initialized.");

                this._usages = (value.HasValue) ? (object)(value) : new object();
            }
        }

        [XmlAttribute("ExportPolicy")]
        public string _ExportPolicy
        {
            get { return (this.ExportPolicy.HasValue) ? null : this.ExportPolicy.ToString(); }
            set { this.ExportPolicy = (String.IsNullOrWhiteSpace(value)) ? null : Enum.Parse(typeof(CngExportPolicies), value.Trim(), true) as CngExportPolicies?; }
        }

        [XmlIgnore()]
        public CngKey Key
        {
            get
            {
                if (this._key == null)
                    this.LoadKey();

                return this._key;
            }
            set { this.SetKey(value, null, false); }
        }

        public UserPrivateKey() { }

        public UserPrivateKey(string name)
        {
            this.SetKey(null, name, true);
        }

        public UserPrivateKey(CngKey key)
        {
            this.SetKey(key, null, true);
        }

        private void SetKey(CngKey key, string name, bool force)
        {
            Action resetFields = () =>
            {
                this._key = key;
                this._name = "";
                this._isUserPrivateKey = null;
                this._exportPolicy = null;
                this._usages = null;
                this.UniqueName = "";
            };

            if (this.Name.Length > 0 && !force)
                throw new InvalidOperationException("Cannot change name or key after they have been initialized.");

            if (key == null)
            {
                if (name == null)
                    name = "";

                if (this.Name == name)
                    return;

                resetFields();
                this._name = name;

                return;
            }

            if (this._key != null && Object.ReferenceEquals(this._key, key))
                return;

            if (!key.Algorithm.Equals(CngAlgorithm.ECDiffieHellmanP521))
                throw new ArgumentException("Unsupported algorithm");

            resetFields();
            this._key = key;
            this.UniqueName = key.UniqueName;
            this.ExportPolicy = key.ExportPolicy;
            this.Usages = key.KeyUsage;

            bool isUserPrivateKey;
            this._name = UserPrivateKey.DetectName(key, out isUserPrivateKey);
            this._isUserPrivateKey = isUserPrivateKey;
        }

        private void LoadKey()
        {
            if (String.IsNullOrEmpty(this.Name))
                throw new InvalidOperationException("Name has not been defined");

            if (CngKey.Exists(this.FullName, UserPrivateKey.KeyStorageProvider, UserPrivateKey.KeyStorageOption))
            {
                this.SetKey(CngKey.Open(this.FullName, UserPrivateKey.KeyStorageProvider, UserPrivateKey.KeyStorageOption), null, true);
                return;
            }

            CngKeyCreationParameters p = new CngKeyCreationParameters();
            p.ExportPolicy = (this.ExportPolicy == null) ? (CngExportPolicies.AllowExport as CngExportPolicies?) : this.ExportPolicy;
            p.KeyUsage = (this.Usages == null) ? (CngKeyUsages.AllUsages as CngKeyUsages?) : this.Usages;
            p.Provider = UserPrivateKey.KeyStorageProvider;
            p.UIPolicy = new CngUIPolicy(CngUIProtectionLevels.ProtectKey, "UserPrivateKey Key", "Key for exchanging protected data");
            CngKey result;
            try
            {
                result = CngKey.Create(CngAlgorithm.ECDiffieHellmanP521, this.FullName, p);
            }
            catch
            {
                p.ExportPolicy = CngExportPolicies.AllowArchiving;
                result = CngKey.Create(CngAlgorithm.ECDiffieHellmanP521, this.FullName, p);
            }

            this.SetKey(result, null, true);
        }

        private static string DetectName(CngKey key, out bool isUserPrivateKey)
        {
            isUserPrivateKey = key.KeyName.StartsWith(UserPrivateKey.KeyContainerPrefix);
            return UserPrivateKey.ToFullName(key.KeyName, isUserPrivateKey);
        }

        private static string DetectName(string keyName, out bool isUserPrivateKey)
        {
            isUserPrivateKey = (String.IsNullOrEmpty(keyName) || keyName.StartsWith(UserPrivateKey.KeyContainerPrefix));
            return UserPrivateKey.ToFullName(keyName, isUserPrivateKey);
        }

        public static string ToFullName(string keyName, bool isUserPrivateKey)
        {
            return (isUserPrivateKey) ? keyName.Substring(UserPrivateKey.KeyContainerPrefix.Length) : keyName;
        }

        public static UserPrivateKey[] GetAllSupportedKeys()
        {
            DirectoryInfo storageLoc = new DirectoryInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Microsoft\\Crypto\\Keys"));

            if (!storageLoc.Exists)
                return new UserPrivateKey[0];

            return storageLoc.GetFiles().Select(f =>
            {
                CngKey result;
                try
                {
                    result = (CngKey.Exists(f.Name, UserPrivateKey.KeyStorageProvider, UserPrivateKey.KeyStorageOption)) ? null : CngKey.Open(f.Name, UserPrivateKey.KeyStorageProvider, UserPrivateKey.KeyStorageOption);
                }
                catch
                {
                    result = null;
                }

                return result;
            }).Where(c => c != null && c.Algorithm.Equals(CngAlgorithm.ECDiffieHellmanP521))
                .Select(c => new UserPrivateKey(c)).ToArray();
        }

        public byte[] Decrypt(EncryptedExchangeData data)
        {
            if (String.IsNullOrEmpty(this.Name))
                throw new InvalidOperationException("Name has not been defined");

            byte[] result = null;

            using (PrivateKeyAccessor pkp = new PrivateKeyAccessor(this))
            {
                pkp.Provider.Key = pkp.Algorithm.DeriveKeyMaterial(data.SenderPublicKey.Key);
                pkp.Provider.IV = data.IVBytes;

                using (MemoryStream plaintext = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(plaintext, pkp.Provider.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(data.EncryptedBytes, 0, data.EncryptedBytes.Length);
                        cs.Close();
                        result = plaintext.ToArray();
                    }
                }
            }

            return result;
        }

        public bool Remove()
        {
            if (this._key == null && !CngKey.Exists(this.FullName, UserPrivateKey.KeyStorageProvider, UserPrivateKey.KeyStorageOption))
                return false;

            this.Key.Delete();
            this.Key = null;
            return true;
        }

        public static bool Remove(string name)
        {
            return UserPrivateKey.Remove(name, false);
        }

        public static bool Remove(string name, bool isFullName)
        {
            if (String.IsNullOrEmpty(name))
                return false;

            string fullName = UserPrivateKey.ToFullName(name, !isFullName);
            if (!CngKey.Exists(fullName, UserPrivateKey.KeyStorageProvider, UserPrivateKey.KeyStorageOption))
                return false;

            CngKey key = CngKey.Open(fullName, UserPrivateKey.KeyStorageProvider, UserPrivateKey.KeyStorageOption);
            key.Delete();
            return true;
        }

        public bool Exists()
        {
            return UserPrivateKey.Exists(this.Name);
        }

        public static bool Exists(string name)
        {
            return UserPrivateKey.Exists(name, false);
        }

        public static bool Exists(string name, bool isFullName)
        {
            return (!String.IsNullOrEmpty(name) && CngKey.Exists(UserPrivateKey.ToFullName(name, !isFullName)));
        }
    }
}
