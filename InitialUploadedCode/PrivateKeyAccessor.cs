using System;
using System.Security.Cryptography;

namespace KeyStorageTest
{
    public class PrivateKeyAccessor : IDisposable
    {
        public const Base64FormattingOptions SerializedPublicKey_FormattingOptions = Base64FormattingOptions.InsertLineBreaks;
        public static readonly CngKeyBlobFormat PublicKeyExport_Format = CngKeyBlobFormat.EccPublicBlob;
        public static readonly CngAlgorithm Export_HashAlgorithm = CngAlgorithm.Sha512;
        public static readonly ECDiffieHellmanKeyDerivationFunction Export_KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;

        public AesCryptoServiceProvider Provider { get; private set; }
        public ECDiffieHellmanCng Algorithm { get; private set; }
        public PublicKeyItem PublicKeyData { get; private set; }
        public UserPrivateKey PrivateKeyData { get; private set; }

        public PrivateKeyAccessor(string name)
        {
            if (name == null)
                throw new ArgumentNullException("name");

            if (name.Length == 0)
                throw new ArgumentException("Name cannot be empty", "name");

            this.Initialize(new UserPrivateKey(name));
        }

        public PrivateKeyAccessor(CngKey key)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            this.Initialize(new UserPrivateKey(key));
        }

        public PrivateKeyAccessor(UserPrivateKey privateKey)
        {
            if (privateKey == null)
                throw new ArgumentNullException("privateKey");

            if (privateKey.Name.Length == 0)
                throw new ArgumentException("Private key name has not been defined", "privateKey");

            this.Initialize(privateKey);
        }

        private void Initialize(UserPrivateKey privateKey)
        {
            this.PublicKeyData = new PublicKeyItem();
            this.PublicKeyData.Name = privateKey.Name;

            this.Provider = new AesCryptoServiceProvider();

            try
            {
                this.Algorithm = new ECDiffieHellmanCng(privateKey.Key);
                try
                {
                    this.Algorithm.KeyDerivationFunction = PrivateKeyAccessor.Export_KeyDerivationFunction;
                    this.Algorithm.HashAlgorithm = PrivateKeyAccessor.Export_HashAlgorithm;
                    this.PublicKeyData.KeyBlob = PrivateKeyAccessor.Export(privateKey.Key);
                }
                catch
                {
                    try
                    {
                        this.Algorithm.Dispose();
                    }
                    catch { }
                    throw;
                }
            }
            catch
            {
                try
                {
                    this.Provider.Dispose();
                }
                catch { }
                throw;
            }
        }

        public static string ToBase64String(byte[] data)
        {
            return (data == null || data.Length == 0) ? "" : Convert.ToBase64String(data, PrivateKeyAccessor.SerializedPublicKey_FormattingOptions);
        }

        public static byte[] FromBase64String(string b64Text)
        {
            return (String.IsNullOrWhiteSpace(b64Text)) ? new byte[0] : Convert.FromBase64String(b64Text);
        }

        public static CngKey Import(byte[] keyBlob)
        {
            return (keyBlob == null || keyBlob.Length == 0) ? null : CngKey.Import(keyBlob, PrivateKeyAccessor.PublicKeyExport_Format);
        }

        public static byte[] Export(CngKey key)
        {
            return (key == null) ? new byte[0] : key.Export(PrivateKeyAccessor.PublicKeyExport_Format);
        }

        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (this.Provider == null)
                return;

            if (disposing)
            {
                if (this.Algorithm != null)
                    this.Algorithm.Dispose();
                this.Algorithm = null;
                this.Provider.Dispose();
            }
            else
                this.Algorithm = null;

            this.Provider = null;
        }
    }
}
