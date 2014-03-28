using System;
using System.IO;
using System.Security.Cryptography;
using System.Xml.Serialization;

namespace KeyStorageTest
{
    public class EncryptedExchangeData
    {
        private string _initializationVector = "";
        private byte[] _ivBytes = new byte[0];
        private string _encrptedData = "";
        private byte[] _encryptedBytes = new byte[0];

        public PublicKeyItem SenderPublicKey { get; set; }

        public string EncryptedData
        {
            get { return this._encrptedData; }
            set { this.SetEncryptedData(null, value); }
        }

        [XmlIgnore]
        public byte[] EncryptedBytes
        {
            get { return this._encryptedBytes; }
            set { this.SetEncryptedData(value, null); }
        }

        public string InitializationVector
        {
            get { return this._initializationVector; }
            set { this.SetInitializationVector(null, value); }
        }

        [XmlIgnore]
        public byte[] IVBytes
        {
            get { return this._ivBytes; }
            set { this.SetInitializationVector(value, null); }
        }

        private void SetEncryptedData(byte[] buffer, string b64Data)
        {
            if (buffer != null && buffer.Length > 0)
                b64Data = PrivateKeyAccessor.ToBase64String(buffer);
            else if (!String.IsNullOrWhiteSpace(b64Data))
                buffer = PrivateKeyAccessor.FromBase64String(b64Data);
            else if (buffer == null)
                buffer = new byte[0];

            if (this.InitializationVector == b64Data)
                return;

            this._encrptedData = b64Data;
            this._encryptedBytes = buffer;
        }

        private void SetInitializationVector(byte[] buffer, string b64Data)
        {
            if (buffer != null && buffer.Length > 0)
                b64Data = PrivateKeyAccessor.ToBase64String(buffer);
            else if (!String.IsNullOrWhiteSpace(b64Data))
                buffer = PrivateKeyAccessor.FromBase64String(b64Data);
            else
            {
                if (buffer == null)
                    buffer = new byte[0];
                if (b64Data == null)
                    b64Data = "";
            }

            if (this.EncryptedData == b64Data)
                return;

            this._initializationVector = b64Data;
            this._ivBytes = buffer;
        }

        public EncryptedExchangeData() { }

        public static EncryptedExchangeData Create(UserPrivateKey sender, byte[] dataToEncrypt, PublicKeyItem recipient)
        {
            if (sender == null)
                throw new ArgumentNullException("sender");

            if (dataToEncrypt == null)
                throw new ArgumentNullException("dataToEncrypt");

            if (recipient == null)
                throw new ArgumentNullException("recipient");

            if (sender.Name == null)
                throw new ArgumentException("Sender Name has not been defined.", "sender");

            if (recipient.Key == null)
                throw new ArgumentException("Recipient Key has not been defined.", "recipient");

            EncryptedExchangeData result = new EncryptedExchangeData();

            using (PrivateKeyAccessor pka = new PrivateKeyAccessor(sender))
            {
                pka.Provider.Key = pka.Algorithm.DeriveKeyMaterial(recipient.Key);
                result.IVBytes = pka.Provider.IV;
                using (MemoryStream ciphertext = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ciphertext, pka.Provider.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                        cs.Close();
                        result.EncryptedBytes = ciphertext.ToArray();
                    }
                }
            }

            return result;
        }
    }
}
