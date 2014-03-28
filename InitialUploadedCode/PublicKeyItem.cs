using System;
using System.Security.Cryptography;
using System.Xml.Serialization;

namespace KeyStorageTest
{
    public class PublicKeyItem
    {
        private string _name = "";
        private string _keyData = "";
        private byte[] _keyBlob = new byte[0];
        private CngKey _key = null;

        [XmlAttribute("Name")]
        public string Name
        {
            get { return this._name; }
            set { this._name = (value == null) ? "" : value; }
        }

        public string KeyData
        {
            get { return this._keyData; }
            set { this.SetKeyData(null, value, null); }
        }

        [XmlIgnore]
        public byte[] KeyBlob
        {
            get { return this._keyBlob; }
            set { this.SetKeyData(value, null, null); }
        }

        [XmlIgnore]
        public CngKey Key
        {
            get
            {
                if (this._key == null && this.KeyBlob.Length > 0)
                    this._key = PrivateKeyAccessor.Import(this.KeyBlob);

                return this._key;
            }
            set { this.SetKeyData(null, null, value); }
        }

        public PublicKeyItem() { }

        public PublicKeyItem(string  name, byte[] keyBlob) { }

        public static PublicKeyItem Create(UserPrivateKey privateKey)
        {
            PublicKeyItem result = null;

            using (PrivateKeyAccessor pkp = new PrivateKeyAccessor(privateKey))
                result = pkp.PublicKeyData;

            return result;
        }

        private void SetKeyData(byte[] keyBlob, string keyData, CngKey key)
        {
            if (key != null)
                keyBlob = PrivateKeyAccessor.Export(key);
            else if (!String.IsNullOrEmpty(KeyData))
                keyBlob = PrivateKeyAccessor.FromBase64String(keyData);
            else if (keyBlob == null)
                keyBlob = new byte[0];

            if (keyBlob.Length > 0)
            {
                keyData = PrivateKeyAccessor.ToBase64String(keyBlob);

                if (this.KeyData == keyData)
                    return;
            }

            this._key = key;
            this._keyData = keyData;
            this._keyBlob = keyBlob;
        }
    }
}
