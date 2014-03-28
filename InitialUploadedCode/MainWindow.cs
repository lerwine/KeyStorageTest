using System;
using System.Windows;

namespace KeyStorageTest
{
    public partial class MainWindow 
    {
        public MainWindow()
        {
            string testName = "My Key";

            using (PrivateKeyAccessor accessor = new PrivateKeyAccessor(testName))
            {
                MessageBox.Show(accessor.PublicKeyData.Name);
                MessageBox.Show(accessor.PrivateKeyData.FullName);
                MessageBox.Show(accessor.PrivateKeyData.UniqueName);
            }

            UserPrivateKey[] keys = UserPrivateKey.GetAllSupportedKeys();

            MessageBox.Show(String.Format("{0} keys found", keys.Length));

            foreach (UserPrivateKey k in keys)
            {
                using (PrivateKeyAccessor accessor = new PrivateKeyAccessor(k))
                {
                    MessageBox.Show(accessor.PublicKeyData.Name);
                    MessageBox.Show(accessor.PrivateKeyData.FullName);
                    MessageBox.Show(accessor.PrivateKeyData.UniqueName);
                }
            }

            InitializeComponent();
        }
    }
}
