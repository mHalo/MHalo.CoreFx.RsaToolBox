using MHalo.CoreFx.Helper;
using MHalo.CoreFx.RsaToolBox.Helpers.RSAExtensions;
using System.ComponentModel;
using System.IO;
using System.Windows.Documents;
using System.Windows.Media;

namespace MHalo.CoreFx.RsaToolBox.ViewModels.Pages
{

    public partial class RsaKeyGenerateViewModel : ObservableObject
    {

        private RSAKeyType _rsaKeyType;
        private int _rsaKeyTypeSelectedIndex;
        private RSAKeyPair _rsaKey = new ("", "");
        private string _rsaLocalFolder;
        private bool _saveToLocal;
        private int _rsaKeyFormat;
        [ObservableProperty]
        private int _rsaKeyLength;

        public RsaKeyGenerateViewModel()
        {
            _saveToLocal = true;
        }
        public RSAKeyType RsaKeyType
        {
            get { return _rsaKeyType; }
            set
            {
                if (_rsaKeyType != value)
                {
                    _rsaKeyType = value;
                    _rsaKeyFormat = 0;
                    RsaKeyTypeSelectedIndex = (int)value;
                    OnPropertyChanged(nameof(RsaKeyType));
                    OnPropertyChanged(nameof(RsaKeyFormat));
                    OnPropertyChanged(nameof(CanExportTxtFormat));
                    OnPropertyChanged(nameof(CanExportPemFormat));
                    OnPropertyChanged(nameof(CanExportXmlFormat));
                }
            }
        }
        public int RsaKeyTypeSelectedIndex
        {
            get { return _rsaKeyTypeSelectedIndex; }
            set
            {
                if (_rsaKeyTypeSelectedIndex != value)
                {
                    _rsaKeyTypeSelectedIndex = value;
                    RsaKeyType = (RSAKeyType)value;
                    OnPropertyChanged(nameof(RsaKeyTypeSelectedIndex));
                }
            }
        }
        public RSAKeyPair RSAKey
        {
            get => _rsaKey;
            set
            {
                _rsaKey = value;
                OnPropertyChanged(nameof(RSAKey));
                OnPropertyChanged(nameof(IsGenerateKeyValid));
                OnPropertyChanged(nameof(KeyContentColor));
                OnPropertyChanged(nameof(KeyGenerateTips));
                OnPropertyChanged(nameof(RsaKeyTypeVisible)); 
            }
        }
        public string RsaLocalFolder
        {
            get => _rsaLocalFolder;
            set
            {
                _rsaLocalFolder = value;
                OnPropertyChanged(nameof(RsaLocalFolder));
                OnPropertyChanged(nameof(CanOpenRSAFolder));
            }
        }
        public bool SaveToLocal
        {
            get => _saveToLocal;
            set
            {
                _saveToLocal = value;
                OnPropertyChanged(nameof(SaveToLocal));
                OnPropertyChanged(nameof(CanOpenRSAFolder));
            }
        }
        public int RsaKeyFormat
        {
            get => _rsaKeyFormat;
            set
            {
                _rsaKeyFormat = value;
                OnPropertyChanged(nameof(RsaKeyFormat));
            }
        }
        public bool CanExportTxtFormat => RSAKeyType.Pkcs1.Equals(_rsaKeyType) || RSAKeyType.Pkcs8.Equals(_rsaKeyType) || RSAKeyType.Xml.Equals(_rsaKeyType);
        public bool CanExportPemFormat => RSAKeyType.Pkcs1.Equals(_rsaKeyType) || RSAKeyType.Pkcs8.Equals(_rsaKeyType);
        public bool CanExportXmlFormat => RSAKeyType.Xml.Equals(_rsaKeyType);
        public bool CanOpenRSAFolder => SaveToLocal && !string.IsNullOrEmpty(RsaLocalFolder);
        public string KeyGenerateTips => IsGenerateKeyValid ? $"密钥格式：{RsaKeyType}" : "";
        public bool IsGenerateKeyValid => !(string.IsNullOrEmpty(RSAKey.PublicKey) && string.IsNullOrEmpty(RSAKey.PrivateKey));
        public Visibility RsaKeyTypeVisible => IsGenerateKeyValid ? Visibility.Visible : Visibility.Hidden;
        public SolidColorBrush KeyContentColor => IsGenerateKeyValid ? new SolidColorBrush(Color.FromArgb(255, 50, 50, 50)) : new SolidColorBrush(Color.FromArgb(255, 215, 215, 215));


        [RelayCommand]
        private void OnGenderateKey()
        {
            int keyLength = RsaKeyLength switch
            {
                0 => 1024,
                1 => 2048,
                _ => 2048
            };

            (string publicKey, string privateKey) = RSAHelper.ExportRSAKey(_rsaKeyType, keyLength, _rsaKeyFormat == 1);
            string suffix = $"{_rsaKeyType.ToString().ToLower() + (_rsaKeyFormat == 2 ? "" : _rsaKeyFormat == 1 ? ".pem" : ".txt")}";

            if (SaveToLocal)
            {
                string pairPrefix = $"[{_rsaKeyType}] - " + RandomHelper.RandomToken(6, true);
                string parentFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), $"rsa-keys\\{pairPrefix}");
                string publicKeyFilePath = Path.Combine(parentFolder, $"publicKey.{suffix}");
                string privateKeyFilePath = Path.Combine(parentFolder, $"privateKey.{suffix}");

                IoHelper.CreateFile(publicKeyFilePath, publicKey);
                IoHelper.CreateFile(privateKeyFilePath, privateKey);

                RsaLocalFolder = parentFolder;
            }
            else
            {
                RsaLocalFolder = string.Empty;
            }

            

            RSAKey = new RSAKeyPair(publicKey, privateKey);
        }
    }
}
