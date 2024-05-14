using MHalo.CoreFx.Helper;
using System.ComponentModel;
using System.IO;
using System.Windows.Documents;
using System.Windows.Media;

namespace MHalo.CoreFx.RsaToolBox.ViewModels.Pages
{

    public partial class RsaKeyGenerateViewModel : ObservableObject
    {
        /// <summary>
        /// 密钥对
        /// </summary>
        /// <param name="PublicKey">公钥</param>
        /// <param name="PrivateKey">私钥</param>
        public record RSAKeyPair(string PublicKey, string PrivateKey);

        private RSAKeyType _rsaKeyType;
        private int _rsaKeyTypeSelectedIndex;
        private RSAKeyPair _rsaKey = new (DefaultKeyTipText, DefaultKeyTipText);
        private string _rsaLocalFolder;
        private bool _saveToLocal;
        private int _rsaKeyFormat;

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
        public static string DefaultKeyTipText => "点击上方按钮生成";
        public bool IsGenerateKeyValid => !(DefaultKeyTipText.Equals(RSAKey.PublicKey) || DefaultKeyTipText.Equals(RSAKey.PrivateKey));
        public Visibility RsaKeyTypeVisible => IsGenerateKeyValid ? Visibility.Visible : Visibility.Hidden;
        public SolidColorBrush KeyContentColor => IsGenerateKeyValid ? new SolidColorBrush(Color.FromArgb(255, 50, 50, 50)) : new SolidColorBrush(Color.FromArgb(255, 215, 215, 215));


        [RelayCommand]
        private void OnGenderateKey()
        {
            string publicKey = string.Empty, privateKey = string.Empty, suffix = string.Empty;
            switch (_rsaKeyType)
            {
                case RSAKeyType.Pkcs1:
                    RSAHelper.ExportPkcs1Key(1024, out publicKey, out privateKey, _rsaKeyFormat == 1);
                    suffix = _rsaKeyFormat switch
                    {
                        1 => "pkcs1.pem",
                        _ => "pkcs1.txt",
                    };
                    break;
                case RSAKeyType.Pkcs8:
                    RSAHelper.ExportPkcs8Key(1024, out publicKey, out privateKey, _rsaKeyFormat == 1);
                    suffix = _rsaKeyFormat switch
                    {
                        1 => "pkcs8.pem",
                        _ => "pkcs8.txt",
                    };
                    break;
                case RSAKeyType.Xml:
                    RSAHelper.ExportXMLKey(1024, out publicKey, out privateKey);
                    suffix = _rsaKeyFormat switch
                    {
                        2 => "xml",
                        _ => "xml.txt",
                    };
                    break;
            }

            if (SaveToLocal)
            {
                string pairPrefix = RandomHelper.RandomToken(6, true);
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
