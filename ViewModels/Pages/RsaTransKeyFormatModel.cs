using MHalo.CoreFx.Helper;
using MHalo.CoreFx.RsaToolBox.Helpers.RSAExtensions;
using MHalo.CoreFx.RsaToolBox.Models;
using System.Windows.Media;
using Wpf.Ui.Controls;
using static MHalo.CoreFx.RsaToolBox.ViewModels.Pages.RsaKeyGenerateViewModel;

namespace MHalo.CoreFx.RsaToolBox.ViewModels.Pages
{
    public partial class RsaTransKeyFormatViewModel : ObservableObject
    {
        public RsaTransKeyFormatViewModel()
        {

        }
        private int _targetRsaKeyTypeSelectedIndex;
        public int TargetRsaKeyTypeSelectedIndex
        {
            get { return _targetRsaKeyTypeSelectedIndex; }
            set
            {
                if (_targetRsaKeyTypeSelectedIndex != value)
                {
                    _targetRsaKeyTypeSelectedIndex = value;
                    RsaKeyType = (RSAKeyType)value;
                    OnPropertyChanged(nameof(TargetRsaKeyTypeSelectedIndex));
                }
            }
        }


        private RSAKeyPair _rsaKey = new("", "");
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


        private RSAKeyType _rsaKeyType;
        public RSAKeyType RsaKeyType
        {
            get { return _rsaKeyType; }
            set
            {
                if (_rsaKeyType != value)
                {
                    _rsaKeyType = value;
                    _rsaKeyFormat = 0;
                    TargetRsaKeyTypeSelectedIndex = (int)value;
                    OnPropertyChanged(nameof(RsaKeyType));
                    OnPropertyChanged(nameof(RsaKeyFormat));
                    OnPropertyChanged(nameof(CanExportTxtFormat));
                    OnPropertyChanged(nameof(CanExportPemFormat));
                    OnPropertyChanged(nameof(CanExportXmlFormat));
                }
            }
        }
        private int _rsaKeyFormat;
        public int RsaKeyFormat
        {
            get => _rsaKeyFormat;
            set
            {
                _rsaKeyFormat = value;
                OnPropertyChanged(nameof(RsaKeyFormat));
            }
        }

        public string KeyGenerateTips => IsGenerateKeyValid ? $"密钥格式：{RsaKeyType}" : "";
        public bool IsGenerateKeyValid => !(string.IsNullOrEmpty(RSAKey.PublicKey) && string.IsNullOrEmpty(RSAKey.PrivateKey));
        public Visibility RsaKeyTypeVisible => IsGenerateKeyValid ? Visibility.Visible : Visibility.Hidden;
        public SolidColorBrush KeyContentColor => IsGenerateKeyValid ? new SolidColorBrush(Color.FromArgb(255, 50, 50, 50)) : new SolidColorBrush(Color.FromArgb(255, 215, 215, 215));


        public bool CanExportTxtFormat => RSAKeyType.Pkcs1.Equals(_rsaKeyType) || RSAKeyType.Pkcs8.Equals(_rsaKeyType) || RSAKeyType.Xml.Equals(_rsaKeyType);
        public bool CanExportPemFormat => RSAKeyType.Pkcs1.Equals(_rsaKeyType) || RSAKeyType.Pkcs8.Equals(_rsaKeyType);
        public bool CanExportXmlFormat => RSAKeyType.Xml.Equals(_rsaKeyType);








        private string _orginalPrivateKey;
        private RSAKeyType? _orginalPrivateKeyType;
        public string OrginalPrivateKey
        {
            get => _orginalPrivateKey;
            set
            {
                _orginalPrivateKey = value;
                if (RSAKeyExtensions.IsValidPrivateKey(OrginalPrivateKey, out var keyType))
                {
                    _orginalPrivateKeyType = keyType;
                }
                OnPropertyChanged(nameof(OrginalPrivateKey));
                OnPropertyChanged(nameof(OrginalPrivateKeyType));
                OnPropertyChanged(nameof(OrginalPrivateKeyTypeVisible));
            }
        }
        public RSAKeyType? OrginalPrivateKeyType
        {
            get => _orginalPrivateKeyType;
            set
            {
                _orginalPrivateKeyType = value;
                OnPropertyChanged(nameof(OrginalPrivateKeyType));
            }
        }
        public Visibility OrginalPrivateKeyTypeVisible => OrginalPrivateKeyType is not null ? Visibility.Visible : Visibility.Hidden;


    }
}
