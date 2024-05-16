using MHalo.CoreFx.Helper;
using MHalo.CoreFx.RsaToolBox.Helpers.RSAExtensions;
using MHalo.CoreFx.RsaToolBox.Models;
using System.Windows.Media;
using Wpf.Ui.Controls;

namespace MHalo.CoreFx.RsaToolBox.ViewModels.Pages
{
    public partial class RsaCryptViewModel : ObservableObject
    {
        private string _publicKey;
        private string _privateKey;
        private RSAKeyType? _publicKeyType;
        private RSAKeyType? _privateKeyType;

        public string PublickKey
        {
            get => _publicKey;
            set
            {
                _publicKey = value;
                if(RSAKeyValidator.IsValidPublicKey(_publicKey, out var keyType))
                {
                    _publicKeyType = keyType;
                }
                OnPropertyChanged(nameof(PublickKey));
                OnPropertyChanged(nameof(PublicKeyType));
                OnPropertyChanged(nameof(PublicKeyTypeVisible));
                OnPropertyChanged(nameof(PublicKeyEncryptEnabled));
            }
        }
        public string PrivateKey
        {
            get => _privateKey;
            set
            {
                _privateKey = value;
                if (RSAKeyValidator.IsValidPrivateKey(PrivateKey, out var keyType))
                {
                    _privateKeyType = keyType;
                }
                OnPropertyChanged(nameof(PrivateKey));
                OnPropertyChanged(nameof(PrivateKeyType));
                OnPropertyChanged(nameof(PrivateKeyTypeVisible));
                OnPropertyChanged(nameof(PrivateKeyEncryptEnabled));
            }
        }


        public Visibility PublicKeyTypeVisible => PublicKeyType is not null ? Visibility.Visible : Visibility.Hidden;
        public Visibility PrivateKeyTypeVisible => PrivateKeyType is not null ? Visibility.Visible : Visibility.Hidden;

        public RSAKeyType? PublicKeyType
        {
            get => _publicKeyType;
            set
            {
                _publicKeyType = value;
                OnPropertyChanged(nameof(PublicKeyType));
            }
        }
        public RSAKeyType? PrivateKeyType
        {
            get => _privateKeyType;
            set
            {
                _privateKeyType = value;
                OnPropertyChanged(nameof(PrivateKeyType));
            }
        }

        private string _orginalText;
        private string _resultText;

        public string OrginalText
        {
            get => _orginalText;
            set
            {
                _orginalText = value;
                OnPropertyChanged(nameof(OrginalText));
                OnPropertyChanged(nameof(PublicKeyEncryptEnabled));
                OnPropertyChanged(nameof(PrivateKeyEncryptEnabled));
            }
        }
        public string ResultText
        {
            get => _resultText;
            set
            {
                _resultText = value;
                OnPropertyChanged(nameof(ResultText));
            }
        }


        public bool PublicKeyEncryptEnabled => !string.IsNullOrWhiteSpace(_publicKey) && !string.IsNullOrWhiteSpace(_orginalText);
        public bool PrivateKeyEncryptEnabled => !string.IsNullOrWhiteSpace(_privateKey) && !string.IsNullOrWhiteSpace(_orginalText);

        public RsaCryptViewModel()
        {
            
        }

        

    }
}
