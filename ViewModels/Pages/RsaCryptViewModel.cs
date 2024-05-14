using MHalo.CoreFx.Helper;
using MHalo.CoreFx.RsaToolBox.Helpers.RSAExtensions;
using MHalo.CoreFx.RsaToolBox.Models;
using System.Windows.Media;
using Wpf.Ui.Controls;

namespace MHalo.CoreFx.RsaToolBox.ViewModels.Pages
{
    public partial class RsaCryptViewModel : ObservableObject
    {
        private string _publickKey;
        private string _privateKey;

        [ObservableProperty]
        private string _publickKeyType;
        [ObservableProperty]
        private string _privateKeyType;
        [ObservableProperty]
        private Visibility _publickKeyTypeVisible;
        [ObservableProperty]
        private Visibility _privateKeyTypeVisible;

        public RsaCryptViewModel()
        {
            _publickKey = "此处粘贴或点击右上角读取文件";
            _privateKey = "此处粘贴或点击右上角读取文件";
            _publickKeyTypeVisible = Visibility.Hidden;
            _privateKeyTypeVisible = Visibility.Hidden;
        }

        public string PublickKey
        {
            get => _publickKey;
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    _publickKey = "此处粘贴或点击右上角读取文件";
                }
                else
                {
                    _publickKey = value;
                }
                OnPropertyChanged(nameof(PublickKey));
            }
        }
        public string PrivateKey
        {
            get => _privateKey;
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    _privateKey = "此处粘贴或点击右上角读取文件";
                }
                else
                {
                    _privateKey = value;
                }
                OnPropertyChanged(nameof(PrivateKey));
            }
        }

    }
}
