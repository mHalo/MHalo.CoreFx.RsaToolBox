using System.Collections.ObjectModel;
using Wpf.Ui.Controls;

namespace MHalo.CoreFx.RsaToolBox.ViewModels.Windows
{
    public partial class MainWindowViewModel : ObservableObject
    {
        [ObservableProperty]
        private string _applicationTitle = "RSA 工具箱";

        [ObservableProperty]
        private ObservableCollection<object> _menuItems = new()
        {
            new NavigationViewItem()
            {
                Content = "密钥生成",
                Icon = new SymbolIcon { Symbol = SymbolRegular.Key24 },
                TargetPageType = typeof(Views.Pages.RsaKeyGeneratePage)
            },
            new NavigationViewItem()
            {
                Content = "RSA加密",
                Icon = new SymbolIcon { Symbol = SymbolRegular.LockClosed24 },
                TargetPageType = typeof(Views.Pages.RsaCryptPage)
            },
            new NavigationViewItem()
            {
                Content = "RSA验签",
                Icon = new SymbolIcon { Symbol = SymbolRegular.Checkmark24 },
                TargetPageType = typeof(Views.Pages.RsaCryptPage)
            }
        };

        [ObservableProperty]
        private ObservableCollection<object> _footerMenuItems = new()
        {
            //new NavigationViewItem()
            //{
            //    Content = "Settings",
            //    Icon = new SymbolIcon { Symbol = SymbolRegular.Settings24 },
            //    TargetPageType = typeof(Views.Pages.SettingsPage)
            //}
        };

        [ObservableProperty]
        private ObservableCollection<MenuItem> _trayMenuItems = new()
        {
            new MenuItem { Header = "Home", Tag = "tray_home" }
        };
    }
}
