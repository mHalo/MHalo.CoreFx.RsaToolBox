using MHalo.CoreFx.RsaToolBox.Services;
using MHalo.CoreFx.RsaToolBox.ViewModels.Pages;
using System;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography.X509Certificates;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Navigation;
using Wpf.Ui;
using Wpf.Ui.Controls;
using Wpf.Ui.Extensions;
using MessageBox = Wpf.Ui.Controls.MessageBox;

namespace MHalo.CoreFx.RsaToolBox.Views.Pages
{
    public partial class RsaKeyGeneratePage : INavigableView<RsaKeyGenerateViewModel>
    {
        public RsaKeyGenerateViewModel ViewModel { get; }
        public ISnackbarService snackbarService;
        public INavigationService navigationService;
        public IPageService pageService;
        public RsaKeyGeneratePage(
            RsaKeyGenerateViewModel viewModel,
            ISnackbarService _snackbarService,
            IPageService _pageService,
            INavigationService _navigationService
            )
        {
            ViewModel = viewModel;
            DataContext = this;
            pageService = _pageService;
            snackbarService = _snackbarService;
            navigationService = _navigationService;

            InitializeComponent();
        }

        private void GenerateKey_Click(object sender, RoutedEventArgs e)
        {
            snackbarService.Show(
                "提示信息",
                "密钥生成成功",
                ControlAppearance.Success,
                new SymbolIcon(SymbolRegular.Fluent24),
                TimeSpan.FromSeconds(5)
            );
        }

        private void PublicKey_Copy_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.Clear();
            Clipboard.SetText(ViewModel.RSAKey.PublicKey);
            snackbarService.Show(
                "提示信息",
                "公钥已复制到剪切板",
                ControlAppearance.Caution,
                new SymbolIcon(SymbolRegular.Fluent24),
                TimeSpan.FromSeconds(5)
            );
        }
        private void PrivateKey_Copy_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.Clear();
            Clipboard.SetText(ViewModel.RSAKey.PrivateKey);
            snackbarService.Show(
                "提示信息",
                "私钥已复制到剪切板",
                ControlAppearance.Danger,
                new SymbolIcon(SymbolRegular.Fluent24),
                TimeSpan.FromSeconds(5)
            );
        }
        

        private void RsaKeyType_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            
        }

        private async void OpenRSAFolder_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                System.Diagnostics.Process.Start("explorer.exe", ViewModel.RsaLocalFolder);
            }
            catch (Exception ex)
            {
                var uiMessageBox = new MessageBox
                {
                    Title = "打开失败",
                    Content = ex.Message,
                };
                _ = await uiMessageBox.ShowDialogAsync();
            }
        }

        private void PublicKeyBox_PreviewMouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            PublicKeyBox.SelectAll();
            e.Handled = true;
        }

        private void PrivateKeyBox_PreviewMouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            PrivateKeyBox.SelectAll();
            e.Handled = true;
        }

        private void SendToCrypt_Click(object sender, RoutedEventArgs e)
        {
            var cryptPage = pageService.GetPage<RsaCryptPage>();
            if(cryptPage == null)
            {
                return;
            }
            cryptPage.ViewModel.PublickKey = ViewModel.RSAKey.PublicKey;
            cryptPage.ViewModel.PrivateKey = ViewModel.RSAKey.PrivateKey;
            navigationService.Navigate(typeof(RsaCryptPage));
        }

        private void SendToSign_Click(object sender, RoutedEventArgs e)
        {
            var signPage = pageService.GetPage<RsaSignPage>();
            if (signPage == null)
            {
                return;
            }
            signPage.ViewModel.PublickKey = ViewModel.RSAKey.PublicKey;
            signPage.ViewModel.PrivateKey = ViewModel.RSAKey.PrivateKey;
            navigationService.Navigate(typeof(RsaSignPage));
        }
    }
}
