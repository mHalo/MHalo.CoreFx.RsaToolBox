using MHalo.CoreFx.Helper;
using MHalo.CoreFx.RsaToolBox.Helpers.RSAExtensions;
using MHalo.CoreFx.RsaToolBox.ViewModels.Pages;
using Microsoft.Win32;
using System.IO;
using System.Text;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using Wpf.Ui;
using Wpf.Ui.Controls;
using MessageBox = Wpf.Ui.Controls.MessageBox;

namespace MHalo.CoreFx.RsaToolBox.Views.Pages
{
    public partial class RsaCryptPage : INavigableView<RsaCryptViewModel>
    {
        public RsaCryptViewModel ViewModel { get; }
        public ISnackbarService snackbarService;

        public RsaCryptPage(
            RsaCryptViewModel viewModel,
            ISnackbarService _snackbarService)
        {
            ViewModel = viewModel;
            DataContext = this;
            snackbarService = _snackbarService;
            InitializeComponent();
        }

        #region  公钥相关处理程序
        private async void PickUp_PublicKey_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new()
            {
                //InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                RestoreDirectory = true,
                Filter = "All files (*.*)|*.*"
            };

            if (openFileDialog.ShowDialog() != true)
            {
                return;
            }

            if (!File.Exists(openFileDialog.FileName))
            {
                return;
            }
            try
            {
                string content = await File.ReadAllTextAsync(openFileDialog.FileName);
                if(RSAKeyValidator.IsValidPublicKey(content, out var publicKeyType))
                {
                    ViewModel.PublickKey = content;
                    ViewModel.PublickKeyType = $"{publicKeyType}";
                    ViewModel.PublickKeyTypeVisible = Visibility.Visible;
                }
                else
                {
                    ViewModel.PublickKey = string.Empty;
                    ViewModel.PublickKeyType = string.Empty;
                    ViewModel.PublickKeyTypeVisible = Visibility.Hidden;
                    snackbarService.Show(
                        "读取失败",
                        "非有效的公钥字符",
                        ControlAppearance.Caution,
                        new SymbolIcon(SymbolRegular.Fluent24),
                        TimeSpan.FromSeconds(5)
                    );
                }
            }
            catch (IOException ex)
            {
                ViewModel.PublickKey = string.Empty;
                var uiMessageBox = new MessageBox
                {
                    Title = "打开失败",
                    Content = ex.Message,
                };
                _ = await uiMessageBox.ShowDialogAsync();
            }

        }
        private void OnPublicKeyTextBox_GetFocus(object sender, RoutedEventArgs e)
        {
            e.Handled = true;
            PublicKeyBox.SelectAll();
        }
        private void PublicKeyBox_PreviewDragOver(object sender, DragEventArgs e)
        {
            PublicKeyWrapper.BorderBrush = new SolidColorBrush(Color.FromArgb(255, 43, 138, 62));
            PublicKeyWrapper.Background = new SolidColorBrush(Color.FromArgb(255, 214, 255, 224));
            e.Handled = true;
        }
        private void PublicKeyBox_PreviewDragLeave(object sender, DragEventArgs e)
        {
            PublicKeyWrapper.BorderBrush = new SolidColorBrush(Color.FromArgb(255, 241, 241, 241));
            PublicKeyWrapper.Background = new SolidColorBrush(Color.FromArgb(0, 0, 0, 0));
            e.Handled = true;
        }
        private void PublicKeyBox_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data is not null && e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.Copy;
                e.Handled = true;
            }
            else
            {
                e.Effects = DragDropEffects.None;
            }
        }
        private async void PublicKeyBox_Drop(object sender, DragEventArgs e)
        {
            if (e.Data is not null && e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                try
                {
                    string[] files = e.Data.GetData(DataFormats.FileDrop) as string[] ?? Array.Empty<string>();
                    if (files.Length <= 0)
                    {
                        snackbarService.Show(
                            "读取失败",
                            "非有效的文件",
                            ControlAppearance.Caution,
                            new SymbolIcon(SymbolRegular.Fluent24),
                            TimeSpan.FromSeconds(5)
                        );
                        e.Handled = true;
                        return;
                    }
                    else
                    {
                        string file = files[0];
                        if (!File.Exists(file))
                        {
                            return;
                        }
                        try
                        {
                            string content = await File.ReadAllTextAsync(file);
                            if (RSAKeyValidator.IsValidPublicKey(content, out var publicKeyType))
                            {
                                ViewModel.PublickKey = content;
                                ViewModel.PublickKeyType = $"{publicKeyType}";
                                ViewModel.PublickKeyTypeVisible = Visibility.Visible;
                            }
                            else
                            {
                                ViewModel.PublickKey = string.Empty;
                                ViewModel.PublickKeyType = string.Empty;
                                ViewModel.PublickKeyTypeVisible = Visibility.Hidden;
                                snackbarService.Show(
                                    "读取失败",
                                    "非有效的公钥字符",
                                    ControlAppearance.Caution,
                                    new SymbolIcon(SymbolRegular.Fluent24),
                                    TimeSpan.FromSeconds(5)
                                );
                            }
                        }
                        catch (IOException ex)
                        {
                            ViewModel.PublickKey = string.Empty;
                            var uiMessageBox = new MessageBox
                            {
                                Title = "打开失败",
                                Content = ex.Message,
                            };
                            _ = await uiMessageBox.ShowDialogAsync();
                        }
                    }
                }
                catch (IOException ex)
                {
                    ViewModel.PublickKey = string.Empty;
                    var uiMessageBox = new MessageBox
                    {
                        Title = "打开失败",
                        Content = ex.Message,
                    };
                    _ = await uiMessageBox.ShowDialogAsync();
                }
                e.Handled = true;
            }
            else
            {
                snackbarService.Show(
                    "读取失败",
                    "非有效的公钥字符",
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
            }
            PublicKeyWrapper.BorderBrush = new SolidColorBrush(Color.FromArgb(255, 241, 241, 241));
            PublicKeyWrapper.Background = new SolidColorBrush(Color.FromArgb(0, 0, 0, 0));
        }
        #endregion

        #region 私钥相关处理程序
        private async void PickUp_PrivateKey_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new()
            {
                //InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                RestoreDirectory = true,
                Filter = "All files (*.*)|*.*"
            };

            if (openFileDialog.ShowDialog() != true)
            {
                return;
            }

            if (!File.Exists(openFileDialog.FileName))
            {
                return;
            }
            try
            {
                string content = await File.ReadAllTextAsync(openFileDialog.FileName);
                if (RSAKeyValidator.IsValidPrivateKey(content, out var privateKeyType))
                {
                    ViewModel.PrivateKey = content;
                    ViewModel.PrivateKeyType = $"{privateKeyType}";
                    ViewModel.PrivateKeyTypeVisible = Visibility.Visible;
                }
                else
                {
                    ViewModel.PrivateKey = string.Empty;
                    ViewModel.PrivateKeyType = string.Empty;
                    ViewModel.PrivateKeyTypeVisible = Visibility.Hidden;
                    snackbarService.Show(
                        "读取失败",
                        "非有效的私钥字符",
                        ControlAppearance.Caution,
                        new SymbolIcon(SymbolRegular.Fluent24),
                        TimeSpan.FromSeconds(5)
                    );
                }
            }
            catch (IOException ex)
            {
                ViewModel.PrivateKey = string.Empty;
                var uiMessageBox = new MessageBox
                {
                    Title = "打开失败",
                    Content = ex.Message,
                };
                _ = await uiMessageBox.ShowDialogAsync();
            }
        }
        private void OnPrivateKeyTextBox_GetFocus(object sender, RoutedEventArgs e)
        {
            e.Handled = true;
            PrivateKeyBox.SelectAll();
        }
        private void PrivateKeyBox_PreviewDragOver(object sender, DragEventArgs e)
        {
            PrivateKeyWrapper.BorderBrush = new SolidColorBrush(Color.FromArgb(255, 173, 84, 29));
            PrivateKeyWrapper.Background = new SolidColorBrush(Color.FromArgb(255, 255, 227, 209));
            e.Handled = true;
        }
        private void PrivateKeyBox_PreviewDragLeave(object sender, DragEventArgs e)
        {
            PrivateKeyWrapper.BorderBrush = new SolidColorBrush(Color.FromArgb(255, 241, 241, 241));
            PrivateKeyWrapper.Background = new SolidColorBrush(Color.FromArgb(0, 0, 0, 0));
            e.Handled = true;
        }
        private void PrivateKeyBox_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data is not null && e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.Copy;
                e.Handled = true;
            }
            else
            {
                e.Effects = DragDropEffects.None;
            }
        }
        private async void PrivateKeyBox_Drop(object sender, DragEventArgs e)
        {
            if (e.Data is not null && e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                try
                {
                    string[] files = e.Data.GetData(DataFormats.FileDrop) as string[] ?? Array.Empty<string>();
                    if (files.Length <= 0)
                    {
                        snackbarService.Show(
                            "读取失败",
                            "非有效的文件",
                            ControlAppearance.Caution,
                            new SymbolIcon(SymbolRegular.Fluent24),
                            TimeSpan.FromSeconds(5)
                        );
                        e.Handled = true;
                        return;
                    }
                    else
                    {
                        string file = files[0];
                        if (!File.Exists(file))
                        {
                            return;
                        }
                        try
                        {
                            string content = await File.ReadAllTextAsync(file);
                            if (RSAKeyValidator.IsValidPrivateKey(content, out var privateKeyType))
                            {
                                ViewModel.PrivateKey = content;
                                ViewModel.PrivateKeyType = $"{privateKeyType}";
                                ViewModel.PrivateKeyTypeVisible = Visibility.Visible;
                            }
                            else
                            {
                                ViewModel.PrivateKey = string.Empty;
                                ViewModel.PrivateKeyType = string.Empty;
                                ViewModel.PrivateKeyTypeVisible = Visibility.Hidden;
                                snackbarService.Show(
                                    "读取失败",
                                    "非有效的私钥字符",
                                    ControlAppearance.Caution,
                                    new SymbolIcon(SymbolRegular.Fluent24),
                                    TimeSpan.FromSeconds(5)
                                );
                            }
                        }
                        catch (IOException ex)
                        {
                            ViewModel.PrivateKey = string.Empty;
                            var uiMessageBox = new MessageBox
                            {
                                Title = "打开失败",
                                Content = ex.Message,
                            };
                            _ = await uiMessageBox.ShowDialogAsync();
                        }
                    }
                }
                catch (IOException ex)
                {
                    ViewModel.PrivateKey = string.Empty;
                    var uiMessageBox = new MessageBox
                    {
                        Title = "打开失败",
                        Content = ex.Message,
                    };
                    _ = await uiMessageBox.ShowDialogAsync();
                }
                e.Handled = true;
            }
            else
            {
                snackbarService.Show(
                    "读取失败",
                    "非有效的私钥字符",
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
            }
            PrivateKeyWrapper.BorderBrush = new SolidColorBrush(Color.FromArgb(255, 241, 241, 241));
            PrivateKeyWrapper.Background = new SolidColorBrush(Color.FromArgb(0, 0, 0, 0));
        }
        #endregion


        private void PublicKeyEncrypt_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(ViewModel.PublickKey))
            {
                snackbarService.Show(
                    "加密失败",
                    "未识别到有效的公钥字符",
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
                return;
            }
            if(string.IsNullOrEmpty(ViewModel.OrginalText))
            {
                snackbarService.Show(
                    "加密失败",
                    "请输入需要加密的原文",
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
                return;
            }
        }
        private void PublicKeyDecrypt_Click(object sender, RoutedEventArgs e)
        {

            if (string.IsNullOrEmpty(ViewModel.PublickKey))
            {
                snackbarService.Show(
                    "解密失败",
                    "未识别到有效的公钥字符",
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
            }
            if (string.IsNullOrEmpty(ViewModel.OrginalText))
            {
                snackbarService.Show(
                    "解密失败",
                    "请输入需要解密的原文",
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
                return;
            }
        }
        private void PrivateKeyEncrypt_Click(object sender, RoutedEventArgs e)
        {

            if (string.IsNullOrEmpty(ViewModel.PublickKey))
            {
                snackbarService.Show(
                    "加密失败",
                    "未识别到有效的私钥字符",
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
            }
            if (string.IsNullOrEmpty(ViewModel.OrginalText))
            {
                snackbarService.Show(
                    "加密失败",
                    "请输入需要加密的原文",
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
                return;
            }
        }
        private void PrivateKeyDecrypt_Click(object sender, RoutedEventArgs e)
        {

            if (string.IsNullOrEmpty(ViewModel.PublickKey))
            {
                snackbarService.Show(
                    "解密失败",
                    "未识别到有效的私钥字符",
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
            }
            if (string.IsNullOrEmpty(ViewModel.OrginalText))
            {
                snackbarService.Show(
                    "解密失败",
                    "请输入需要解密的原文",
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
                return;
            }
        }

        private void OrginalTextBox_FocusableChanged(object sender, DependencyPropertyChangedEventArgs e)
        {
             
        }
    }
}
