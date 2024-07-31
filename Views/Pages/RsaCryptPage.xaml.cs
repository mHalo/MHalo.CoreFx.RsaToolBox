using MHalo.CoreFx.Helper;
using MHalo.CoreFx.RsaToolBox.ViewModels.Pages;
using Microsoft.Win32;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
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
            DataObject.AddPastingHandler(PublicKeyBox, PublicKeyBox_Pasting);
            DataObject.AddPastingHandler(PrivateKeyBox, PrivateKeyBox_Pasting);
        }

        #region 私有方法
        /// <summary>
        /// 打开密钥文件
        /// </summary>
        /// <param name="fileName"></param>
        /// <returns></returns>
        private bool OpenDialogPickKeyFile(out string fileName)
        {
            fileName = string.Empty;
            OpenFileDialog openFileDialog = new()
            {
                //InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                RestoreDirectory = true,
                Filter = "All files (*.*)|*.*"
            };
            if (openFileDialog.ShowDialog() != true)
            {
                return false;
            }
            if (!File.Exists(openFileDialog.FileName))
            {
                return false;
            }
            fileName = openFileDialog.FileName;
            return true;
        }

        #endregion


        #region  公钥相关处理程序
        private async void PickUp_PublicKey_Click(object sender, RoutedEventArgs e)
        {
            if(!OpenDialogPickKeyFile(out string keyFile))
            {
                return;
            }
            try
            {
                string content = await File.ReadAllTextAsync(keyFile);
                if(RSAKeyExtensions.IsValidPublicKey(content, out var publicKeyType))
                {
                    ViewModel.PublickKey = content;
                }
                else
                {
                    ViewModel.PublickKey = string.Empty;
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
            PublicKeyBox.SelectAll();
            e.Handled = true;
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
                            if (RSAKeyExtensions.IsValidPublicKey(content, out var publicKeyType))
                            {
                                ViewModel.PublickKey = content;
                            }
                            else
                            {
                                ViewModel.PublickKey = string.Empty;
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
                    "非读取到有效的公钥字符",
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
            }
            PublicKeyWrapper.BorderBrush = new SolidColorBrush(Color.FromArgb(255, 241, 241, 241));
            PublicKeyWrapper.Background = new SolidColorBrush(Color.FromArgb(0, 0, 0, 0));
        }

        private void PublicKeyBox_Pasting(object sender, DataObjectPastingEventArgs e)
        {
            var isText = e.SourceDataObject.GetDataPresent(DataFormats.UnicodeText, true);
            if (!isText)
            {
                return;
            }
            var text = e.SourceDataObject.GetData(DataFormats.UnicodeText) as string;
            if (text == null)
            {
                return;
            }
            try
            {
                string content = text!;
                if (RSAKeyExtensions.IsValidPublicKey(content, out var publicKeyType))
                {
                    ViewModel.PublickKey = content;
                }
                else
                {
                    snackbarService.Show(
                        "读取失败",
                        "非读取到有效的公钥字符",
                        ControlAppearance.Caution,
                        new SymbolIcon(SymbolRegular.Fluent24),
                        TimeSpan.FromSeconds(5)
                    );
                }
            }
            catch { }
            e.CancelCommand();
        }
        #endregion

        #region 私钥相关处理程序
        private async void PickUp_PrivateKey_Click(object sender, RoutedEventArgs e)
        {
            if (!OpenDialogPickKeyFile(out string keyFile))
            {
                return;
            }
            try
            {
                string content = await File.ReadAllTextAsync(keyFile);
                if (RSAKeyExtensions.IsValidPrivateKey(content, out var privateKeyType))
                {
                    ViewModel.PrivateKey = content;
                }
                else
                {
                    ViewModel.PrivateKey = string.Empty;
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
                            "非读取到有效的私钥字符",
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
                            if (RSAKeyExtensions.IsValidPrivateKey(content, out var privateKeyType))
                            {
                                ViewModel.PrivateKey = content;
                            }
                            else
                            {
                                ViewModel.PrivateKey = string.Empty;
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

        private void PrivateKeyBox_Pasting(object sender, DataObjectPastingEventArgs e)
        {
            var isText = e.SourceDataObject.GetDataPresent(DataFormats.UnicodeText, true);
            if (!isText)
            {
                return;
            }
            if (e.SourceDataObject.GetData(DataFormats.UnicodeText) is not string text)
            {
                return;
            }
            try
            {
                string content = text!;
                if (RSAKeyExtensions.IsValidPrivateKey(content, out var privateKeyType))
                {
                    ViewModel.PrivateKey = content;
                }
                else
                {
                    snackbarService.Show(
                        "读取失败",
                        "非读取到有效的私钥字符",
                        ControlAppearance.Caution,
                        new SymbolIcon(SymbolRegular.Fluent24),
                        TimeSpan.FromSeconds(5)
                    );
                }
            }
            catch { }
            e.CancelCommand();
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

            try
            {
                if (ViewModel.PublicKeyType.HasValue)
                {
                    ViewModel.ResultText = RSAHelper.Encrypt(ViewModel.PublicKeyType.Value, ViewModel.OrginalText, ViewModel.PublickKey);
                }
                else
                {
                    snackbarService.Show(
                        "加密失败",
                        "未知异常",
                        ControlAppearance.Caution,
                        new SymbolIcon(SymbolRegular.Fluent24),
                        TimeSpan.FromSeconds(5)
                    );
                }
            }
            catch(Exception ex)
            {
                snackbarService.Show(
                    "加密失败",
                    ex.Message,
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
            }
        }
        private void PrivateKeyDecrypt_Click(object sender, RoutedEventArgs e)
        {

            if (string.IsNullOrEmpty(ViewModel.PrivateKey))
            {
                snackbarService.Show(
                    "解密失败",
                    "未识别到有效的私钥字符",
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
                return;
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
            try
            {
                if (ViewModel.PrivateKeyType.HasValue)
                {
                    ViewModel.ResultText = RSAHelper.Decrypt(ViewModel.PrivateKeyType.Value, ViewModel.OrginalText, ViewModel.PrivateKey);
                }
                else
                {
                    snackbarService.Show(
                        "加密失败",
                        "未知异常",
                        ControlAppearance.Caution,
                        new SymbolIcon(SymbolRegular.Fluent24),
                        TimeSpan.FromSeconds(5)
                    );
                }
            }
            catch (Exception ex)
            {
                snackbarService.Show(
                    "解密失败",
                    ex.Message,
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
            }
        }
        private void ExchangeOrginalTextAndResultText(object sender, RoutedEventArgs e)
        {
            ViewModel.OrginalText = ViewModel.ResultText;
            ViewModel.ResultText = string.Empty;
        }
        

        private void PrivateKeyEncrypt_Click(object sender, RoutedEventArgs e)
        {

            if (string.IsNullOrEmpty(ViewModel.PrivateKey))
            {
                snackbarService.Show(
                    "加密失败",
                    "未识别到有效的私钥字符",
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
                return;
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

            try
            {
                if (ViewModel.PrivateKeyType.HasValue)
                {
                    ViewModel.ResultText = RSAHelper.EncyptByPrivateKey(ViewModel.PrivateKeyType.Value, ViewModel.OrginalText, ViewModel.PrivateKey);
                }
                else
                {
                    snackbarService.Show(
                        "加密失败",
                        "未知异常",
                        ControlAppearance.Caution,
                        new SymbolIcon(SymbolRegular.Fluent24),
                        TimeSpan.FromSeconds(5)
                    );
                }
            }
            catch (Exception ex)
            {
                snackbarService.Show(
                    "加密失败",
                    ex.Message,
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
            }
        }
        private void PublicKeyDecrypt_Click(object sender, RoutedEventArgs e)
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
                return;
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


            try
            {
                if (ViewModel.PublicKeyType.HasValue)
                {
                    ViewModel.ResultText = RSAHelper.DecryptByPublicKey(ViewModel.PublicKeyType.Value, ViewModel.OrginalText, ViewModel.PublickKey);
                }
                else
                {
                    snackbarService.Show(
                        "解密失败",
                        "未知异常",
                        ControlAppearance.Caution,
                        new SymbolIcon(SymbolRegular.Fluent24),
                        TimeSpan.FromSeconds(5)
                    );
                }
            }
            catch (Exception ex)
            {
                snackbarService.Show(
                    "解密失败",
                    ex.Message,
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
            }
        }



    }
}
