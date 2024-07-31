using MHalo.CoreFx.Helper;
using MHalo.CoreFx.RsaToolBox.Helpers.RSAExtensions;
using MHalo.CoreFx.RsaToolBox.ViewModels.Pages;
using Microsoft.Win32;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
    public partial class RsaTransKeyFormatPage : INavigableView<RsaTransKeyFormatViewModel>
    {
        public RsaTransKeyFormatViewModel ViewModel { get; }
        public ISnackbarService snackbarService;

        public RsaTransKeyFormatPage(
            RsaTransKeyFormatViewModel viewModel,
            ISnackbarService _snackbarService)
        {
            ViewModel = viewModel;
            DataContext = this;
            snackbarService = _snackbarService;
            InitializeComponent();
            DataObject.AddPastingHandler(OrginalPrivateKeyBox, OrginalPrivateKeyBox_Pasting);
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

        #region 私钥相关处理程序
        private async void PickUp_OrginalPrivateKey_Click(object sender, RoutedEventArgs e)
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
                    ViewModel.OrginalPrivateKey = content;
                }
                else
                {
                    ViewModel.OrginalPrivateKey = string.Empty;
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
                ViewModel.OrginalPrivateKey = string.Empty;
                var uiMessageBox = new MessageBox
                {
                    Title = "打开失败",
                    Content = ex.Message,
                };
                _ = await uiMessageBox.ShowDialogAsync();
            }
        }
        private void OnOrginalPrivateKeyTextBox_GetFocus(object sender, RoutedEventArgs e)
        {
            e.Handled = true;
            OrginalPrivateKeyBox.SelectAll();
        }
        private void OrginalPrivateKeyBox_PreviewDragOver(object sender, DragEventArgs e)
        {
            OrginalPrivateKeyWrapper.BorderBrush = new SolidColorBrush(Color.FromArgb(255, 173, 84, 29));
            OrginalPrivateKeyWrapper.Background = new SolidColorBrush(Color.FromArgb(255, 255, 227, 209));
            e.Handled = true;
        }
        private void OrginalPrivateKeyBox_PreviewDragLeave(object sender, DragEventArgs e)
        {
            OrginalPrivateKeyWrapper.BorderBrush = new SolidColorBrush(Color.FromArgb(255, 241, 241, 241));
            OrginalPrivateKeyWrapper.Background = new SolidColorBrush(Color.FromArgb(0, 0, 0, 0));
            e.Handled = true;
        }
        private void OrginalPrivateKeyBox_DragEnter(object sender, DragEventArgs e)
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
        private async void OrginalPrivateKeyBox_Drop(object sender, DragEventArgs e)
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
                                ViewModel.OrginalPrivateKey = content;
                            }
                            else
                            {
                                ViewModel.OrginalPrivateKey = string.Empty;
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
                            ViewModel.OrginalPrivateKey = string.Empty;
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
                    ViewModel.OrginalPrivateKey = string.Empty;
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
            OrginalPrivateKeyWrapper.BorderBrush = new SolidColorBrush(Color.FromArgb(255, 241, 241, 241));
            OrginalPrivateKeyWrapper.Background = new SolidColorBrush(Color.FromArgb(0, 0, 0, 0));
        }

        private void OrginalPrivateKeyBox_Pasting(object sender, DataObjectPastingEventArgs e)
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
                    ViewModel.OrginalPrivateKey = content;
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

        private void TransformKeyFormat_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(ViewModel.OrginalPrivateKey))
            {
                snackbarService.Show(
                    "转换失败",
                    "原始私钥字符不能为空",
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
                return;
            }
            if (!RSAKeyExtensions.IsValidPrivateKey(ViewModel.OrginalPrivateKey, out _))
            {
                snackbarService.Show(
                    "转换失败",
                    "未识别到有效的原始私钥字符",
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
                return;
            }

            if(RSAHelper.TryTransformKeyFormat(ViewModel.RsaKeyType, ViewModel.OrginalPrivateKey, out string publicKey, out string privateKey, ViewModel.RsaKeyFormat == 1))
            {
                ViewModel.RSAKey = new RSAKeyPair(publicKey, privateKey);
            }
            else
            {
                snackbarService.Show(
                    "转换失败",
                    "未知原因",
                    ControlAppearance.Caution,
                    new SymbolIcon(SymbolRegular.Fluent24),
                    TimeSpan.FromSeconds(5)
                );
                ViewModel.RSAKey = new RSAKeyPair("", "");
            }

            
        }
    }
}
