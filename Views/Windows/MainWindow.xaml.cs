using MHalo.CoreFx.RsaToolBox.ViewModels.Windows;
using System.Windows.Media;
using Wpf.Ui;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace MHalo.CoreFx.RsaToolBox.Views.Windows
{
    public partial class MainWindow : INavigationWindow
    {
        public MainWindowViewModel ViewModel { get; }

        public MainWindow(
            MainWindowViewModel viewModel,
            IPageService pageService,
            ISnackbarService snackbarService,
            INavigationService navigationService
        )
        {
            ViewModel = viewModel;
            DataContext = this;

            SystemThemeWatcher.Watch(this);

            InitializeComponent();
            SetPageService(pageService);

            snackbarService.SetSnackbarPresenter(SnackbarPresenter);
            navigationService.SetNavigationControl(NavigationView);
            if (NavigationView.TitleBar is not null)
            {
                NavigationView.TitleBar!.Margin = new Thickness(0, 0, 0, 0);

            }
            
        }

        #region INavigationWindow methods

        public INavigationView GetNavigation() => NavigationView;

        public bool Navigate(Type pageType) => NavigationView.Navigate(pageType);

        public void SetPageService(IPageService pageService) => NavigationView.SetPageService(pageService);

        public void ShowWindow() => Show();

        public void CloseWindow() => Close();

        #endregion INavigationWindow methods

        /// <summary>
        /// Raises the closed event.
        /// </summary>
        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);

            // Make sure that closing this window will begin the process of closing the application.
            Application.Current.Shutdown();
        }

        INavigationView INavigationWindow.GetNavigation()
        {
            throw new NotImplementedException();
        }

        public void SetServiceProvider(IServiceProvider serviceProvider)
        {
            throw new NotImplementedException();
        }
    }
}
