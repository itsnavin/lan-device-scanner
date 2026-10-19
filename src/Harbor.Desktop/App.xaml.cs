using System.Windows;

namespace Harbor.Desktop;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var window = new MainWindow(e.Args.Contains("--demo") || e.Args.Contains("--smoke-test"));
        MainWindow = window;
        window.Show();
        if (e.Args.Contains("--smoke-test"))
        {
            window.Dispatcher.InvokeAsync(() =>
            {
                try { window.VerifyDemo(); Shutdown(0); }
                catch (InvalidOperationException) { Shutdown(1); }
            }, System.Windows.Threading.DispatcherPriority.ApplicationIdle);
        }
    }
}
