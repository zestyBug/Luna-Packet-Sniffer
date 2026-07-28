namespace LunaPacketSniffer.App;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        ApplicationLog.Clear();
        ApplicationLog.Write("Application started.");
        DispatcherUnhandledException += (_, eventArgs) => ApplicationLog.Write(eventArgs.Exception);
        AppDomain.CurrentDomain.UnhandledException += (_, eventArgs) => ApplicationLog.Write((Exception)eventArgs.ExceptionObject);
        base.OnStartup(e);
    }
}
