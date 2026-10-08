using System.IO;
using System.Windows;

namespace NorthstarEncrypt;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : System.Windows.Application
{
	protected override void OnStartup(StartupEventArgs e)
	{
		base.OnStartup(e);
		ShutdownMode = ShutdownMode.OnExplicitShutdown;

		if (!AccessGate.VerifyOrEnroll())
		{
			Shutdown();
			return;
		}

		try
		{
			FileAssociation.RegisterCurrentUser();
		}
		catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
		{
		}

		var cryptPath = e.Args.FirstOrDefault(argument =>
			string.Equals(Path.GetExtension(argument), ".crypt", StringComparison.OrdinalIgnoreCase) && File.Exists(argument));
		var window = new MainWindow(cryptPath);
		MainWindow = window;
		ShutdownMode = ShutdownMode.OnMainWindowClose;
		window.Show();
	}
}

