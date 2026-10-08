using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace NorthstarEncrypt;

internal static class FileAssociation
{
    private const string ProgId = "NorthstarEncrypt.crypt";

    public static void RegisterCurrentUser()
    {
        var executable = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executable) || !File.Exists(executable)) return;

        var appDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NorthstarEncrypt");
        Directory.CreateDirectory(appDirectory);
        var iconPath = Path.Combine(appDirectory, "northstar-lock.ico");
        if (!File.Exists(iconPath)) CreateLockIcon(iconPath);

        using (var extensionKey = Registry.CurrentUser.CreateSubKey(@"Software\Classes\.crypt"))
        {
            extensionKey?.SetValue("", ProgId, RegistryValueKind.String);
            extensionKey?.SetValue("Content Type", "application/x-northstar-crypt", RegistryValueKind.String);
            using var openWith = extensionKey?.CreateSubKey("OpenWithProgids");
            openWith?.SetValue(ProgId, Array.Empty<byte>(), RegistryValueKind.None);
        }

        using var appKey = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{ProgId}");
        appKey?.SetValue("", "Northstar encrypted file", RegistryValueKind.String);
        using (var iconKey = appKey?.CreateSubKey("DefaultIcon"))
        {
            iconKey?.SetValue("", $"\"{iconPath}\",0", RegistryValueKind.String);
        }

        using (var commandKey = appKey?.CreateSubKey(@"shell\open\command"))
        {
            commandKey?.SetValue("", $"\"{executable}\" \"%1\"", RegistryValueKind.String);
        }

        using (var supportedTypes = Registry.CurrentUser.CreateSubKey($@"Software\Classes\Applications\{Path.GetFileName(executable)}\SupportedTypes"))
        {
            supportedTypes?.SetValue(".crypt", "", RegistryValueKind.String);
        }

        SHChangeNotify(0x08000000, 0x0000, IntPtr.Zero, IntPtr.Zero);
    }

    private static void CreateLockIcon(string path)
    {
        using var bitmap = new Bitmap(64, 64);
        using (var graphics = Graphics.FromImage(bitmap))
        using (var background = new GraphicsPath())
        using (var body = new SolidBrush(Color.FromArgb(101, 217, 178)))
        using (var dark = new SolidBrush(Color.FromArgb(16, 32, 27)))
        using (var shackle = new Pen(Color.FromArgb(16, 32, 27), 6))
        {
            graphics.SmoothingMode = SmoothingMode.AntiAlias;
            graphics.Clear(Color.Transparent);
            background.AddArc(2, 2, 60, 60, 180, 90);
            background.AddArc(2, 2, 60, 60, 270, 90);
            background.AddArc(2, 2, 60, 60, 0, 90);
            background.AddArc(2, 2, 60, 60, 90, 90);
            background.CloseFigure();
            graphics.FillPath(body, background);
            graphics.DrawArc(shackle, 19, 11, 26, 30, 180, 180);
            graphics.FillRectangle(dark, 15, 28, 34, 24);
            graphics.FillEllipse(body, 29, 34, 6, 6);
            graphics.FillRectangle(body, 31, 38, 2, 7);
        }

        var handle = bitmap.GetHicon();
        try
        {
            using var icon = Icon.FromHandle(handle);
            using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            icon.Save(stream);
        }
        finally
        {
            DestroyIcon(handle);
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr handle);

    [DllImport("shell32.dll")]
    private static extern void SHChangeNotify(uint eventId, uint flags, IntPtr item1, IntPtr item2);
}