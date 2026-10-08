using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using WpfButton = System.Windows.Controls.Button;
using WpfColor = System.Windows.Media.Color;
using WpfFontFamily = System.Windows.Media.FontFamily;
using WpfMessageBox = System.Windows.MessageBox;

namespace NorthstarEncrypt;

internal static class AccessGate
{
    private static readonly byte[] Magic = "NSTARPIN"u8.ToArray();
    private const int Iterations = 600_000;
    private const int SaltLength = 16;
    private const int HashLength = 32;
    private const int MinimumCodeLength = 12;
    private const int MaximumCodeLength = 1024;

    public static bool VerifyOrEnroll()
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NorthstarEncrypt", "access.dat");
        if (!File.Exists(path)) return Enroll(path);

        try
        {
            var verifier = ReadVerifier(path);
            var failures = 0;
            var error = string.Empty;
            while (true)
            {
                var dialog = new AccessDialog(false);
                dialog.SetError(error);
                if (dialog.ShowDialog() != true) return false;
                var candidate = dialog.Code;
                var derived = Rfc2898DeriveBytes.Pbkdf2(candidate, verifier.Salt, verifier.Iterations,
                    HashAlgorithmName.SHA256, HashLength);
                var matches = CryptographicOperations.FixedTimeEquals(derived, verifier.Hash);
                CryptographicOperations.ZeroMemory(derived);
                if (matches) return true;

                failures++;
                if (failures >= 5)
                {
                    WpfMessageBox.Show("Too many incorrect attempts. Northstar will close; wait briefly before trying again.",
                        "Access denied", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }

                error = $"That access code is incorrect. {5 - failures} attempts remain.";
                if (failures >= 3) System.Threading.Thread.Sleep(1200);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException or CryptographicException)
        {
            WpfMessageBox.Show("The local access-code verifier could not be read. Northstar will not open.\n\n" + exception.Message,
                "Northstar access", MessageBoxButton.OK, MessageBoxImage.Error);
        }

        return false;
    }

    private static bool Enroll(string path)
    {
        var dialog = new AccessDialog(true);
        if (dialog.ShowDialog() != true) return false;
        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var hash = Rfc2898DeriveBytes.Pbkdf2(dialog.Code, salt, Iterations, HashAlgorithmName.SHA256, HashLength);
        var data = new byte[Magic.Length + 4 + SaltLength + HashLength];
        Magic.CopyTo(data, 0);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(Magic.Length, 4), Iterations);
        salt.CopyTo(data, Magic.Length + 4);
        hash.CopyTo(data, Magic.Length + 4 + SaltLength);
        CryptographicOperations.ZeroMemory(hash);

        var directory = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(directory);
        var temporaryPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllBytes(temporaryPath, data);
            File.Move(temporaryPath, path, false);
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    private static Verifier ReadVerifier(string path)
    {
        var data = File.ReadAllBytes(path);
        if (data.Length != Magic.Length + 4 + SaltLength + HashLength || !data.AsSpan(0, Magic.Length).SequenceEqual(Magic))
        {
            throw new InvalidDataException("The verifier file has an invalid format.");
        }

        var iterations = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(Magic.Length, 4));
        if (iterations is < 600_000 or > 2_000_000)
        {
            throw new InvalidDataException("The verifier has unsupported key-derivation settings.");
        }

        return new Verifier(iterations, data.AsSpan(Magic.Length + 4, SaltLength).ToArray(),
            data.AsSpan(Magic.Length + 4 + SaltLength, HashLength).ToArray());
    }

    private sealed record Verifier(int Iterations, byte[] Salt, byte[] Hash);

    private sealed class AccessDialog : Window
    {
        private readonly PasswordBox _codeBox = new();
        private readonly PasswordBox? _confirmationBox;
        private readonly TextBlock _errorText = new();
        private readonly bool _firstRun;

        public AccessDialog(bool firstRun)
        {
            _firstRun = firstRun;
            Title = firstRun ? "Set up Northstar access" : "Unlock Northstar";
            Width = 430;
            Height = firstRun ? 450 : 320;
            MaxHeight = Math.Max(320, SystemParameters.WorkArea.Height - 24);
            ResizeMode = ResizeMode.NoResize;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            Background = new SolidColorBrush(WpfColor.FromRgb(16, 23, 25));
            Foreground = new SolidColorBrush(WpfColor.FromRgb(233, 240, 238));
            FontFamily = new WpfFontFamily("Segoe UI");

            var panel = new StackPanel();
            panel.Children.Add(new TextBlock
            {
                Text = firstRun ? "Create an access code" : "Northstar is locked",
                FontSize = 24,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 0, 0, 8)
            });
            panel.Children.Add(new TextBlock
            {
                Text = firstRun
                    ? "Choose a private code you can remember. It must be at least 12 characters. Lost codes cannot be recovered."
                    : "Enter your access code to continue. You will be asked again each time Northstar opens.",
                TextWrapping = TextWrapping.Wrap,
                Foreground = new SolidColorBrush(WpfColor.FromRgb(145, 161, 159)),
                Margin = new Thickness(0, 0, 0, 20)
            });
            panel.Children.Add(new TextBlock { Text = firstRun ? "NEW ACCESS CODE" : "ACCESS CODE", Margin = new Thickness(0, 0, 0, 6) });
            StylePasswordBox(_codeBox);
            panel.Children.Add(_codeBox);

            if (firstRun)
            {
                panel.Children.Add(new TextBlock { Text = "CONFIRM ACCESS CODE", Margin = new Thickness(0, 16, 0, 6) });
                _confirmationBox = new PasswordBox();
                StylePasswordBox(_confirmationBox);
                panel.Children.Add(_confirmationBox);
            }

            _errorText.Foreground = new SolidColorBrush(WpfColor.FromRgb(240, 145, 124));
            _errorText.Margin = new Thickness(0, 12, 0, 0);
            _errorText.TextWrapping = TextWrapping.Wrap;
            panel.Children.Add(_errorText);

            var button = new WpfButton
            {
                Content = firstRun ? "Save access code" : "Unlock",
                IsDefault = true,
                Height = 42,
                Margin = new Thickness(0, 12, 0, 0),
                Background = new SolidColorBrush(WpfColor.FromRgb(101, 217, 178)),
                Foreground = new SolidColorBrush(WpfColor.FromRgb(16, 32, 27)),
                FontWeight = FontWeights.SemiBold
            };
            button.Click += Submit_Click;
            var layout = new Grid { Margin = new Thickness(24) };
            layout.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var scroll = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                Content = panel
            };
            layout.Children.Add(scroll);
            Grid.SetRow(button, 1);
            layout.Children.Add(button);
            Content = layout;
            Loaded += (_, _) => _codeBox.Focus();
        }

        public string Code => _codeBox.Password;
        public string Confirmation => _confirmationBox?.Password ?? string.Empty;

        public void SetError(string message) => _errorText.Text = message;

        private static void StylePasswordBox(PasswordBox box)
        {
            box.Padding = new Thickness(11, 9, 11, 9);
            box.FontSize = 15;
            box.Background = new SolidColorBrush(WpfColor.FromRgb(16, 23, 25));
            box.Foreground = new SolidColorBrush(WpfColor.FromRgb(233, 240, 238));
            box.BorderBrush = new SolidColorBrush(WpfColor.FromRgb(52, 66, 70));
        }

        private void Submit_Click(object sender, RoutedEventArgs e)
        {
            if (_firstRun && (Code.Length < MinimumCodeLength || Code.Length > MaximumCodeLength))
            {
                SetError($"Use between {MinimumCodeLength} and {MaximumCodeLength} characters.");
                return;
            }

            if (_confirmationBox is not null && !string.Equals(Code, Confirmation, StringComparison.Ordinal))
            {
                SetError("The access codes do not match.");
                _confirmationBox.Clear();
                _confirmationBox.Focus();
                return;
            }

            DialogResult = true;
        }
    }
}