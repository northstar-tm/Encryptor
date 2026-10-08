using System.Windows;
using System.IO;
using System.Security.Cryptography;
using Dialogs = Microsoft.Win32;
using Forms = System.Windows.Forms;

namespace NorthstarEncrypt;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    private bool _isBusy;
    private ContainerInfo? _selectedContainerInfo;

    public MainWindow()
    {
        InitializeComponent();
    }

    public MainWindow(string? cryptPath) : this()
    {
        if (!string.IsNullOrWhiteSpace(cryptPath)) LoadCryptFile(cryptPath);
    }

    private bool IsEncryptMode => EncryptMode.IsChecked == true;

    private void Mode_Checked(object sender, RoutedEventArgs e)
    {
        if (InputPathBox is null) return;

        var encrypting = IsEncryptMode;
        TitleText.Text = encrypting ? "Encrypt your files" : "Restore your files";
        SubtitleText.Text = encrypting
            ? "Seal a file or an entire folder into one private archive."
            : "Open a Northstar archive and restore its original contents.";
        InputLabel.Text = encrypting ? "SOURCE FILE OR FOLDER" : "NORTHSTAR .CRYPT FILE";
        InputHint.Text = encrypting ? "Original file or folder stays unchanged." : "The archive stays unchanged.";
        OutputBrowseButton.Content = encrypting ? "Save as..." : "Choose output...";
        ChooseFolderButton.Visibility = encrypting ? Visibility.Visible : Visibility.Collapsed;
        ChooseFileButton.Content = encrypting ? "Choose file" : "Choose .crypt";
        ActionButton.Content = encrypting ? "Encrypt file" : "Decrypt archive";
        ConfirmPanel.Visibility = encrypting ? Visibility.Visible : Visibility.Collapsed;
        _selectedContainerInfo = null;
        InputPathBox.Clear();
        OutputPathBox.Clear();
        SetStatus("Ready. Choose what you want to " + (encrypting ? "protect." : "restore."), false);
    }

    private void ChooseFile_Click(object sender, RoutedEventArgs e)
    {
        var openDialog = new Dialogs.OpenFileDialog
        {
            Title = IsEncryptMode ? "Choose a file to encrypt" : "Choose a Northstar encrypted file",
            Filter = IsEncryptMode ? "All files (*.*)|*.*" : "Northstar encrypted files (*.crypt)|*.crypt|All files (*.*)|*.*",
            CheckFileExists = true
        };
        if (openDialog.ShowDialog(this) != true) return;

        if (IsEncryptMode)
        {
            SetEncryptionSource(openDialog.FileName);
            return;
        }

        LoadCryptFile(openDialog.FileName);
    }

    private void LoadCryptFile(string path)
    {
        DecryptMode.IsChecked = true;
        try
        {
            _selectedContainerInfo = CryptoContainer.ReadInfo(path);
            InputPathBox.Text = path;
            var parent = Path.GetDirectoryName(path)!;
            OutputPathBox.Text = Path.Combine(parent, _selectedContainerInfo.OriginalName);
            OutputBrowseButton.Content = _selectedContainerInfo.Kind == PayloadKind.File ? "Save as..." : "Choose folder...";
            SetStatus(_selectedContainerInfo.Kind == PayloadKind.Folder
                ? $"Folder archive · {_selectedContainerInfo.OriginalName}"
                : $"File archive · {_selectedContainerInfo.OriginalName}", false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            _selectedContainerInfo = null;
            SetStatus(exception.Message, true);
        }
    }

    private void ChooseFolder_Click(object sender, RoutedEventArgs e)
    {
        using var dialog = new Forms.FolderBrowserDialog
        {
            Description = "Choose a folder to encrypt",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = false
        };
        if (dialog.ShowDialog() == Forms.DialogResult.OK)
        {
            InputPathBox.Text = dialog.SelectedPath;
            OutputPathBox.Text = dialog.SelectedPath + ".crypt";
            SetStatus("Folder selected. It will be compressed before encryption.", false);
        }
    }

    private void SetEncryptionSource(string path)
    {
        InputPathBox.Text = path;
        OutputPathBox.Text = path + ".crypt";
        SetStatus("File selected and ready to encrypt.", false);
    }

    private void ChooseOutput_Click(object sender, RoutedEventArgs e)
    {
        if (IsEncryptMode)
        {
            var dialog = new Dialogs.SaveFileDialog
            {
                Title = "Save encrypted archive",
                Filter = "Northstar encrypted files (*.crypt)|*.crypt",
                DefaultExt = ".crypt",
                AddExtension = true,
                FileName = string.IsNullOrWhiteSpace(OutputPathBox.Text) ? "archive.crypt" : Path.GetFileName(OutputPathBox.Text),
                OverwritePrompt = false
            };
            if (dialog.ShowDialog(this) == true) OutputPathBox.Text = dialog.FileName;
            return;
        }

        if (_selectedContainerInfo is null) return;
        var parent = Path.GetDirectoryName(OutputPathBox.Text) ?? Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        if (_selectedContainerInfo.Kind == PayloadKind.File)
        {
            var dialog = new Dialogs.SaveFileDialog
            {
                Title = "Restore original file",
                FileName = _selectedContainerInfo.OriginalName,
                InitialDirectory = Directory.Exists(parent) ? parent : Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                OverwritePrompt = false
            };
            if (dialog.ShowDialog(this) == true) OutputPathBox.Text = dialog.FileName;
            return;
        }

        using var folderDialog = new Forms.FolderBrowserDialog
        {
            Description = "Choose where to restore the folder",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = true,
            SelectedPath = Directory.Exists(parent) ? parent : Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
        };
        if (folderDialog.ShowDialog() == Forms.DialogResult.OK)
        {
            OutputPathBox.Text = Path.Combine(folderDialog.SelectedPath, _selectedContainerInfo.OriginalName);
        }
    }

    private async void Action_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy) return;

        var sourcePath = InputPathBox.Text.Trim();
        var destinationPath = OutputPathBox.Text.Trim();
        var passphrase = PasswordBox.Password;
        if (string.IsNullOrWhiteSpace(sourcePath) || !File.Exists(sourcePath) && !Directory.Exists(sourcePath))
        {
            SetStatus("Choose an existing source file or folder first.", true);
            return;
        }

        if (string.IsNullOrWhiteSpace(destinationPath))
        {
            SetStatus("Choose an output location first.", true);
            return;
        }

        if (string.IsNullOrEmpty(passphrase))
        {
            SetStatus("Enter your passphrase to continue.", true);
            PasswordBox.Focus();
            return;
        }

        if (IsEncryptMode && passphrase.Length < 12)
        {
            SetStatus("Use a passphrase with at least 12 characters.", true);
            PasswordBox.Focus();
            return;
        }

        if (IsEncryptMode && passphrase != ConfirmPasswordBox.Password)
        {
            SetStatus("The passphrases do not match.", true);
            ConfirmPasswordBox.Focus();
            return;
        }

        if (!IsEncryptMode && (Directory.Exists(sourcePath) || _selectedContainerInfo is null))
        {
            SetStatus("Choose a valid Northstar .crypt file first.", true);
            return;
        }

        if (File.Exists(destinationPath) || Directory.Exists(destinationPath))
        {
            SetStatus("The output already exists. Choose a different output location.", true);
            return;
        }

        SetBusy(true);
        WorkProgress.Visibility = Visibility.Visible;
        WorkProgress.Value = 0;
        SetStatus(IsEncryptMode ? "Encrypting locally..." : "Authenticating and restoring locally...", false);
        var progress = new Progress<double>(value => WorkProgress.Value = value);
        try
        {
            var encrypting = IsEncryptMode;
            await Task.Run(() =>
            {
                if (encrypting)
                {
                    if (Directory.Exists(sourcePath))
                    {
                        CryptoContainer.EncryptFolder(sourcePath, destinationPath, passphrase, progress, CancellationToken.None);
                    }
                    else
                    {
                        CryptoContainer.EncryptFile(sourcePath, destinationPath, passphrase, progress, CancellationToken.None);
                    }
                }
                else
                {
                    CryptoContainer.Decrypt(sourcePath, destinationPath, passphrase, progress, CancellationToken.None);
                }
            });

            WorkProgress.Value = 100;
            SetStatus(encrypting ? "Encryption complete. Your original is unchanged." : "Restoration complete.", false);
            PasswordBox.Clear();
            ConfirmPasswordBox.Clear();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or CryptographicException or NotSupportedException or OverflowException)
        {
            SetStatus(exception.Message, true);
        }
        finally
        {
            SetBusy(false);
            WorkProgress.Visibility = Visibility.Collapsed;
        }
    }

    private void SetBusy(bool busy)
    {
        _isBusy = busy;
        ActionButton.IsEnabled = !busy;
        InputPathBox.IsEnabled = !busy;
        OutputPathBox.IsEnabled = !busy;
        PasswordBox.IsEnabled = !busy;
        ConfirmPasswordBox.IsEnabled = !busy;
        EncryptMode.IsEnabled = !busy;
        DecryptMode.IsEnabled = !busy;
    }

    private void SetStatus(string message, bool isError)
    {
        StatusText.Text = message;
        StatusText.Foreground = isError
            ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(240, 145, 124))
            : new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(145, 161, 159));
    }
}