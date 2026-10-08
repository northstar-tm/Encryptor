using System.Security.Cryptography;
using System.Buffers.Binary;
using System.Text;

namespace NorthstarEncrypt.SmokeTests;

internal static class Program
{
    private const string Passphrase = "test-only-passphrase-2026";

    private static int Main()
    {
        var root = Path.Combine(Path.GetTempPath(), "northstar-smoke-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            FileRoundTrip(root);
            EmptyFileAndHeaderAuthentication(root);
            LegacyVersionOneCompatibility(root);
            FolderRoundTrip(root);
            Console.WriteLine("All Northstar encryption smoke checks passed.");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception);
            return 1;
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    private static void LegacyVersionOneCompatibility(string root)
    {
        const string name = "legacy.txt";
        const string contents = "Legacy Northstar container.";
        const int iterations = 600_000;
        const int tagSize = 16;
        var nameBytes = Encoding.UTF8.GetBytes(name);
        var salt = RandomNumberGenerator.GetBytes(16);
        var noncePrefix = RandomNumberGenerator.GetBytes(8);
        var header = new byte[48 + nameBytes.Length];
        Encoding.ASCII.GetBytes("NSTARCRY").CopyTo(header, 0);
        header[8] = 1;
        header[9] = 0;
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(10, 4), iterations);
        salt.CopyTo(header, 14);
        noncePrefix.CopyTo(header, 30);
        BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(38, 8), Encoding.UTF8.GetByteCount(contents));
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(46, 2), checked((ushort)nameBytes.Length));
        nameBytes.CopyTo(header, 48);

        var plaintext = Encoding.UTF8.GetBytes(contents);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[tagSize];
        var nonce = new byte[12];
        noncePrefix.CopyTo(nonce, 0);
        var aad = new byte[header.Length + 8];
        header.CopyTo(aad, 0);
        BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(header.Length, 4), 0);
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(header.Length + 4, 4), plaintext.Length);
        var key = Rfc2898DeriveBytes.Pbkdf2(Passphrase, salt, iterations, HashAlgorithmName.SHA256, 32);
        using (var aes = new AesGcm(key, tagSize)) aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        CryptographicOperations.ZeroMemory(key);

        var encrypted = Path.Combine(root, "legacy.crypt");
        var restored = Path.Combine(root, "legacy-restored.txt");
        using (var output = new FileStream(encrypted, FileMode.CreateNew))
        {
            output.Write(header);
            output.Write(ciphertext);
            output.Write(tag);
        }

        CryptoContainer.Decrypt(encrypted, restored, Passphrase, null, CancellationToken.None);
        Require(File.ReadAllText(restored) == contents, "Version-1 archive did not decrypt.");
    }

    private static void EmptyFileAndHeaderAuthentication(string root)
    {
        var source = Path.Combine(root, "empty.bin");
        var encrypted = Path.Combine(root, "empty.bin.crypt");
        var restored = Path.Combine(root, "empty-restored.bin");
        var modifiedHeader = Path.Combine(root, "modified-header.crypt");
        var modifiedOutput = Path.Combine(root, "modified-output.bin");
        File.WriteAllBytes(source, Array.Empty<byte>());

        CryptoContainer.EncryptFile(source, encrypted, Passphrase, null, CancellationToken.None);
        CryptoContainer.Decrypt(encrypted, restored, Passphrase, null, CancellationToken.None);
        Require(new FileInfo(restored).Length == 0, "Empty file did not round-trip.");

        var encryptedBytes = File.ReadAllBytes(encrypted);
        encryptedBytes[48] ^= 0x01;
        File.WriteAllBytes(modifiedHeader, encryptedBytes);
        try
        {
            CryptoContainer.Decrypt(modifiedHeader, modifiedOutput, Passphrase, null, CancellationToken.None);
            throw new InvalidOperationException("Modified empty-file metadata was accepted.");
        }
        catch (CryptographicException)
        {
            Require(!File.Exists(modifiedOutput), "Failed header authentication left an output file.");
        }
    }

    private static void FileRoundTrip(string root)
    {
        var source = Path.Combine(root, "payload.bin");
        var encrypted = Path.Combine(root, "payload.bin.crypt");
        var restored = Path.Combine(root, "restored.bin");
        var wrongPasswordOutput = Path.Combine(root, "wrong-password.bin");
        var tampered = Path.Combine(root, "tampered.crypt");
        var tamperedOutput = Path.Combine(root, "tampered-output.bin");
        var contents = RandomNumberGenerator.GetBytes(1_100_117);
        File.WriteAllBytes(source, contents);

        CryptoContainer.EncryptFile(source, encrypted, Passphrase, null, CancellationToken.None);
        var info = CryptoContainer.ReadInfo(encrypted);
        Require(info.Kind == PayloadKind.File && info.OriginalName == "payload.bin", "File metadata did not round-trip.");
        CryptoContainer.Decrypt(encrypted, restored, Passphrase, null, CancellationToken.None);
        Require(File.ReadAllBytes(restored).AsSpan().SequenceEqual(contents), "File contents did not round-trip.");

        try
        {
            CryptoContainer.Decrypt(encrypted, wrongPasswordOutput, "incorrect-passphrase", null, CancellationToken.None);
            throw new InvalidOperationException("An incorrect passphrase was accepted.");
        }
        catch (CryptographicException)
        {
            Require(!File.Exists(wrongPasswordOutput), "Failed decryption left a partial output file.");
        }

        var encryptedBytes = File.ReadAllBytes(encrypted);
        encryptedBytes[48 + "payload.bin".Length + 8] ^= 0x40;
        File.WriteAllBytes(tampered, encryptedBytes);
        try
        {
            CryptoContainer.Decrypt(tampered, tamperedOutput, Passphrase, null, CancellationToken.None);
            throw new InvalidOperationException("Tampered ciphertext was accepted.");
        }
        catch (CryptographicException)
        {
            Require(!File.Exists(tamperedOutput), "Tampered decryption left a partial output file.");
        }
    }

    private static void FolderRoundTrip(string root)
    {
        var source = Path.Combine(root, "source-folder");
        var encrypted = Path.Combine(root, "source-folder.crypt");
        var restored = Path.Combine(root, "restored-folder");
        Directory.CreateDirectory(Path.Combine(source, "nested"));
        Directory.CreateDirectory(Path.Combine(source, "empty"));
        File.WriteAllText(Path.Combine(source, "readme.txt"), "Northstar folder round trip.");
        var nestedContents = RandomNumberGenerator.GetBytes(4_321);
        File.WriteAllBytes(Path.Combine(source, "nested", "data.bin"), nestedContents);

        CryptoContainer.EncryptFolder(source, encrypted, Passphrase, null, CancellationToken.None);
        var info = CryptoContainer.ReadInfo(encrypted);
        Require(info.Kind == PayloadKind.Folder && info.OriginalName == "source-folder", "Folder metadata did not round-trip.");
        CryptoContainer.Decrypt(encrypted, restored, Passphrase, null, CancellationToken.None);
        Require(File.ReadAllText(Path.Combine(restored, "readme.txt")) == "Northstar folder round trip.", "Folder text file did not round-trip.");
        Require(File.ReadAllBytes(Path.Combine(restored, "nested", "data.bin")).AsSpan().SequenceEqual(nestedContents), "Nested folder data did not round-trip.");
        Require(Directory.Exists(Path.Combine(restored, "empty")), "Empty folder did not round-trip.");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}