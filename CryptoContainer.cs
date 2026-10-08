using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace NorthstarEncrypt;

internal enum PayloadKind : byte
{
    File = 0,
    Folder = 1
}

internal sealed record ContainerInfo(PayloadKind Kind, string OriginalName, long PayloadLength);

internal static class CryptoContainer
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("NSTARCRY");
    private const byte Version = 2;
    private const int Iterations = 600_000;
    private const int SaltSize = 16;
    private const int NoncePrefixSize = 8;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int ChunkSize = 1024 * 1024;
    private const int MaxNameBytes = 1024;
    private const long MaxFolderArchiveBytes = 1024L * 1024 * 1024;
    private const long MaxExpandedFolderBytes = 10L * 1024 * 1024 * 1024;
    private const int MaxFolderEntries = 100_000;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static void EncryptFile(string sourcePath, string destinationPath, string passphrase,
        IProgress<double>? progress, CancellationToken cancellationToken)
    {
        using var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read,
            ChunkSize, FileOptions.SequentialScan);
        Encrypt(source, source.Length, Path.GetFileName(sourcePath), PayloadKind.File, destinationPath,
            passphrase, progress, cancellationToken);
    }

    public static void EncryptFolder(string sourcePath, string destinationPath, string passphrase,
        IProgress<double>? progress, CancellationToken cancellationToken)
    {
        using var archive = new MemoryStream();
        using (var zip = new ZipArchive(archive, ZipArchiveMode.Create, true, Encoding.UTF8))
        {
            var enumerationOptions = new EnumerationOptions
            {
                RecurseSubdirectories = true,
                AttributesToSkip = FileAttributes.ReparsePoint
            };
            var entryCount = 0;
            foreach (var directory in Directory.EnumerateDirectories(sourcePath, "*", enumerationOptions))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (++entryCount > MaxFolderEntries) throw new IOException("The folder contains too many entries.");
                var relative = Path.GetRelativePath(sourcePath, directory).Replace(Path.DirectorySeparatorChar, '/');
                zip.CreateEntry(relative.TrimEnd('/') + "/");
            }

            foreach (var file in Directory.EnumerateFiles(sourcePath, "*", enumerationOptions))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (++entryCount > MaxFolderEntries) throw new IOException("The folder contains too many entries.");
                var relative = Path.GetRelativePath(sourcePath, file).Replace(Path.DirectorySeparatorChar, '/');
                var entry = zip.CreateEntry(relative, CompressionLevel.Optimal);
                using var entryStream = entry.Open();
                using var fileStream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read,
                    ChunkSize, FileOptions.SequentialScan);
                var buffer = new byte[ChunkSize];
                int read;
                while ((read = fileStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    entryStream.Write(buffer, 0, read);
                    if (archive.Length > MaxFolderArchiveBytes)
                    {
                        throw new IOException("The compressed folder archive exceeds the 1 GB in-memory limit.");
                    }
                }
            }
        }

        if (archive.Length > MaxFolderArchiveBytes)
        {
            throw new IOException("The compressed folder archive exceeds the 1 GB in-memory limit.");
        }

        archive.Position = 0;
        Encrypt(archive, archive.Length, Path.GetFileName(Path.TrimEndingDirectorySeparator(sourcePath)),
            PayloadKind.Folder, destinationPath, passphrase, progress, cancellationToken);
    }

    public static ContainerInfo ReadInfo(string containerPath)
    {
        using var input = new FileStream(containerPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        return ReadHeader(input).Info;
    }

    public static void Decrypt(string containerPath, string destinationPath, string passphrase,
        IProgress<double>? progress, CancellationToken cancellationToken)
    {
        using var input = new FileStream(containerPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            ChunkSize, FileOptions.SequentialScan);
        var parsed = ReadHeader(input);
        var info = parsed.Info;
        if (info.Kind == PayloadKind.Folder && info.PayloadLength > MaxFolderArchiveBytes)
        {
            throw new InvalidDataException("This folder archive exceeds the 1 GB in-memory limit supported by this version.");
        }

        var fullDestination = Path.GetFullPath(destinationPath);
        if (info.Kind == PayloadKind.File)
        {
            if (Directory.Exists(fullDestination))
            {
                throw new IOException("The output path is a directory.");
            }

            EnsureParentDirectory(fullDestination);
            WriteAtomically(fullDestination, output => DecryptPayload(input, parsed, passphrase, output, progress, cancellationToken));
            return;
        }

        if (File.Exists(fullDestination) || Directory.Exists(fullDestination))
        {
            throw new IOException("The output folder already exists. Choose a different location.");
        }

        var parent = Path.GetDirectoryName(fullDestination);
        if (string.IsNullOrEmpty(parent))
        {
            throw new IOException("Choose a valid parent folder for the restored folder.");
        }

        Directory.CreateDirectory(parent);
        var stagingDirectory = Path.Combine(parent, ".northstar-" + Guid.NewGuid().ToString("N"));
        try
        {
            using var archive = new MemoryStream(checked((int)info.PayloadLength));
            DecryptPayload(input, parsed, passphrase, archive, progress, cancellationToken);
            archive.Position = 0;
            Directory.CreateDirectory(stagingDirectory);
            ExtractArchive(archive, stagingDirectory, cancellationToken);
            Directory.Move(stagingDirectory, fullDestination);
        }
        catch
        {
            TryDeleteDirectory(stagingDirectory);
            throw;
        }
    }

    private static void Encrypt(Stream plaintext, long plaintextLength, string originalName, PayloadKind kind,
        string destinationPath, string passphrase, IProgress<double>? progress, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(passphrase))
        {
            throw new ArgumentException("A passphrase is required.", nameof(passphrase));
        }

        if (plaintextLength < 0 || (kind == PayloadKind.Folder && plaintextLength > MaxFolderArchiveBytes))
        {
            throw new IOException("The input is larger than this version supports.");
        }

        var safeName = Path.GetFileName(originalName);
        var nameBytes = StrictUtf8.GetBytes(safeName);
        if (nameBytes.Length is 0 or > MaxNameBytes)
        {
            throw new IOException("The original name is too long to store in the encrypted file.");
        }

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var noncePrefix = RandomNumberGenerator.GetBytes(NoncePrefixSize);
        var header = BuildHeader(kind, plaintextLength, nameBytes, salt, noncePrefix);
        var key = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, Iterations, HashAlgorithmName.SHA256, 32);
        var fullDestination = Path.GetFullPath(destinationPath);
        EnsureParentDirectory(fullDestination);
        if (File.Exists(fullDestination) || Directory.Exists(fullDestination))
        {
            CryptographicOperations.ZeroMemory(key);
            throw new IOException("The output already exists. Choose a different location.");
        }

        var temporaryPath = Path.Combine(Path.GetDirectoryName(fullDestination)!, ".northstar-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var output = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                       ChunkSize, FileOptions.SequentialScan))
            using (var aes = new AesGcm(key, TagSize))
            {
                output.Write(header);
                var headerTag = new byte[TagSize];
                aes.Encrypt(BuildNonce(noncePrefix, 0), ReadOnlySpan<byte>.Empty, Span<byte>.Empty,
                    headerTag, header);
                output.Write(headerTag);
                var plaintextBuffer = new byte[ChunkSize];
                var ciphertextBuffer = new byte[ChunkSize];
                var tag = new byte[TagSize];
                var remaining = plaintextLength;
                uint chunkIndex = 1;
                while (remaining > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var count = (int)Math.Min(ChunkSize, remaining);
                    ReadExactly(plaintext, plaintextBuffer.AsSpan(0, count));
                    var nonce = BuildNonce(noncePrefix, chunkIndex);
                    var aad = BuildAad(header, chunkIndex, count);
                    aes.Encrypt(nonce, plaintextBuffer.AsSpan(0, count), ciphertextBuffer.AsSpan(0, count), tag, aad);
                    output.Write(ciphertextBuffer, 0, count);
                    output.Write(tag);
                    remaining -= count;
                    chunkIndex = checked(chunkIndex + 1);
                    progress?.Report(plaintextLength == 0 ? 100 : (plaintextLength - remaining) * 100d / plaintextLength);
                }

                if (plaintext.ReadByte() != -1)
                {
                    throw new IOException("The source changed while it was being encrypted.");
                }

                output.Flush(true);
            }

            File.Move(temporaryPath, fullDestination);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            TryDeleteFile(temporaryPath);
        }
    }

    private static void DecryptPayload(Stream input, ParsedHeader parsed, string passphrase, Stream output,
        IProgress<double>? progress, CancellationToken cancellationToken)
    {
        var info = parsed.Info;
        var key = Rfc2898DeriveBytes.Pbkdf2(passphrase, parsed.Salt, parsed.Iterations, HashAlgorithmName.SHA256, 32);
        try
        {
            using var aes = new AesGcm(key, TagSize);
            uint chunkIndex = parsed.Version >= 2 ? 1u : 0u;
            if (parsed.Version >= 2)
            {
                var headerTag = new byte[TagSize];
                ReadExactly(input, headerTag);
                aes.Decrypt(BuildNonce(parsed.NoncePrefix, 0), ReadOnlySpan<byte>.Empty, headerTag,
                    Span<byte>.Empty, parsed.Header);
            }

            var ciphertextBuffer = new byte[ChunkSize];
            var plaintextBuffer = new byte[ChunkSize];
            var tag = new byte[TagSize];
            var remaining = info.PayloadLength;
            while (remaining > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var count = (int)Math.Min(ChunkSize, remaining);
                ReadExactly(input, ciphertextBuffer.AsSpan(0, count));
                ReadExactly(input, tag);
                var nonce = BuildNonce(parsed.NoncePrefix, chunkIndex);
                var aad = BuildAad(parsed.Header, chunkIndex, count);
                aes.Decrypt(nonce, ciphertextBuffer.AsSpan(0, count), tag, plaintextBuffer.AsSpan(0, count), aad);
                output.Write(plaintextBuffer, 0, count);
                remaining -= count;
                chunkIndex = checked(chunkIndex + 1);
                progress?.Report(info.PayloadLength == 0 ? 100 : (info.PayloadLength - remaining) * 100d / info.PayloadLength);
            }

            if (input.ReadByte() != -1)
            {
                throw new InvalidDataException("The encrypted file contains unexpected trailing data.");
            }

            output.Flush();
        }
        catch (CryptographicException exception)
        {
            throw new CryptographicException("The passphrase is incorrect or the encrypted file has been modified.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static ParsedHeader ReadHeader(Stream input)
    {
        var fixedPart = new byte[48];
        ReadExactly(input, fixedPart);
        using var fixedStream = new MemoryStream(fixedPart, false);
        using var reader = new BinaryReader(fixedStream, Encoding.UTF8);
        var magic = reader.ReadBytes(Magic.Length);
        if (!magic.AsSpan().SequenceEqual(Magic))
        {
            throw new InvalidDataException("This is not a Northstar .crypt file.");
        }

        var version = reader.ReadByte();
        if (version is not 1 and not Version)
        {
            throw new InvalidDataException("This .crypt file version is not supported by this app.");
        }

        var kind = (PayloadKind)reader.ReadByte();
        if (kind is not PayloadKind.File and not PayloadKind.Folder)
        {
            throw new InvalidDataException("The encrypted file has an invalid content type.");
        }

        var iterations = reader.ReadInt32();
        if (iterations is < 600_000 or > 2_000_000)
        {
            throw new InvalidDataException("The encrypted file has unsupported key-derivation settings.");
        }

        var salt = reader.ReadBytes(SaltSize);
        var noncePrefix = reader.ReadBytes(NoncePrefixSize);
        var payloadLength = reader.ReadInt64();
        var nameLength = reader.ReadUInt16();
        if (salt.Length != SaltSize || noncePrefix.Length != NoncePrefixSize || payloadLength < 0 || nameLength is 0 or > MaxNameBytes)
        {
            throw new InvalidDataException("The encrypted file header is invalid.");
        }

        var nameBytes = new byte[nameLength];
        ReadExactly(input, nameBytes);
        var originalName = StrictUtf8.GetString(nameBytes);
        if (string.IsNullOrWhiteSpace(originalName) || originalName is "." or ".." ||
            originalName.IndexOfAny(new[] { '/', '\\', ':', '\0' }) >= 0)
        {
            throw new InvalidDataException("The encrypted file contains an unsafe original name.");
        }

        var header = new byte[fixedPart.Length + nameBytes.Length];
        fixedPart.CopyTo(header, 0);
        nameBytes.CopyTo(header, fixedPart.Length);
        var info = new ContainerInfo(kind, originalName, payloadLength);
        return new ParsedHeader(info, version, iterations, salt, noncePrefix, header);
    }

    private static byte[] BuildHeader(PayloadKind kind, long payloadLength, byte[] nameBytes, byte[] salt, byte[] noncePrefix)
    {
        var header = new byte[48 + nameBytes.Length];
        Magic.CopyTo(header, 0);
        header[8] = Version;
        header[9] = (byte)kind;
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(10, 4), Iterations);
        salt.CopyTo(header, 14);
        noncePrefix.CopyTo(header, 30);
        BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(38, 8), payloadLength);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(46, 2), checked((ushort)nameBytes.Length));
        nameBytes.CopyTo(header, 48);
        return header;
    }

    private static byte[] BuildNonce(byte[] prefix, uint index)
    {
        var nonce = new byte[NonceSize];
        prefix.CopyTo(nonce, 0);
        BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(NoncePrefixSize), index);
        return nonce;
    }

    private static byte[] BuildAad(byte[] header, uint index, int count)
    {
        var aad = new byte[header.Length + 8];
        header.CopyTo(aad, 0);
        BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(header.Length, 4), index);
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(header.Length + 4, 4), count);
        return aad;
    }

    private static void ExtractArchive(Stream archive, string stagingDirectory, CancellationToken cancellationToken)
    {
        using var zip = new ZipArchive(archive, ZipArchiveMode.Read, false, Encoding.UTF8);
        if (zip.Entries.Count > MaxFolderEntries)
        {
            throw new InvalidDataException("The folder archive contains too many entries.");
        }

        var root = Path.GetFullPath(stagingDirectory) + Path.DirectorySeparatorChar;
        long expandedBytes = 0;
        foreach (var entry in zip.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var normalized = entry.FullName.Replace('/', Path.DirectorySeparatorChar);
            if (Path.IsPathRooted(normalized) || normalized.Contains(':') || normalized.Contains('\0') ||
                normalized.Split(Path.DirectorySeparatorChar).Any(part => part is "." or "..") ||
                (entry.ExternalAttributes >> 16 & 0xF000) == 0xA000)
            {
                throw new InvalidDataException("The folder archive contains an unsafe path or link.");
            }

            var target = Path.GetFullPath(Path.Combine(stagingDirectory, normalized));
            if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("The folder archive contains an unsafe path.");
            }

            if (entry.FullName.EndsWith('/'))
            {
                Directory.CreateDirectory(target);
                continue;
            }

            var targetDirectory = Path.GetDirectoryName(target)!;
            Directory.CreateDirectory(targetDirectory);
            using var source = entry.Open();
            using var destination = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            var buffer = new byte[ChunkSize];
            int read;
            while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
            {
                expandedBytes = checked(expandedBytes + read);
                if (expandedBytes > MaxExpandedFolderBytes)
                {
                    throw new InvalidDataException("The extracted folder exceeds the 10 GB safety limit.");
                }

                destination.Write(buffer, 0, read);
            }
        }
    }

    private static void WriteAtomically(string destinationPath, Action<Stream> write)
    {
        var temporaryPath = Path.Combine(Path.GetDirectoryName(destinationPath)!, ".northstar-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var output = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                       ChunkSize, FileOptions.SequentialScan))
            {
                write(output);
                output.Flush(true);
            }

            File.Move(temporaryPath, destinationPath);
        }
        finally
        {
            TryDeleteFile(temporaryPath);
        }
    }

    private static void EnsureParentDirectory(string path)
    {
        var parent = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(parent))
        {
            throw new IOException("Choose a valid output location.");
        }

        Directory.CreateDirectory(parent);
    }

    private static void ReadExactly(Stream stream, Span<byte> buffer)
    {
        while (!buffer.IsEmpty)
        {
            var read = stream.Read(buffer);
            if (read == 0)
            {
                throw new EndOfStreamException("The encrypted file is incomplete.");
            }

            buffer = buffer[read..];
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path)) Directory.Delete(path, true);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private sealed record ParsedHeader(ContainerInfo Info, byte Version, int Iterations, byte[] Salt, byte[] NoncePrefix, byte[] Header);
}