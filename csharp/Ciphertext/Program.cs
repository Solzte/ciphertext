using System.Security.Cryptography;
using System.Text;

namespace Ciphertext;

internal static class Crypto
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("CPT1");
    private const byte Version = 1;
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int Pbkdf2Iterations = 100_000;

    public static byte[] EncryptBytes(byte[] plaintext, string password)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new CryptographicException("Password cannot be empty.");
        }

        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] key = DeriveKey(password, salt);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSize];

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        byte[] encrypted = new byte[ciphertext.Length + tag.Length];
        Buffer.BlockCopy(ciphertext, 0, encrypted, 0, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, encrypted, ciphertext.Length, tag.Length);

        return Pack(salt, nonce, encrypted);
    }

    public static byte[] DecryptBytes(byte[] payload, string password)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new CryptographicException("Password cannot be empty.");
        }

        var (salt, nonce, encrypted) = Unpack(payload);
        byte[] key = DeriveKey(password, salt);
        byte[] ciphertext = new byte[encrypted.Length - TagSize];
        byte[] tag = new byte[TagSize];

        Buffer.BlockCopy(encrypted, 0, ciphertext, 0, ciphertext.Length);
        Buffer.BlockCopy(encrypted, ciphertext.Length, tag, 0, TagSize);

        byte[] plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }

    public static string Encrypt(string plaintext, string password)
    {
        byte[] payload = EncryptBytes(Encoding.UTF8.GetBytes(plaintext), password);
        return Convert.ToBase64String(payload);
    }

    public static string Decrypt(string ciphertext, string password)
    {
        byte[] payload = Convert.FromBase64String(ciphertext);
        return Encoding.UTF8.GetString(DecryptBytes(payload, password));
    }

    public static void EncryptFile(string inputPath, string password, string? outputPath = null)
    {
        string destination = outputPath ?? inputPath + ".enc";
        byte[] encrypted = EncryptBytes(File.ReadAllBytes(inputPath), password);
        File.WriteAllBytes(destination, encrypted);
        Console.WriteLine(destination);
    }

    public static void DecryptFile(string inputPath, string password, string? outputPath = null)
    {
        string destination = outputPath ?? (inputPath.EndsWith(".enc", StringComparison.OrdinalIgnoreCase)
            ? inputPath[..^4]
            : inputPath + ".decrypted");

        byte[] decrypted = DecryptBytes(File.ReadAllBytes(inputPath), password);
        File.WriteAllBytes(destination, decrypted);
        Console.WriteLine(destination);
    }

    private static byte[] DeriveKey(string password, byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            Pbkdf2Iterations,
            HashAlgorithmName.SHA256,
            32);
    }

    private static byte[] Pack(byte[] salt, byte[] nonce, byte[] encrypted)
    {
        byte[] payload = new byte[Magic.Length + 1 + SaltSize + NonceSize + encrypted.Length];
        Buffer.BlockCopy(Magic, 0, payload, 0, Magic.Length);
        payload[Magic.Length] = Version;
        Buffer.BlockCopy(salt, 0, payload, Magic.Length + 1, SaltSize);
        Buffer.BlockCopy(nonce, 0, payload, Magic.Length + 1 + SaltSize, NonceSize);
        Buffer.BlockCopy(encrypted, 0, payload, Magic.Length + 1 + SaltSize + NonceSize, encrypted.Length);
        return payload;
    }

    private static (byte[] Salt, byte[] Nonce, byte[] Encrypted) Unpack(byte[] payload)
    {
        int headerSize = Magic.Length + 1 + SaltSize + NonceSize;
        if (payload.Length < headerSize)
        {
            throw new CryptographicException("Payload is too short.");
        }

        for (int i = 0; i < Magic.Length; i++)
        {
            if (payload[i] != Magic[i])
            {
                throw new CryptographicException("Unknown ciphertext format.");
            }
        }

        if (payload[Magic.Length] != Version)
        {
            throw new CryptographicException("Unsupported format version.");
        }

        byte[] salt = payload.AsSpan(Magic.Length + 1, SaltSize).ToArray();
        byte[] nonce = payload.AsSpan(Magic.Length + 1 + SaltSize, NonceSize).ToArray();
        byte[] encrypted = payload.AsSpan(headerSize).ToArray();
        return (salt, nonce, encrypted);
    }
}

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            return RunInteractive();
        }

        try
        {
            return args[0] switch
            {
                "encrypt" => RunEncrypt(args),
                "decrypt" => RunDecrypt(args),
                "encrypt-file" => RunEncryptFile(args),
                "decrypt-file" => RunDecryptFile(args),
                _ => UnknownCommand(),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
    }

    private static int RunEncrypt(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: Ciphertext encrypt <text> [password]");
            return 1;
        }

        string password = args.Length > 2 ? args[2] : ReadPassword("Enter password: ");
        Console.WriteLine(Crypto.Encrypt(args[1], password));
        return 0;
    }

    private static int RunDecrypt(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: Ciphertext decrypt <ciphertext> [password]");
            return 1;
        }

        string password = args.Length > 2 ? args[2] : ReadPassword("Enter password: ");
        Console.WriteLine(Crypto.Decrypt(args[1], password));
        return 0;
    }

    private static int RunEncryptFile(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: Ciphertext encrypt-file <input> [password] [output]");
            return 1;
        }

        string password = args.Length > 2 ? args[2] : ReadPassword("Enter password: ");
        string? output = args.Length > 3 ? args[3] : null;
        Crypto.EncryptFile(args[1], password, output);
        return 0;
    }

    private static int RunDecryptFile(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: Ciphertext decrypt-file <input> [password] [output]");
            return 1;
        }

        string password = args.Length > 2 ? args[2] : ReadPassword("Enter password: ");
        string? output = args.Length > 3 ? args[3] : null;
        Crypto.DecryptFile(args[1], password, output);
        return 0;
    }

    private static int RunInteractive()
    {
        Console.WriteLine("Ciphertext (.NET)");
        Console.WriteLine("1) Encrypt text");
        Console.WriteLine("2) Decrypt text");
        Console.WriteLine("3) Encrypt file");
        Console.WriteLine("4) Decrypt file");
        Console.Write("Choice: ");
        string? choice = Console.ReadLine();

        string password = ReadPassword("Enter password: ");

        try
        {
            switch (choice)
            {
                case "1":
                    Console.Write("Text: ");
                    Console.WriteLine(Crypto.Encrypt(Console.ReadLine() ?? string.Empty, password));
                    break;
                case "2":
                    Console.Write("Ciphertext: ");
                    Console.WriteLine(Crypto.Decrypt(Console.ReadLine() ?? string.Empty, password));
                    break;
                case "3":
                    Console.Write("File: ");
                    Crypto.EncryptFile(Console.ReadLine() ?? string.Empty, password);
                    break;
                case "4":
                    Console.Write("File: ");
                    Crypto.DecryptFile(Console.ReadLine() ?? string.Empty, password);
                    break;
                default:
                    Console.Error.WriteLine("Invalid choice.");
                    return 1;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }

        return 0;
    }

    private static string ReadPassword(string prompt)
    {
        Console.Write(prompt);
        string? password = Console.ReadLine();
        if (string.IsNullOrEmpty(password))
        {
            throw new CryptographicException("Password cannot be empty.");
        }

        return password;
    }

    private static int UnknownCommand()
    {
        Console.Error.WriteLine("Unknown command. Use encrypt, decrypt, encrypt-file, or decrypt-file.");
        return 1;
    }
}
