using System.Security.Cryptography;

namespace FolderGuard.Services;

/// <summary>
/// PBKDF2-SHA256 password hashing. Plaintext passwords are never persisted and never logged.
/// </summary>
public static class PasswordService
{
    public const int SaltSize = 16;
    public const int HashSize = 32;
    public const int DefaultIterations = 600_000;
    public const int MinimumPasswordLength = 8;

    public sealed record PasswordMaterial(string SaltBase64, string HashBase64, int Iterations);

    /// <summary>Derives a new salt/hash pair for a password.</summary>
    public static PasswordMaterial Create(string password, int iterations = DefaultIterations)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password must not be empty.", nameof(password));
        if (iterations < 10_000)
            iterations = DefaultIterations;

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, HashSize);
        return new PasswordMaterial(Convert.ToBase64String(salt), Convert.ToBase64String(hash), iterations);
    }

    /// <summary>
    /// Verifies a candidate password in constant time against the stored salt/hash.
    /// Returns false on any malformed stored data instead of throwing.
    /// </summary>
    public static bool Verify(string? password, string saltBase64, string hashBase64, int iterations)
    {
        if (string.IsNullOrEmpty(password) ||
            string.IsNullOrEmpty(saltBase64) ||
            string.IsNullOrEmpty(hashBase64) ||
            iterations < 1)
        {
            return false;
        }

        byte[] salt;
        byte[] expected;
        try
        {
            salt = Convert.FromBase64String(saltBase64);
            expected = Convert.FromBase64String(hashBase64);
        }
        catch (FormatException)
        {
            return false;
        }

        if (salt.Length == 0 || expected.Length == 0)
            return false;

        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    /// <summary>Minimum policy enforced by the UI and by the service layer.</summary>
    public static bool IsAcceptable(string? password, out string error)
    {
        if (string.IsNullOrEmpty(password))
        {
            error = "Enter a password.";
            return false;
        }

        if (password.Length < MinimumPasswordLength)
        {
            error = $"Use at least {MinimumPasswordLength} characters.";
            return false;
        }

        error = string.Empty;
        return true;
    }

    /// <summary>Cheap strength hint for the UI (0-4).</summary>
    public static int Strength(string? password)
    {
        if (string.IsNullOrEmpty(password))
            return 0;

        var score = 0;
        if (password.Length >= 8) score++;
        if (password.Length >= 14) score++;
        if (password.Any(char.IsUpper) && password.Any(char.IsLower) && password.Any(char.IsDigit)) score++;
        if (password.Any(c => !char.IsLetterOrDigit(c))) score++;
        return Math.Clamp(score, 0, 4);
    }
}
