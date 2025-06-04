using System;
using Microsoft.Research.SEAL;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;

class Program
{
    static Dictionary<string, Ciphertext> passwordDatabase = new Dictionary<string, Ciphertext>();

    internal static void ClearPasswordDatabase()
    {
        passwordDatabase.Clear();
    }

#if !EXCLUDE_MAIN
    static void Main(string[] args)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();

        try
        {         
            var encryptionParameters = SetupEncryptionParameters(out double scale);         
            var context = new SEALContext(encryptionParameters);
            
            var keys = GenerateKeys(context);

            var encoder = new CKKSEncoder(context);
            var encryptor = new Encryptor(context, keys.PublicKey);
            var decryptor = new Decryptor(context, keys.SecretKey);
            var evaluator = new Evaluator(context);
            
            PasswordManagementExample2(encoder, encryptor, decryptor, evaluator, scale);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An unexpected error occurred: {ex.Message}");
        }

        stopwatch.Stop();
        Console.WriteLine($"Execution time: {stopwatch.ElapsedMilliseconds}ms");
        Console.ReadLine();
    }
#endif

    internal static EncryptionParameters SetupEncryptionParameters(out double scale)
    {
        var parms = new EncryptionParameters(SchemeType.CKKS)
        {
            PolyModulusDegree = 8192,
            CoeffModulus = CoeffModulus.Create(8192, new int[] { 60, 40, 40, 60 })
        };
        scale = Math.Pow(2.0, 40);
        return parms;
    }

    internal static (PublicKey PublicKey, SecretKey SecretKey) GenerateKeys(SEALContext context)
    {
        var keygen = new KeyGenerator(context);
        var secretKey = keygen.SecretKey;
        keygen.CreatePublicKey(out var publicKey);
        return (publicKey, secretKey);
    }

    internal static Plaintext EncodePassword(CKKSEncoder encoder, List<double> plaintextPassword, double scale)
    {
        var plaintext = new Plaintext();
        encoder.Encode(plaintextPassword, scale, plaintext);
        return plaintext;
    }

    internal static Ciphertext EncryptPassword(Encryptor encryptor, Plaintext plaintext)
    {
        var encryptedPassword = new Ciphertext();
        encryptor.Encrypt(plaintext, encryptedPassword);
        return encryptedPassword;
    }

    internal static Plaintext DecryptPassword(Decryptor decryptor, Ciphertext encryptedPassword)
    {
        var decryptedPassword = new Plaintext();
        decryptor.Decrypt(encryptedPassword, decryptedPassword);
        return decryptedPassword;
    }

    internal static List<double> DecodePassword(CKKSEncoder encoder, Plaintext decryptedPassword, int count)
    {
        var decodedPassword = new List<double>();
        encoder.Decode(decryptedPassword, decodedPassword);
        return decodedPassword.Take(count).Select(x => Math.Round(x)).ToList();
    }

    internal static void StorePassword(string userId, List<double> plaintextPassword, CKKSEncoder encoder, Encryptor encryptor, double scale)
    {
        passwordDatabase[userId] = EncryptPassword(encryptor, EncodePassword(encoder, plaintextPassword, scale));
    }

    internal static bool ValidatePassword(string userId, List<double> inputPassword, CKKSEncoder encoder, Encryptor encryptor, Decryptor decryptor, double scale)
    {        
        if (!passwordDatabase.ContainsKey(userId)) 
            return false;

        var ep = EncodePassword(encoder, inputPassword, scale);
        var xp = EncryptPassword(encryptor, ep);

        var dp1 = DecryptPassword(decryptor, passwordDatabase[userId]);
        var dp2 = DecryptPassword(decryptor, xp);        
        
        return 
            DecodePassword(encoder, dp1, inputPassword.Count).SequenceEqual(
            DecodePassword(encoder, dp2, inputPassword.Count));
    }

    internal static void PasswordManagementExample2(CKKSEncoder encoder, Encryptor encryptor, Decryptor decryptor, Evaluator evaluator, double scale)
    {
        List<double> password1 = new List<double> { 1, 2, 3, 4, 5, 67, 7, 8, 9, 10 };
        List<double> password2 = new List<double> { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

        Console.WriteLine("Storing passwords...");
        StorePassword("user1", password1, encoder, encryptor, scale);
        StorePassword("user2", password2, encoder, encryptor, scale);

        Console.WriteLine("Validating passwords...");
        bool isValid1 = ValidatePassword("user1", password1, encoder, encryptor, decryptor, scale);
        bool isValid2 = ValidatePassword("user2", password2, encoder, encryptor, decryptor, scale);
        bool isInvalid = ValidatePassword("user1", password2, encoder, encryptor, decryptor, scale);

        Console.WriteLine($"Validation for user1 with correct password: {isValid1}");
        Console.WriteLine($"Validation for user2 with correct password: {isValid2}");
        Console.WriteLine($"Validation for user1 with incorrect password: {isInvalid}");
    }


    internal static void PasswordManagementExample(CKKSEncoder encoder, Encryptor encryptor, Decryptor decryptor, Evaluator evaluator, double scale)
    {
        List<double> plaintextPassword = new List<double>
        {
            1, 2, 3, 4, 5, 67, 7, 8, 9, 10,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            1, 255, 35, 4, 5, 6, 7, 8, 9, 255,
            1, 2, 3, 4, 15, 6, 7, 8, 9, 10,
            1, 2, 3, 4, 5, 65, 7, 8, 9, 10,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        };
        Console.WriteLine($"Original:  {string.Join(" ", plaintextPassword)}");

        try
        {
            // Encode
            var plaintext = EncodePassword(encoder, plaintextPassword, scale);

            // Encrypt
            var encryptedPassword = EncryptPassword(encryptor, plaintext);

            // Store or transfer the encrypted password
            //Console.WriteLine($"Encrypted: {encryptedPassword}");

            // Decrypt
            var decryptedPassword = DecryptPassword(decryptor, encryptedPassword);

            // Decode
            var decodedPassword = DecodePassword(encoder, decryptedPassword, plaintextPassword.Count);

            Console.Write("Decrypted: ");
            var roundedPassword = decodedPassword.Select(n => Math.Round(n)).ToList();
            Console.WriteLine(string.Join(" ", roundedPassword));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error during password management: {ex.Message}");
        }
    }

}
