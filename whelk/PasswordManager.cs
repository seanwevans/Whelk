using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Research.SEAL;

public class PasswordManager
{
    private readonly CKKSEncoder _encoder;
    private readonly Encryptor _encryptor;
    private readonly Decryptor _decryptor;
    private readonly double _scale;
    private readonly Dictionary<string, Ciphertext> _passwordDatabase = new();

    public PasswordManager(CKKSEncoder encoder, Encryptor encryptor, Decryptor decryptor, double scale)
    {
        _encoder = encoder;
        _encryptor = encryptor;
        _decryptor = decryptor;
        _scale = scale;
    }

    public Plaintext EncodePassword(List<double> plaintextPassword)
    {
        var plaintext = new Plaintext();
        _encoder.Encode(plaintextPassword, _scale, plaintext);
        return plaintext;
    }

    public Ciphertext EncryptPassword(Plaintext plaintext)
    {
        var encryptedPassword = new Ciphertext();
        _encryptor.Encrypt(plaintext, encryptedPassword);
        return encryptedPassword;
    }

    public Plaintext DecryptPassword(Ciphertext encryptedPassword)
    {
        var decryptedPassword = new Plaintext();
        _decryptor.Decrypt(encryptedPassword, decryptedPassword);
        return decryptedPassword;
    }

    public List<double> DecodePassword(Plaintext decryptedPassword, int count)
    {
        var decodedPassword = new List<double>();
        _encoder.Decode(decryptedPassword, decodedPassword);
        return decodedPassword.Take(count).Select(x => Math.Round(x)).ToList();
    }

    public void StorePassword(string userId, List<double> plaintextPassword)
    {
        _passwordDatabase[userId] = EncryptPassword(EncodePassword(plaintextPassword));
    }

    public bool ValidatePassword(string userId, List<double> inputPassword)
    {
        if (!_passwordDatabase.ContainsKey(userId))
            return false;

        var ep = EncodePassword(inputPassword);
        var xp = EncryptPassword(ep);

        var dp1 = DecryptPassword(_passwordDatabase[userId]);
        var dp2 = DecryptPassword(xp);

        return DecodePassword(dp1, inputPassword.Count)
            .SequenceEqual(DecodePassword(dp2, inputPassword.Count));
    }

    public void ClearDatabase() => _passwordDatabase.Clear();
}
