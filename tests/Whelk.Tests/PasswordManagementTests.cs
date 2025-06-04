using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Research.SEAL;
using Xunit;

public class PasswordManagementTests
{

    [Fact]
    public void SetupEncryptionParameters_ReturnsExpectedSettings()
    {
        var parms = Program.SetupEncryptionParameters(out double scale);
        Assert.Equal(8192u, parms.PolyModulusDegree);
        Assert.Equal(Math.Pow(2.0, 40), scale);
    }

    [Fact]
    public void EncodeEncryptDecrypt_RoundTripMaintainsData()
    {
        var parms = Program.SetupEncryptionParameters(out double scale);
        using var context = new SEALContext(parms);
        var keys = Program.GenerateKeys(context);
        var encoder = new CKKSEncoder(context);
        var encryptor = new Encryptor(context, keys.PublicKey);
        var decryptor = new Decryptor(context, keys.SecretKey);
        var manager = new PasswordManager(encoder, encryptor, decryptor, scale);

        List<double> pwd = new() {1,2,3,4,5};
        var pt = manager.EncodePassword(pwd);
        var ct = manager.EncryptPassword(pt);
        var dpt = manager.DecryptPassword(ct);
        var decoded = manager.DecodePassword(dpt, pwd.Count);

        Assert.Equal(pwd, decoded);
    }

    [Fact]
    public void ValidatePassword_WorksForCorrectAndIncorrectPasswords()
    {
        var parms = Program.SetupEncryptionParameters(out double scale);
        using var context = new SEALContext(parms);
        var keys = Program.GenerateKeys(context);
        var encoder = new CKKSEncoder(context);
        var encryptor = new Encryptor(context, keys.PublicKey);
        var decryptor = new Decryptor(context, keys.SecretKey);
        var manager = new PasswordManager(encoder, encryptor, decryptor, scale);

        List<double> pwd = new() {1,2,3,4,5};
        manager.StorePassword("user", pwd);

        Assert.True(manager.ValidatePassword("user", pwd));
        var wrong = new List<double>{5,4,3,2,1};
        Assert.False(manager.ValidatePassword("user", wrong));
    }

    [Fact]
    public void PasswordManagementExample2_PrintsExpectedResults()
    {
        var parms = Program.SetupEncryptionParameters(out double scale);
        using var context = new SEALContext(parms);
        var keys = Program.GenerateKeys(context);
        var encoder = new CKKSEncoder(context);
        var encryptor = new Encryptor(context, keys.PublicKey);
        var decryptor = new Decryptor(context, keys.SecretKey);
        var evaluator = new Evaluator(context);

        using var sw = new StringWriter();
        Console.SetOut(sw);
        Program.PasswordManagementExample2(encoder, encryptor, decryptor, evaluator, scale);
        Console.Out.Flush();
        var output = sw.ToString();
        Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });

        Assert.Contains("Storing passwords...", output);
        Assert.Contains("Validating passwords...", output);
        Assert.Contains("Validation for user1 with correct password: True", output);
        Assert.Contains("Validation for user2 with correct password: True", output);
        Assert.Contains("Validation for user1 with incorrect password: False", output);
    }
}
