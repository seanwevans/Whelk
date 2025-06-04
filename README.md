# Whelk - Homomorphic Password Management

Whelk is a secure password management application that leverages Microsoft SEAL's CKKS homomorphic encryption to perform password operations without exposing sensitive data in plaintext. This project demonstrates encoding, encryption, decryption, and validation of passwords using fully homomorphic encryption (FHE).

This project targets the .NET 6 runtime.

## Features
- **Homomorphic Encryption**: Protects passwords using CKKS encryption scheme.
- **Secure Storage**: Passwords are stored in encrypted form, preventing direct access to plaintext data.
- **Validation**: Passwords can be validated without decrypting the stored values.
- **Performance Monitoring**: Tracks execution time for performance evaluation.

## Requirements
- .NET 6 SDK or higher
- Microsoft SEAL (Simple Encrypted Arithmetic Library)
- Visual Studio or compatible C# IDE

## Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/username/whelk.git
    ```
2. Install Microsoft SEAL:
    ```bash
    dotnet add package Microsoft.Research.SEALNet
    ```
3. Open the project in Visual Studio.

## Usage
### Running the Program
To execute the program, build and run the `Program.cs` file.

```bash
cd whelk
dotnet run
```

### Password Storage and Validation
The program demonstrates password storage and validation using homomorphic encryption. Passwords are encoded as lists of doubles, encrypted, and stored securely.

Example outputs:
```
Storing passwords...
Validating passwords...
Validation for user1 with correct password: True
Validation for user2 with correct password: True
Validation for user1 with incorrect password: False
Execution time: 1234ms
```

## How It Works
### Key Components
- **EncryptionParameters**: Configures CKKS scheme with polynomial modulus degree and coefficient modulus.
- **Key Generation**: Generates public and secret keys for encryption and decryption.
- **Encoding**: Converts plaintext passwords into CKKS-compatible plaintexts.
- **Encryption/Decryption**: Encrypts and decrypts passwords using CKKS.
- **Password Validation**: Compares encrypted input passwords against stored encrypted passwords.

### Example Workflow
1. **Setup Encryption Parameters**:
   ```csharp
   var parms = new EncryptionParameters(SchemeType.CKKS)
   {
       PolyModulusDegree = 8192,
       CoeffModulus = CoeffModulus.Create(8192, new int[] { 60, 40, 40, 60 })
   };
   ```
2. **Generate Keys**:
   ```csharp
   var keys = GenerateKeys(context);
   ```
3. **Encode and Encrypt Password**:
   ```csharp
   var plaintext = EncodePassword(encoder, password, scale);
   var encryptedPassword = EncryptPassword(encryptor, plaintext);
   ```
4. **Store Password**:
   ```csharp
   StorePassword("user1", password, encoder, encryptor, scale);
   ```
5. **Validate Password**:
   ```csharp
   var isValid = ValidatePassword("user1", inputPassword, encoder, encryptor, decryptor, scale);
   ```

## Code Structure
- **Program.cs**: Main entry point containing password storage and validation logic.
- **Password Management**: Methods to encode, encrypt, decrypt, store, and validate passwords.

## Configuration
Modify the encryption parameters and scale to adjust the security level and performance.
```csharp
PolyModulusDegree = 8192
CoeffModulus = CoeffModulus.Create(8192, new int[] { 60, 40, 40, 60 })
scale = Math.Pow(2.0, 40)
```

## Performance Considerations
- Larger polynomial modulus degrees provide higher security but increase computation time.
- Adjust coefficient modulus to balance security and performance.

## License
This project is licensed under the MIT License.

## Contributions
Contributions are welcome! Feel free to submit issues or pull requests to improve functionality or add features.

