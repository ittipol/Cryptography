using System.Security.Cryptography;
using System.Text;

// 96bit = 12 byte
// 128bit = 16 byte
// 256bit = 32 byte
// 512bit = 64 byte
// 2048bit = 256 byte
// 4096bit = 512 byte

byte[] key = new byte[32];  // 32-byte, 256bit
new Random().NextBytes(key);
byte[] iv = new byte[16];  // 16-byte initialization vector
new Random().NextBytes(iv); // randomize the IV

Console.WriteLine("Key (Base64): " + Convert.ToBase64String(key));
Console.WriteLine("Key (Length): " + key.Length);

Console.WriteLine("IV (Base64): " + Convert.ToBase64String(iv));
Console.WriteLine("IV (Length): " + iv.Length);

string plainText = "message"; //Text to encode
byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
Console.WriteLine("plain Text: " + plainText);

byte[] cipherBytes = Encrypt(plainBytes, key, iv);
string cipherText = Convert.ToBase64String(cipherBytes);
Console.WriteLine("Cipher Text: " + cipherText);

byte[] decryptedBytes = Decrypt(cipherBytes, key, iv);
string decryptedText = Encoding.UTF8.GetString(decryptedBytes);
Console.WriteLine("Decrypted Text: " + decryptedText);

Console.WriteLine($"[Plain Text == Decrypted Text] => {decryptedText.Equals(plainText)}");

byte[] Encrypt(byte[] plainBytes, byte[] key, byte[] iv)
{
    byte[]? encryptedBytes = null;

    using (Aes aes = Aes.Create())
    {
        aes.KeySize = 256;
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using (ICryptoTransform encryptor = aes.CreateEncryptor())
        {
            encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
        }
    }

    return encryptedBytes;
}

byte[] Decrypt(byte[] cipherBytes, byte[] key, byte[] iv)
{
    byte[]? decryptedBytes = null;

    using (Aes aes = Aes.Create())
    {
        aes.KeySize = 256;
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using (ICryptoTransform decryptor = aes.CreateDecryptor())
        {
            decryptedBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
        }
    }

    return decryptedBytes;
}
