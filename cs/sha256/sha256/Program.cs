using System.Security.Cryptography;

var strToHashCode = "message";
var result = string.Empty;

using (var sha = SHA256.Create())
{
    byte[] strData = System.Text.Encoding.UTF8.GetBytes(strToHashCode);
    byte[] hash = sha.ComputeHash(strData);
    result =  BitConverter.ToString(hash);
}

Console.WriteLine($"SHA256: {result}");