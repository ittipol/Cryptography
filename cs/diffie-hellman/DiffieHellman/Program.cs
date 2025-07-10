using System.Collections;
using System.Numerics;
using System.Security.Cryptography;

var rand = new Random();

// ulong n = Convert.ToUInt64(rand.Next(1, 20001));
ulong n = 983;

var isPrimeNumber = isPrime(n);
Console.WriteLine("***************************************************************\n");
if (isPrimeNumber)
{
  var primeRootNumber = findPrimeRootNumber(n);
  Console.WriteLine($"primitive root number = {primeRootNumber.ToString()}");
  Console.WriteLine("***************************************************************\n");
  dh(n, primeRootNumber);
}

bool isPrime(ulong num)
{
  bool result = false;
  int k = 0;
  for (ulong i = 1; i <= num; i++)
  {
    if (num % i == 0)
    {
      k++;
    }
  }
  if (k == 2)
  {
    result = true;
    Console.WriteLine("Number is a Prime Number and " +
                      "the Largest Factor is {0}", num);
  }
  else
  {
    Console.WriteLine("{0} | Not a Prime Number", num.ToString());
  }

  return result;
}

ulong findPrimeRootNumber(ulong p)
{
  var rand = new Random();

  // r = 2
  // k = 1 to p-1

  var list = new List<ulong>();

  for (ulong r = 2; r < p; r++)
  {
    Console.WriteLine("\t\t -----> [ {0} ]", r.ToString());
    var hash = new Hashtable();
    var isDistinct = false;

    for (ulong k = 1; k < p; k++)
    {
      // var result = Math.Pow(r, k) % p;
      var result = BigInteger.ModPow(r, k, p);

      // var x = result % p;

      // if (x == result)
      // {
      //   Console.WriteLine("{0} mod {1} = {2}", result.ToString(), p.ToString(), x.ToString()); ;
      // }

      if (hash.ContainsKey(result))
      {
        Console.WriteLine("\t\t\t\t({0}^{1}) mod {2} = {3} -----> The results [ {4} ] are distinct", r.ToString(), k.ToString(), p.ToString(), result.ToString(), result.ToString());
        isDistinct = true;
      }
      else
      {
        hash.Add(result, true);
        Console.WriteLine("\t\t\t\t({0}^{1}) mod {2} = {3}", r.ToString(), k.ToString(), p.ToString(), result.ToString());
      }      
    }

    if (isDistinct)
    {
      Console.WriteLine("\t\tThe results are distinct, so [ {0} ] is not a primitive root of [ {1} ]", r.ToString(), p.ToString());
    }
    else
    {
      Console.WriteLine("\t\t [########] The results are not distinct, so [ {0} ] is a primitive root of [ {1} ]", r.ToString(), p.ToString());
      list.Add(r);
    }

    Console.WriteLine("\n*******************************************************************************************\n");
  }

  Console.WriteLine("Primilitive number of [{0}]", p.ToString());

  list.ForEach(x =>
  {
    Console.Write("{0}, ", x.ToString());
  });

  Console.WriteLine("\n*******************************************************************************************\n");

  return list[rand.Next(0, list.Count)];
}

void findFactor(ulong num)
{
  var factor = new List<ulong>();
  for (ulong i = 1; i < num; i++)
  {
    var result = num % i;
    Console.WriteLine("{0} % {1} = {2}", num.ToString(), i.ToString(), result.ToString());
    if (result == 0)
    {
      Console.WriteLine("===> {0}", i.ToString());
      factor.Add(i);
    }
  }
}

BigInteger? dh(ulong modulusNumber, ulong baseNumber)
{
  var rand = new Random();

  // The modulus need to be a big number and a big prime number
  // p --> prime number
  Console.WriteLine("p = {0}", modulusNumber);

  // prime root number of p
  // g --> generator of p
  Console.WriteLine("g = {0}", baseNumber);
  Console.WriteLine("\n");

  // generates a private key (a secret random number)
  // range = 1 to p - 1
  long privateKeyA = rand.NextInt64(1, Convert.ToInt64(modulusNumber));
  long privateKeyB = rand.NextInt64(1, Convert.ToInt64(modulusNumber));

  Console.WriteLine("privateKeyA {0}", privateKeyA);
  Console.WriteLine("privateKeyB {0}", privateKeyB);
  Console.WriteLine("\n");

  // var publicKeyA = BigInteger.Pow(baseNumber, privateKeyA) % modulusNumber;
  // var publicKeyB = BigInteger.Pow(baseNumber, privateKeyB) % modulusNumber;
  var publicKeyA = BigInteger.ModPow(baseNumber, privateKeyA, modulusNumber);
  var publicKeyB = BigInteger.ModPow(baseNumber, privateKeyB, modulusNumber);

  // Public key exchange
  Console.WriteLine("publicKeyA {0}", publicKeyA);
  Console.WriteLine("publicKeyB {0}", publicKeyB);
  Console.WriteLine("\n");

  // =================================================================================
  // Shared secret calculation
  // var secretKeyPersonA = BigInteger.Pow(publicKeyB, privateKeyA) % modulusNumber;
  // var secretKeyPersonB = BigInteger.Pow(publicKeyA, privateKeyB) % modulusNumber;
  var secretKeyPersonA = BigInteger.ModPow(publicKeyB, privateKeyA, modulusNumber);
  var secretKeyPersonB = BigInteger.ModPow(publicKeyA, privateKeyB, modulusNumber);

  // These 2 secret key will be same
  Console.WriteLine("secret key A {0}", secretKeyPersonA);
  Console.WriteLine("secret key B {0}", secretKeyPersonB);
  Console.WriteLine("\n");

  // var k = BigInteger.Pow(baseNumber, privateKeyA * privateKeyB) % modulusNumber;
  // Shared secret calculation
  var k = BigInteger.ModPow(baseNumber, privateKeyA * privateKeyB, modulusNumber);

  Console.WriteLine("k --> {0}", k);

  var match1 = secretKeyPersonA == secretKeyPersonB;
  var match2 = k == secretKeyPersonA;
  var match3 = k == secretKeyPersonB;

  Console.WriteLine("Keys match --> {0}", match1);
  Console.WriteLine("Keys match --> {0}", match2);
  Console.WriteLine("Keys match --> {0}", match3);

  if (match1 && match2 && match3)
  {
    return k;
  }
  else
  {
    return null;
  }
}

void Encrypt(string plainText)
{
  using var aes = Aes.Create();
  aes.KeySize = 256; // 32 byte
  aes.BlockSize = 128; // 16 byte

  // Generate a random key and IV
  aes.GenerateKey();
  aes.GenerateIV();

  byte[] encryptedData;

  using (var encryptor = aes.CreateEncryptor())
  using (var memoryStreamEncrypt = new MemoryStream())
  {
    using (var cryptoStreamEncrypt = new CryptoStream(memoryStreamEncrypt, encryptor, CryptoStreamMode.Write))
    using (var streamWriterEncrypt = new StreamWriter(cryptoStreamEncrypt))
    {
      streamWriterEncrypt.Write(plainText);
    }

    encryptedData = memoryStreamEncrypt.ToArray();
  }
}

string Decrypt(byte[] cipherText, string key, byte[] iv)
{
  using var aes = Aes.Create();
  aes.KeySize = 256; // 32 byte
  aes.BlockSize = 128; // 16 byte
  aes.Key = Convert.FromBase64String(key);
  aes.IV = iv;

  using var decryptor = aes.CreateDecryptor();
  using var memoryStreamDecrypt = new MemoryStream(cipherText);
  using var cryptoStreamDecrypt = new CryptoStream(memoryStreamDecrypt, decryptor, CryptoStreamMode.Read);
  using var streamReaderDecrypt = new StreamReader(cryptoStreamDecrypt);

  try
  {
    return streamReaderDecrypt.ReadToEnd();
  }
  catch (CryptographicException ex)
  {
    throw new CryptographicException("Decryption failed", ex);
  }
}
