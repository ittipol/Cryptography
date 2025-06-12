// Define base and modulus number
// These 2 number can share, not secret

// It should be a Primitive root modulo n, where n = prime number of modulusNumber
long baseNumber = 3;

// The modulus need to be a big number and a big prime number
long modulusNumber = 19;

// Define secret number (cannot share)
// Person A
long secretNumberA = 8;
// Person B
long secretNumberB = 15;

// Find modular exponent number for sharing across network, Sharing between person A and person B
// formula = (baseNumber power of your secret number) modulo with modulusNumber

var modularExponentA = Math.Pow(baseNumber, secretNumberA) % modulusNumber;
var modularExponentB = Math.Pow(baseNumber, secretNumberB) % modulusNumber;

Console.WriteLine("modularExponentA {0}", modularExponentA);
Console.WriteLine("modularExponentB {0}", modularExponentB);

// Share <modularExponentA> to person B
// Share <modularExponentB> to person A

// Receive a modular exponent number
// Find a secret key

var secretKeyPersonA = Math.Pow(modularExponentB, secretNumberA) % modulusNumber;
var secretKeyPersonB = Math.Pow(modularExponentA, secretNumberB) % modulusNumber;

// These 2 secret key will be same
Console.WriteLine("secret key A {0}", secretKeyPersonA);
Console.WriteLine("secret key B {0}", secretKeyPersonB);

Console.WriteLine("{0} == {1} --> {2}", secretKeyPersonA.ToString(), secretKeyPersonB.ToString(), (secretKeyPersonA == secretKeyPersonB).ToString());