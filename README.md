# Public Key Infrastructure (PKI)
## Symmetric key encryption / Secret key encryption
```
Plaintext 
  —> Encryption (use symmetric key) 
    -> Ciphertext 
      -> Decryption (use symmetric key) 
        -> Plaintext
```

## Asymmetric key encryption / Public key encryption
```
Plaintext 
  —> Encryption (use public key) 
    -> Ciphertext 
      -> Decryption (use private key) 
        -> Plaintext
```

## Digital signature
```
Original text 
  —> Signing (use private key) 
    -> Signed text 
      -> Verifying (use public key) 
        -> Verified text
```

## One way hash
```
Plaintext
  -> Hash with hashing Algorithms
    -> Message digest / Fingerprint
```

## Secure digital signature
```
Plaintext [1]
  -> Hash with hashing Algorithms
    -> Message digest
      -> Signing Message digest [2] (use private key)
        -> Plaintext [1] + Signature [2]
```

## X.509 certificate (Digital Certificate)
```
CA (Certification Authority)
  -> Generate Digital Certificate (Public key and Digital Signature)
```

**X.509 certificate chain**
```
Root CA
  -> Intermediate CA
    -> My Certificate
```

## Digital envelope
**Sender**
1. Sender encrypt data and send to receiver
    1. Sender generate secret key [1]
    2. Sender encrypt data/plaintext with secret key [1]
    3. Sender send encrypted data to receiver

2. Receiver generate asymmetric key
    1. Receiver generate asymmetric key (public key [2] and private key [3])
    2. Receiver send public key [2] to sender

3. Sender send encrypted secret key to receiver (Digital Envelope)    
    1. Sender encrypt secret key [1] with public key [2] from receiver
    2. Sender send encrypted secret key to receiver

**Receiver**
1. Receiver receive encrypted data and encrypted secret key (Digital Envelope)
2. Receiver decrypt encrypted secret key with private key [3] (Open Digital Envelope)
3. Receiver decrypt encrypted data with secret key [1]
4. Receiver can now read the data

## Secure negotiated sessions using SSL
1. Client request to Server (website)
```
Client -> Request -> Server
```
2. Server send certificate (Public key and Digital Signature) to client
```
Server -> Send certificate -> Client
```
3. Client send data to server
    1. Client generate secret key (Session key)
    2. Client encrypt data with secret key
    3. Client send encrypted data to server
    4. Client encrypt secret key with public key from certificate
    5. Client send encrypted secret key to server

# Cryptography algorithms
## Symmetric Key Encryption Algorithms
Use a same key both encrypts and decrypts data
- Data Encryption Standard (DES)
- Triple Data Encryption Standard (Triple DES)
- Advanced Encryption Standard (AES)
- International Data Encryption Algorithm (IDEA)
- TLS/SSL protocol

## Asymmetric Key Encryption Algorithms
Use a public key-private key pairing: data encrypted with the public key can only be decrypted with the private key
- Rivest Shamir Adleman (RSA)
- the Digital Signature Standard (DSS), which incorporates - the Digital Signature Algorithm (DSA)
- Elliptical Curve Cryptography (ECC)
- TLS/SSL protocol

## Digital Signature Algorithms
- RSA (RC4)
- the Digital Signature Standard (DSS), which incorporates - the Digital Signature Algorithm (DSA)
- SHA, MD2, MD5
- Elliptical Curve DSA

## Key Exchange Algorithms (Digital Envelope)
- RSA, ANSI x9.17
- the Diffie-Hellman exchange method

## JSON Web Token (JWT) with HMAC protection
- HS256 - HMAC with SHA-256, requires 256+ bit secret
- HS384 - HMAC with SHA-384, requires 384+ bit secret
- HS512 - HMAC with SHA-512, requires 512+ bit secret

## JSON Web Signature (JWS) with RSA
- RS256 - RSA PKCS#1 signature with SHA-256
- RS384 - RSA PKCS#1 signature with SHA-384
- RS512 - RSA PKCS#1 signature with SHA-512
- PS256 - RSA PSS signature with SHA-256
- PS384 - RSA PSS signature with SHA-384
- PS512 - RSA PSS signature with SHA-512

## JSON Web Signature (JWS) with Elliptic Curve (EC)
- ES256 - EC P-256 DSA with SHA-256
- ES384 - EC P-384 DSA with SHA-384
- ES512 - EC P-521 DSA with SHA-512

# Password
## Hashing Password
According to the Open Worldwide Application Security Project (OWASP) should:
- Use Argon2id
- Use bcrypt
- Use scrypt (for legacy systems)
- Use PBKDF2 with HMAC-SHA-256 (for FIPS-140 compliance)

## Password Storing
- A - Slow Hashing (bcrypt, scrypt, Argon2)
> - Run slowly
> - Use tons of power
> - Use tons of memory
- B - Hashing + Salting
- C - Hashing
- D - Encrypting
- F - Storing in plaintext