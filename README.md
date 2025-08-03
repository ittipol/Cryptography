# Cryptography

## Encoding • Hashing • Encryption
### Encoding
- Not security
- Not secrecy
- Reversible

**e.g.,**
- Binary
- Hex
- base64
- ASCII
- UTF-8

### Hashing
- Use for storing password
- Fixed length
- Not reversible

**e.g.,**
- SHA-256
  - Output 256 bits length (Base2)
  - Hex = 64 characters
  - Byte (ASCII) = 32 characters
  - e.g., ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d (Hex format)
- SHA-512
  - Output 512 bits length (Base2)
  - Hex = 128 characters
  - Byte (ASCII) = 64 characters
  - e.g., f8daf57a3347cc4d6b9d575b31fe6077e2cb487f60a96233c08cb479dbf31538cc915ec6d48bdbaa96ddc1a16db4f4f96f37276cfcb3510b8246241770d5952c (Hex format)
- HMACSHA256
  - Output 256 bits length (Base2)
  - Hex = 64 characters
  - Byte (ASCII) = 32 characters
  - e.g., 8b5f48702995c1598c573db1e21866a9b825d4a794d169d7060a03605796360b (Hex format)
- BCrypt
- Argon2

### Encryption
- Data confidentiality

**e.g.,**
- AES
  - Use symmetric keys
  - Key lengths: 128, 192, and 256 bits
  - AES-256: Use 256-bits for input block size and key size
  - AES-256 ECB Mode (Electronic Codebook)
    - Not secure to use, There is a security risk
  - AES-256 CBC Mode (Cipher Block Chaining)
    - Use Initialization Vector (IV)
  - AES-256 CFB Mode (Cipher Feedback)
  - AES-256 CTR Mode (Counter)
  - AES-256 GCM Mode (Galois/Counter)
    - Use nonce and authentication tag for encryption
- RSA
- Elliptic Curve Cryptography (ECC)

## Public Key Infrastructure (PKI)
### Symmetric key encryption / Secret key encryption
```
Plaintext 
  —> Encryption (use symmetric key) 
    -> Ciphertext 
      -> Decryption (use symmetric key) 
        -> Plaintext
```

### Asymmetric key encryption / Public key encryption
```
Plaintext 
  —> Encryption (use public key) 
    -> Ciphertext 
      -> Decryption (use private key) 
        -> Plaintext
```

### Digital signature
```
Original text
  —> Signing (use private key) 
    -> Signed text (signature)
      -> Verifying (use public key) 
        -> Verified text
```

### One way hash
```
Plaintext
  -> Hash with hashing Algorithms
    -> Message digest / Fingerprint
```
**Sender generate hash value (Message digest / Fingerprint)**
1. Sender create a message/data for sending to receiver
2. Sender hash a message/data with hash algorithms (SHA256, SHA512)
3. Sender send a message/data and hash value to receiver

**Receiver verify a message/data**
1. Receiver receive a message/data and hash value from sender
2. Receiver hash a message/data with hash algorithms same as sender (SHA256, SHA512)
3. Receiver compare a hash value with sender hash value
4. The both hash value must be equal, Otherwise if not equal, It mean a message/data is not send from trusted sender

### Secure digital signature
```
Plaintext [1]
  -> Hash with hashing algorithms
    -> Message digest
      -> Signing Message digest [2] (use private key)
        -> Plaintext [1] + Signature [2]
```

**Sender sign a digital signature**
1. Sender hash a message with hash algorithms
2. Sender generate an asymmetric key (public key and private key)
3. Sender encrypt a hash value with private key
4. Sender send a message and secure digital signature to receiver

``` bash
# Create source file
echo -n 'message' > data.txt

# Generate a private key and a public key in PEM format
openssl genrsa -out key.pem 4096

# Extract the public key in PEM format
openssl rsa -in key.pem -outform PEM -pubout -out key.pem.pub

# Hash a message/data with hash algorithms and sign with private key
openssl dgst -sha256 -sign key.pem -out sign.sha256 data.txt

# Encode to base64 format
openssl enc -base64 -in sign.sha256 -out sign.sha256.base64
```

**Receiver verify a digital signature**
``` bash
# Decode base64 format
openssl enc -base64 -d -in sign.sha256.base64 -out sign.sha256

# Verify the signature
openssl dgst -sha256 -verify key.pem.pub -signature sign.sha256 data.txt
```

### X.509 certificate (Digital Certificate)
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

**Create a self-signed certificate**
1. Generate certificate authority and trust certificate (CA)
``` bash
openssl genrsa -passout pass:${password} -des3 -out ca.key 4096

openssl req -passin pass:${password} -new -x509 -sha256 -days 365 -key ca.key -out ca.crt -subj "/CN=${server_common_name}"
# -subj "/C=${c}/ST=${st}/L=${l}/O=${o}/OU=${ou}/CN=${cn}"
```

2. Generate the private key and public key
``` bash
openssl genrsa -passout pass:${password} -des3 -out server.key 4096
```

3. Create certificate signing request (CSR)
``` bash
openssl req -passin pass:${password} -new -sha256 -key server.key -out server.csr -subj "/CN=${server_common_name}" -config ${config_file}
```

4. Sign the certificate with the CA
``` bash
openssl x509 -req -passin pass:${password} -sha256 -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt -extensions req_ext -extfile ${config_file}
```

**Read a certificate**
``` bash
openssl x509 -in server.crt -text -noout
```

**Check the modulus of an SSL certificate and private key** \
Hash value of certificate modulus must be equal with hash value of private key modulus
``` bash
# Hash value of private key modulus
openssl rsa -noout -modulus -in server.key | openssl sha256

# Hash value of certificate modulus
openssl x509 -noout -modulus -in server.crt | openssl sha256
```

**Get certificate fingerprint**
``` bash
openssl x509 -noout -fingerprint -sha256 -inform pem -in server.crt
```

### Digital envelope
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

### Secure negotiated sessions using SSL
1. TCP handshake
2. Certificate check
    1. Server send a certificate (Public key and Digital Signature) to client
    2. Client check the certificate with CA (issuer)
3. Key exchange
    1. Client generate a session key (secret key)
    2. Client encrypt session key with public key from certificate
    3. Client send encrypted session key to server
    4. Server receive an encrypted session key and decrypt an encrypted session key with private key
    5. Client and Server have a same session key (secret key)
4. Data transmission
    1. Client send data to server
        1. Client encrypt data with session key (secret key)
        2. Client send encrypted data to server
        3. Server receive an encrypted data from client
        4. Server decrypt an encrypted data with session key (secret key)
    2. Server send data to client
        1. Server encrypt data with session key (secret key)
        2. Server send encrypted data to client
        3. Client receive an encrypted data from server
        4. Client decrypt an encrypted data with session key (secret key)

## Cryptography algorithms
### Symmetric Key Encryption Algorithms
Use a same key both encrypts and decrypts data
- Data Encryption Standard (DES)
- Triple Data Encryption Standard (Triple DES)
- Advanced Encryption Standard (AES)
- International Data Encryption Algorithm (IDEA)
- TLS/SSL protocol

``` bash
# Key
# Random 256-bit key (32 bytes)
# Hex format
key = 561157f52ef5baf22e2781223fb9b46aede672371a4d160aff625dfdb1948e8c

# IV
# Random 128-bit key (16 bytes)
# Hex format
iv = e5f40aa9ee68b85f2ac2b90119d132c3

# AES256 encrypt
echo -n 'message' |  openssl aes-256-cbc -e -K {$key} -iv {$iv} | xxd -p

# AES256 decrypt
echo -n '{ciphertext}' | xxd -p -r | openssl aes-256-cbc -d -K {$key} -iv {$iv}
```

### Asymmetric Key Encryption Algorithms
Use a public key-private key pairing: data encrypted with the public key can only be decrypted with the private key
- Rivest Shamir Adleman (RSA)
- the Digital Signature Standard (DSS), which incorporates - the Digital Signature Algorithm (DSA)
- Elliptical Curve Cryptography (ECC)
- TLS/SSL protocol

**RSA**
``` bash
# Generate a private key and a public key in PEM format
openssl genrsa -out key.pem 2048
openssl genrsa -out key.pem 3072
openssl genrsa -out key.pem 4096

# Extract the public key in PEM format
openssl rsa -in key.pem -outform PEM -pubout -out key.pem.pub

# RSA encryption (Base64 format)
echo -n 'message' | openssl rsautl -encrypt -pubin -inkey key.pem.pub | base64 > encrypted_data
# RSA decryption (Base64 format)
cat encrypted_data | base64 -d | openssl rsautl -decrypt -inkey key.pem
# echo -n '{base64}' | base64 -d | openssl rsautl -decrypt -inkey key.pem

# RSA encryption (from file)
openssl rsautl -encrypt -in ./message.txt -out ./ciphertext -pubin -inkey key.pem.pub
# RSA decryption (from file)
openssl rsautl -decrypt -in ./ciphertext -out ./plaintext -inkey key.pem
```

**Elliptic curve cryptography (ECC)**
``` bash
# List a curve names
openssl ecparam -list_curves

# Generate a private key
openssl ecparam -name <curve> -genkey -noout -out private_key.pem
openssl ecparam -name prime256v1 -genkey -noout -out private_key.pem

# Extract the public key
openssl ec -in private_key.pem -outform PEM -pubout -out public_key.pem

# Generate the CSR
openssl req -new -sha256 -key private_key.pem -out my.csr
```

### Digital Signature Algorithms
**Use to create digital signatures**
- RSA (RC4)
- the Digital Signature Standard (DSS), which incorporates - the Digital Signature Algorithm (DSA)
- SHA, MD2, MD5
- Elliptic Curve Digital Signature Algorithm (ECDSA) (use elliptic curve cryptography (ECC))

### Key Exchange Algorithms (Digital Envelope)
- RSA, ANSI x9.17
- the Diffie-Hellman exchange method
  - ECDH (Elliptic Curve Diffie-Hellman) (use elliptic curve cryptography (ECC))

### Hash algorithms
- MD5
- SHA-224 (keyless)
- SHA-256 (keyless)
- SHA-384 (keyless)
- SHA-512 (keyless)
- HMAC (Hash-Based Message Authentication Code)
  - HmacSHA256 (Keyed-Hash Message Authentication Code with SHA-256)

``` bash
openssl dgst -h

# SHA-256
echo -n 'message' | openssl dgst -sha256

# SHA-256 (Hex)
echo -n 'message' | openssl dgst -sha256 -hex

# SHA-512
echo -n 'message' | openssl dgst -sha512

# HMAC-SHA256 (hash with secret key)
echo -n "message" | openssl dgst -sha256 -hmac secret_key
```

``` bash
# Create source file
echo -n 'message' > data.txt

# SHA-256
openssl dgst -sha256 data.txt

openssl dgst -sha256 istio-1.25.0-osx-arm64.tar.gz
openssl dgst -sha256 Python-3.11.1.tgz
```

## X.509 certificate
``` bash
# Generate a private key and a public key in PEM format
openssl genrsa -out key.pem 4096

# Generate a self-signed certificate
openssl req -new -x509 -key key.pem -out cert.pem -days 365

# Get certificate fingerprint
openssl x509 -noout -fingerprint -sha256 -inform pem -in cert.pem

# Generate Personal Information Exchange (.pfx) file
openssl pkcs12 -export -inkey key.pem -in cert.pem -out cert.pfx

# Convert .pfx file to .pem format
openssl pkcs12 -in cert.pfx -out certificate.pem -nodes

# Extract private key from .pfx file
openssl pkcs12 -in cert.pfx -nocerts -out server.key

# Extract cert from .pfx file
openssl pkcs12 -in cert.pfx -clcerts -nokeys -out server.crt
```

## JWT • JWS • JWE • JWA • JWK
JWT: JSON Web Token \
JWS: JSON Web Signature \
JWE: JSON Web Encryption \
JWA: JSON Web Algorithms (Cryptographic algorithms) \
JWK: JSON Web Key (Key Encryption)

**JSON Web Signature (JWS) (Signing)** \
Contain 3 components
1. Header
2. Payload
3. Signature

**JSON Web Encryption (JWE) (Encryption)** \
Contain 5 components
1. Header
2. Encrypted key (encrypted content encryption key value)
3. Initialization vector (size 96-bit, use for encrypting the plaintext)
4. Ciphertext (can decrypt by content encryption key)
5. Authentication tag

**JSON Web Algorithms** \
Cryptographic algorithms for signing and encryption

**JSON Web Key** \
Use for creating the JWE Encrypted Key

**JSON Web Token (JWT) with HMAC protection**
- HS256 - HMAC with SHA-256, requires 256+ bit secret
- HS384 - HMAC with SHA-384, requires 384+ bit secret
- HS512 - HMAC with SHA-512, requires 512+ bit secret

**JSON Web Signature (JWS) with RSA**
- RS256 - RSA PKCS#1 signature with SHA-256
- RS384 - RSA PKCS#1 signature with SHA-384
- RS512 - RSA PKCS#1 signature with SHA-512
- PS256 - RSA PSS signature with SHA-256
- PS384 - RSA PSS signature with SHA-384
- PS512 - RSA PSS signature with SHA-512

**JSON Web Signature (JWS) with Elliptic Curve (EC)**
- ES256 - EC P-256 DSA with SHA-256
- ES384 - EC P-384 DSA with SHA-384
- ES512 - EC P-521 DSA with SHA-512

## Key size
96-bit = 12 byte \
128-bit = 16 byte \
192-bit = 24 byte \
256-bit = 32 byte \
384-bit = 48 byte \
512-bit = 64 byte \
2048-bit = 256 byte \
4096-bit = 512 byte

## Password
**Hashing Password**
According to the Open Worldwide Application Security Project (OWASP) should:
- Use Argon2id
- Use bcrypt
- Use scrypt (for legacy systems)
- Use PBKDF2 with HMAC-SHA-256 (for FIPS-140 compliance)

**Password Storing**
- A - Slow Hashing (bcrypt, scrypt, Argon2)
> - Run slowly
> - Use tons of power
> - Use tons of memory
- B - Hashing + Salting
- C - Hashing
- D - Encrypting
- F - Storing in plaintext