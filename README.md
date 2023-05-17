# Cryptography

## Symmetric Encryption
- Data Encryption Standard (DES)
- Triple Data Encryption Standard (Triple DES)
- Advanced Encryption Standard (AES)
- International Data Encryption Algorithm (IDEA)
- TLS/SSL protocol

## Asymmetric Encryption
- Rivest Shamir Adleman (RSA)
- the Digital Signature Standard (DSS), which incorporates - the Digital Signature Algorithm (DSA)
- Elliptical Curve Cryptography (ECC)
- the Diffie-Hellman exchange method
- TLS/SSL protocol

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