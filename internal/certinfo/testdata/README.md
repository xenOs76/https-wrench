# Certinfo testdata

Sample private keys generated with Openssl. Plaintext and encrypted versions.  
*Warning*: the keys stored in this folder are meant to be used for testing only.  

## Create sample RSA private keys

### PKCS1

Generating PKCS1 RSA private key with Openssl requires version 1.1.1.  
Get it with Nix:  

```shell
> export NIXPKGS_ALLOW_INSECURE=1

> nix-shell -p openssl_1_1

> openssl version
OpenSSL 1.1.1w  11 Sep 2023
```

Create an encrypted key:

```shell
> openssl genrsa -aes128 -out rsa-pkcs1-encrypted-private-key.pem 1024
Generating RSA private key, 1024 bit long modulus (2 primes)
......................................+++++
............+++++
e is 65537 (0x010001)
Enter pass phrase for rsa-pkcs1-encrypted-private-key.pem:
Verifying - Enter pass phrase for rsa-pkcs1-encrypted-private-key.pem:

> head -n 6 rsa-pkcs1-encrypted-private-key.pem
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,314A1EF1E544F10E9741F8A9C57384C8

8CpkWf5vuUxv15p6c7LJPgNO2gc1M3K+1ncRmJOblOGrpjv/Z5P1kE5wjEMIl/8Q
3BcapXsV+yuAnA+eBglHKBIrUf3Em6KxjjlcHP95qKSitvj7iOXtGBTJtkkswgR5
```

Decrypt the key: 

```shell 
> openssl rsa -in rsa-pkcs1-encrypted-private-key.pem  -out rsa-pkcs1-plaintext-private-key.pem
Enter pass phrase for rsa-pkcs1-encrypted-private-key.pem:
writing RSA key
```

### PKCS8

Recent versions of Openssl create private keys in PKCS8 format:

```shell 
> openssl version
OpenSSL 3.6.0 1 Oct 2025 (Library: OpenSSL 3.6.0 1 Oct 2025
```

Create an encrypted key:  

```shell 
> openssl genrsa -aes256 -out rsa-pkcs8-encrypted-private-key.pem 4096
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:

> head -n 3  rsa-pkcs8-encrypted-private-key.pem
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIJtTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQ188U9zxSGVXQrj4+
8z3z1QICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEDutok8Bf7Wu5Pc6
```

Decrypt the key: 

```shell 
> openssl  rsa -in rsa-pkcs8-encrypted-private-key.pem -out rsa-pkcs8-plaintext-private-key.pem
Enter pass phrase for rsa-pkcs8-encrypted-private-key.pem:
writing RSA key

> head -n 3 rsa-pkcs8-plaintext-private-key.pem
-----BEGIN PRIVATE KEY-----
MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQC2O/PumNzqJcUd
4I0SBD0WP/AsCtDZGa6qF7YuqjO3hXx8jx66KRUQLFccgXRwOgmZ3Jj2hTvVUpbe
```
## Create sample RSA certificates

Create cert with PKCS1 key:

```shell
> openssl req -new -key rsa-pkcs1-plaintext-private-key.pem -out rsa-pkcs1-csr.pem
[...]
> openssl x509 -req -days 3650 -in rsa-pkcs1-csr.pem -signkey rsa-pkcs1-plaintext-private-key.pem -out rsa-pkcs1-crt.pem
```

Create cert with PKCS8 key:

```shell 
> openssl req -new -key rsa-pkcs8-plaintext-private-key.pem -out rsa-pkcs8-csr.pem
[...]
> openssl x509 -req -days 3650 -in rsa-pkcs8-csr.pem -signkey rsa-pkcs8-plaintext-private-key.pem -out rsa-pkcs8-crt.pem
Certificate request self-signature ok
subject=C=DE, ST=Some-State, L=Berlin, O=example Ltd, CN=example.com
```

## Create sample ECDSA private keys

Create the plaintext key: 

```shell 
 > openssl ecparam -name prime256v1 -genkey -noout -out ecdsa-plaintext-private-key.pem

> head -n 2 ecdsa-plaintext-private-key.pem
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILVvywgqKFoKYCDNLNehJSbvwxCdtDr1UT+QID0hxqa+oAoGCCqGSM49
```

Encrypt the key: 

```shell 
> openssl ec -in ecdsa-plaintext-private-key.pem -out ecdsa-encrypted-private-key.pem -aes256 -passout pass:testpassword

> head -n 6 ecdsa-encrypted-private-key.pem
-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,B1D5B0AFFB8F76B80B16373F8D81F9C3

1+K+hCOmodqpbb5s+GlWnW9J5VlnaR4gHyD/WKmIy5xo8iu/0OTHX4FjOc0TpMqi
UqHGMOYI078StHO7kexCwUC26QaU61RVx1P6AQX21ErSfJaSpO/48fkI+/3mgAK+
```

## Create sample ECDSA certificate

```shell
> openssl req -new -x509 -key ecdsa-plaintext-private-key.pem -days 3650 -out ecdsa-crt.pem -subj "/CN=example.com/O=Example Org"
```

## Create sample ED25519 private keys

Create the plaintext key: 

```shell 
> openssl genpkey -algorithm Ed25519 -out ed25519-plaintext-private-key.pem

> head -n2 ed25519-plaintext-private-key.pem
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIEGYgM/XLll7BGmu+g7BdEOD21o+B7w/lZ6YbMOAiJ2s
```

Encrypt the key: 

```shell 
> openssl pkey -in ed25519-plaintext-private-key.pem -out ed25519-encrypted-private-key.pem -aes256 -passout pass:testpassword

> head -n 3 ed25519-encrypted-private-key.pem
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGjMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBAbN/Oyvx9FWCW4Cq/Y
Ea20AgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQaUVczU8lT61K28bk
```
## Create sample ED25519 certificate

```shell
> openssl req -new -x509 -key ed25519-plaintext-private-key.pem -days 3650 -out ed25519-crt.pem -subj "/CN=example.com/O=Example Org"
```


