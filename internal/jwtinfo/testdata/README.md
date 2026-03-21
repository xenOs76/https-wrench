# JwtInfo testdata

Sample private keys generated with Openssl. Plaintext and encrypted versions.
_Warning_: the keys stored in this folder are meant to be used for testing only.

## Create sample RSA private keys

Create an encrypted key:

```shell
> openssl genrsa -aes256 -out rsa-pkcs8-encrypted-private-key.pem 4096
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:

> head -n 3  rsa-pkcs8-encrypted-private-key.pem
-----BEGIN ENCRYPTED PRIVATE KEY-----
(REDACTED PEM Block)
(REDACTED PEM Block)
```

Decrypt the key:

```shell
> openssl  rsa -in rsa-pkcs8-encrypted-private-key.pem -out rsa-pkcs8-plaintext-private-key.pem
Enter pass phrase for rsa-pkcs8-encrypted-private-key.pem:
writing RSA key

> head -n 3 rsa-pkcs8-plaintext-private-key.pem
-----BEGIN PRIVATE KEY-----
(REDACTED PEM Block)
```

Extract the public key:

```shell
❯ openssl rsa -in rsa-pkcs8-plaintext-private-key.pem -pubout > rsa-pkcs8-public-key.pem
writing RSA key
```

## Create sample RSA certificates

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
(REDACTED PEM Block)
```

## Create sample ED25519 private keys

Create the plaintext key:

```shell
> openssl genpkey -algorithm Ed25519 -out ed25519-plaintext-private-key.pem

> head -n2 ed25519-plaintext-private-key.pem
-----BEGIN PRIVATE KEY-----
(REDACTED PEM Block)
```
