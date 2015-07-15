# Virtual Box Disk Image Encryption password cracker

## Requirements
1. PHP >= 5.2.0
2. OpenSSL >= 1.0.1 (XTS support)

## Algorithm description
User password is stored using a combination of PBKDF2 and AES-XTS as following (shown values are fixed at the moment, but they can be controlled inside the file format):

```
# 32 for AES-XTS128-PLAIN64
# 64 for AES-XTS256-PLAIN64
AES_key_length = 32 | 64

AES-password = PBKDF2(algorithm: SHA256,
                      password: user_password,
                      salt: random_salt_1,
                      iterations: 2000,
                      output_length: AES_key_length)

PBKDF2-decrypted-password = AES_decrypt(key_size: AES_key_length,
                                        mode: XTS,
                                        data: random_data
                                        password: AES-password,
                                        type: raw,
                                        iv: NULL);

Stored_hash = PBKDF2(algorithm: SHA256,
                     password: PBKDF2-decrypted-password,
                     salt: random_salt_2,
                     iterations: 2000,
                     output_length: 32)
```

The same process is performed each time the user wants to decrypt the machine disk.

## Example of usage
```
$ php VBOXDIECracker.php
VirtualBox Disk Image Encryption cracker

Usage: VBOXDIECracker.php disk_image.vbox [wordlist]

$ php VBOXDIECracker.php Encrypted.vbox wordlist.txt
VirtualBox Disk Image Encryption cracker

[+] Reading data from: Encrypted.vbox
----------------------------------------------------------------
[+] Checking hard disk encryption for: Encrypted.vdi
[+] Hard disk is encrypted
[+] KeyStore encoded string:
        U0NORQABQUVTLVhUUzI1Ni1QTEFJTjY0AAAAAAAAAAAAAAAAAABQQktERjItU0hB
        MjU2AAAAAAAAAAAAAAAAAAAAAAAAAEAAAAASAniX2ss6TE/u9IdinWigcwAg2bXe
        dJRAjHr5mvCCiSAAAAAntQHDFvSfwpay/jKFVzUWc4GsIJ/RwMg+XkG2b/PDWtAH
        AACKj0qUg37sG7TWmi58n/rcXmWVNt9FqBxGZiz2a+leWNAHAABAAAAA6qVV8nOu
        r58RVxKP0cNRfXyu9D7JqqVAaRfNE3LFdoz4hXxWWWcxjOGBJA/BQ5VuwvrDxO8O
        YpwYgl3yKOcewg==
[+] KeyStore contents:
        Header                        454e4353 (SCNE)
        Version                       1
        Algorithm                     AES-XTS256-PLAIN64
        KDF                           PBKDF2-SHA256
        Key length                    64
        Final hash                    12027897dacb3a4c4feef487629d68a0730020d9b5de7494408c7af99af08289
        PBKDF2 2 Key length           32
        PBKDF2 2 Salt                 27b501c316f49fc296b2fe32855735167381ac209fd1c0c83e5e41b66ff3c35a
        PBKDF2 2 Iterations           2000
        PBKDF2 1 Salt                 8a8f4a94837eec1bb4d69a2e7c9ffadc5e659536df45a81c46662cf66be95e58
        PBKDF2 1 Iterations           2000
        EVP buffer length             64
        PBKDF2 2 encrypted password   eaa555f273aeaf9f1157128fd1c3517d7caef43ec9aaa5406917cd1372c5768c
                                      f8857c565967318ce181240fc143956ec2fac3c4ef0e629c18825df228e71ec2
[+] Cracking finished, measured time: 6.13035 seconds
[!] KeyStore password found: 123
----------------------------------------------------------------
[+] Checking hard disk encryption for: New_Disk.vdi
[-] Hard disk is not encrypted
```
