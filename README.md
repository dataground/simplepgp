# SimplePGP
Very simple library for PGP decryption using the excellent (but rather complex) Singpoyma OpenPGP Library.
A lot of people have problems with the complexity of GnuPG/OpenPGP/PGP decryption in automated workflows.
SimplePGP tries to solve this problem, it can decrypt data without any dependencies and without the need to add the private key to any local keyring.

## Installation
`composer install dataground/simplepgp`

## Input formats
* The PrivateKey file should be ascii armored (default for most key export tools)
* The input file content should be in base64 encoded format (not binary)

## Example
```php
$spgp = new SimplePgp();

$decrypted = $spgp->decrypt(
  file_get_contents('/path/to/my_encrypted_file'),
  file_get_contents('/path/to/my_privatekey_file'),
  'myVerySecretKeyPassPhrase'
);
```

## TODO
* Add encryption support
* Improve error handling
* Add tests and examples

## Contributing
Contributions are very welcome, please adhere to [http://www.phptherightway.com/] best practices.