# Cryptman.

A Two-way encryption manager using the OpenSSL library


## Requirements

- PHP 5.5 and above

## Steps:

* [Installation](#installation)
* [Usage](#usage)
* [Maintainers](#maintainers)
* [License](#license)


### Installation

**Composer**

Run the following command to include this package via Composer

```shell
composer require davmixcool/cryptman
```


### Usage
Simple Usage.

```php

	$cryptman = new Davmixcool\Cryptman([
		'key' => 'Your cipher key'
	]);

	//Encrypt data
	$data = 'Loose lips sink ships';
	$encrypted = $cryptman->cipher($data)->encrypt();

	//Decrypt Data
	$decrypted = $cryptman->cipher($encrypted)->decrypt();

```

Advance Usage

```php
	
	$cryptman = new Davmixcool\Cryptman([
		'key' => 'Your cipher key',
		'method' => 'Your cipher method', //see: http://php.net/openssl_get_cipher_methods for more. resolves to default menthod if none selected
	]);

	//Encrypt data
	$data = 'Loose lips sink ships';
	$encrypted = $cryptman->cipher($data)->encrypt();

	//Decrypt Data
	$decrypted = $cryptman->cipher($encrypted)->decrypt();

```

### Maintainers

This package is maintained by [David Oti](http://github.com/davmixcool) and you!


### License

This package is licensed under the [MIT license](https://github.com/davmixcool/cryptman/blob/master/LICENSE).
