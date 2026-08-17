# Cryptman.

A Two-way encryption manager using the OpenSSL library

---

> ### ⚠️ Always pass a `key`
>
> If you construct Cryptman without one, the key falls back to `php_uname()` —
> a publicly guessable description of your host OS. **Data encrypted that way is
> effectively unencrypted.**
>
> ```php
> // vulnerable
> $cryptman = new Davmixcool\Cryptman();
>
> // fixed — works on this version, no upgrade needed
> $cryptman = new Davmixcool\Cryptman([
>     'key' => $yourSecretKey,
> ]);
> ```
>
> Since 1.1.0 this raises an `E_USER_WARNING`. The fallback is removed entirely
> in 2.0. If you have data encrypted without an explicit key, treat it as
> compromised and re-encrypt it.
>
> ### 1.x is in maintenance
>
> 1.x receives security fixes only. New work happens on 2.x, which replaces the
> unauthenticated ciphers below with authenticated encryption
> (XChaCha20-Poly1305) and can still decrypt data written by 1.x.
>
> 2.x requires PHP 8.2+. **If you are on an older PHP, stay on 1.x** — Composer
> will not offer you 2.x, and nothing will break. Apply the key fix above; it is
> the important one and it does not require upgrading.

---

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
