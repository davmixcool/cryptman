# Cryptman

Dead-simple two-way encryption for PHP, with tamper detection built in.

## Requirements

- PHP 8.2 and above
- `ext-openssl`, and `ext-sodium` for the default method

> **Still on PHP 8.1 or older?** Composer resolves to `1.x` for you — nothing
> breaks and you need to change nothing. 1.x is maintenance-only, so the one
> thing worth doing is making sure you pass an explicit `key` (see the warning
> below); that fix works on 1.x today and needs no upgrade.
>
> To pin it deliberately: `composer require davmixcool/cryptman:^1.0`

## Steps:

* [Installation](#installation)
* [Usage](#usage)
* [Documentation](#documentation)
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

	//Generate a key once and store it, e.g. in your .env
	$key = Davmixcool\Cryptman::generateKey();

	$cryptman = new Davmixcool\Cryptman([
		'key' => $key
	]);

	//Encrypt data
	$data = 'Loose lips sink ships';
	$encrypted = $cryptman->encrypt($data);

	//Decrypt Data
	$decrypted = $cryptman->decrypt($encrypted);

```

Advance Usage

```php

	$cryptman = new Davmixcool\Cryptman([
		'key' => $key,
		'method' => 'aes-256-gcm', //optional. see: Configuration docs. defaults to xchacha20-poly1305
	]);

	//Encrypt data
	$data = 'Loose lips sink ships';
	$encrypted = $cryptman->encrypt($data);

	//Decrypt Data
	$decrypted = $cryptman->decrypt($encrypted);

```

The v1 syntax still works too:

```php

	$encrypted = $cryptman->cipher($data)->encrypt();
	$decrypted = $cryptman->cipher($encrypted)->decrypt();

```

> **⚠️ Always pass a `key`.**
> Constructing without one throws. Cryptman v1 fell back to `php_uname()`, which
> is publicly guessable — if you have data encrypted that way, treat it as
> compromised and re-encrypt it. See [Upgrading](docs/upgrading.md).

**Upgrading from v1?** Your existing code and data keep working — v2 still reads
everything v1 wrote. Read [docs/upgrading.md](docs/upgrading.md) first; there
are two things to check before you deploy.

### Documentation

* [Configuration](docs/configuration.md) — encryption methods, associated data,
  key rotation, exceptions, framework integration
* [Upgrading from v1](docs/upgrading.md) — migration checklist, reading v1 data,
  bulk re-encryption
* [Security](docs/security.md) — threat model, and what not to use this for

### Maintainers

This package is maintained by [David Oti](http://github.com/davmixcool) and you!

### License

This package is licensed under the [MIT license](https://github.com/davmixcool/cryptman/blob/master/LICENSE).
