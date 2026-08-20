# Security Policy

## Supported versions

| Version | PHP       | Status               | Security fixes until |
| ------- | --------- | -------------------- | -------------------- |
| 2.x     | 8.2+      | Active               | current release      |
| 1.x     | >= 5.5    | Maintenance only     | **19 August 2027**   |

2.0.0 was released on 19 August 2026. 1.x receives security fixes for twelve
months from that date and nothing else — no features, no bug fixes.

After 19 August 2027, 1.x receives nothing. It will keep working and your data
stays readable; it simply will not be patched again.

## If you are on 1.x

**Do this today, whatever else you decide.** Cryptman 1.x falls back to
`php_uname()` when constructed without a key — a publicly guessable description
of your host OS. Data encrypted that way is effectively unencrypted.

```php
// vulnerable
$cryptman = new Davmixcool\Cryptman();

// fixed - works on 1.x today, no upgrade needed
$cryptman = new Davmixcool\Cryptman(['key' => $yourSecretKey]);
```

If you have data encrypted under the fallback, treat it as compromised and
re-encrypt it.

**Then, if you are on PHP 8.2 or newer**, upgrade to 2.x. It reads everything
1.x wrote, so your existing data keeps working, and it adds tamper detection
that 1.x cannot provide. See [docs/upgrading.md](docs/upgrading.md).

**If you cannot reach PHP 8.2**, stay on 1.x. Composer will not offer you 2.x,
so nothing breaks. Pin it deliberately if you prefer:

```shell
composer require davmixcool/cryptman:^1.0
```

Note that PHP itself stopped receiving security fixes for 8.1 in December 2025,
so a runtime that cannot reach 8.2 has a larger problem than this library.

## Reporting a vulnerability

Report privately via [GitHub Security Advisories][advisories], or email
davmixcool@gmail.com. Please do not open a public issue.

Include the version, PHP version, and enough detail to reproduce. You can expect
an acknowledgement within a week.

Reports are welcome for any supported version in the table above.

[advisories]: https://github.com/davmixcool/cryptman/security/advisories/new
