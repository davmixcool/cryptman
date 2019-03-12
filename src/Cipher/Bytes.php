<?php

namespace Davmixcool\Cipher;

class Bytes
{
	public static function iv($method)
	{
	    return openssl_cipher_iv_length($method);
	}
}
