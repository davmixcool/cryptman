<?php
namespace Davmixcool\Cipher;
use Davmixcool\Cipher\Bytes;

class Encrypt
{	
	public static function token($data,$method,$key)
  	{
    	$iv = openssl_random_pseudo_bytes(Bytes::iv($method));
    	return bin2hex($iv) . openssl_encrypt($data, $method, $key, 0, $iv);
  	}
}
