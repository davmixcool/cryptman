<?php
namespace Davmixcool;

use Davmixcool\Cipher\Encrypt;
use Davmixcool\Cipher\Decrypt;

class Cryptman
{	
	protected $method = 'aes-128-ctr'; // default cipher method if none supplied. see: http://php.net/openssl_get_cipher_methods for more.

	private $key;

	private $data;

	public function __construct($options=[])
	{
  		//Set default encryption key if none supplied
	  	if(isset($options['key'])) {
	  		$key = $options['key'];
	  	} else {
	  		// SECURITY: php_uname() describes the host OS and is publicly
	  		// guessable, so data encrypted under it is effectively unencrypted.
	  		// The behaviour is retained here for backwards compatibility, but
	  		// it is a defect. Supply a key. See README.
	  		trigger_error(
	  			'Cryptman: no encryption key supplied, so the key has defaulted to php_uname(). '
	  			. 'That value is publicly guessable, which means your data is effectively unencrypted. '
	  			. "Fix: new Davmixcool\\Cryptman(array('key' => \$yourSecretKey)). "
	  			. 'This fallback is deprecated and is removed in Cryptman 2.0.',
	  			E_USER_WARNING
	  		);

	  		$key = php_uname();
	  	}

		$method = isset($options['method'])? $options['method'] : false;

		// convert ASCII keys to binary format
		$this->key = ctype_print($key)? openssl_digest($key, 'SHA256', TRUE) : $key;

	    if($method) {
	      	if(in_array(strtolower($method), openssl_get_cipher_methods())) {
	        	$this->method = $method;
	      	} else {
	        	// Was die() prior to 1.1.0. A library must not terminate the
	        	// host process; any caller reaching this was already dead, and
	        	// an exception is strictly more recoverable.
	        	throw new \InvalidArgumentException(
	        		__METHOD__ . ": unrecognised cipher method: {$method}"
	        	);
	      	}
	    }
	}

  	public function cipher($data)
  	{		
  		$this->data = $data;
  		return $this;
  	}

  	public function encrypt()
  	{
  		return Encrypt::token(
		  			$this->data,
		  			$this->method,
		  			$this->key
		  		);
  	}

  	public function decrypt()
  	{
    	return Decrypt::token(
    				$this->data,
    				$this->method,
    				$this->key
    			);
  	}

}
