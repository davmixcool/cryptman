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
	  	$key = isset($options['key'])? $options['key'] : php_uname(); 

		$method = isset($options['method'])? $options['method'] : false;

		// convert ASCII keys to binary format
		$this->key = ctype_print($key)? openssl_digest($key, 'SHA256', TRUE) : $key; 

	    if($method) {
	      	if(in_array(strtolower($method), openssl_get_cipher_methods())) {
	        	$this->method = $method;
	      	} else {
	        	die(__METHOD__ . ": unrecognised cipher method: {$method}");
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
  		return new Encrypt(
		  			$this->data,
		  			$this->method,
		  			$this->key
		  		);
  	}

  	public function decrypt()
  	{
    	return new Decrypt(
    				$this->data,
    				$this->method,
    				$this->key
    			);
  	}

}
