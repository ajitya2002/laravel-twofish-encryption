<?php

namespace TwoFish\Encryption;

use TwoFish\Encryption\DecryptException;
use TwoFish\Encryption\DecryptTextMissing;
use TwoFish\Encryption\EncryptException;
use TwoFish\Encryption\EncryptionKeyMissing;
use TwoFish\Encryption\EncryptionTextOrKeyMissingException;
use TwoFish\Encryption\EncryptTextMissing;
use TwoFish\Encryption\McryptLibraryNotFoundException;

/**
 * TwoFish Encryption
 *
 * @version          1.0.0
 * @author           Ajit Singh <ajitya2002@gmail.com.com>
 * @date             05/27/2018
 * @license          MIT
 */
class TwoFish implements iEncryptor
{

    private $_ivLength;

    private $_algorithm;

    public function __construct()
    {
        if (!function_exists('mcrypt_module_open')) {
            throw new McryptLibraryNotFoundException('The twofish encryption class requires the Mcrypt library to be compiled into PHP.',
                500);
        }
        $this->_algorithm = MCRYPT_TWOFISH;
        $this->_ivLength  = mcrypt_get_iv_size($this->_algorithm, MCRYPT_MODE_CBC);
    }

    /**
     *
     * Function to encrypt with TwoFish
     *
     * @param String $plaintext
     * @param String $key
     *
     * @return mixed String or boolean (false)
     * @throws EncryptException
     * @throws EncryptTextMissing
     * @throws EncryptionKeyMissing
     */
    public function encrypt($plaintext, $key = null)
    {
        $key = trim($key);
        if (empty($key)) {
            throw new EncryptionKeyMissing("Encryption key is missing");
        }

        $key = md5($key);

        if (empty($plaintext)) {
            throw new EncryptTextMissing("No Text available to encrypt");
        }
        $iv = mcrypt_create_iv($this->_ivLength,
            MCRYPT_DEV_URANDOM); // PHP 5.6.0 MCRYPT_DEV_URANDOM is now the default value

        if ($encrypted = mcrypt_encrypt($this->_algorithm, $key, $plaintext, MCRYPT_MODE_CBC, $iv)) {

            $result = base64_encode($iv . $encrypted);

            return $result;
        }

        throw new EncryptException("Unable to Encrypt the text");
    }

    /**
     *
     * Function to decrypt with TwoFish
     *
     * @param String $crypttext
     * @param string $key
     *
     * @return mixed String or boolean (false)
     * @throws DecryptException
     * @throws DecryptTextMissing
     * @throws EncryptionKeyMissing
     */
    public function decrypt($crypttext, $key = null)
    {
        $crypttext = trim($crypttext);

        $key = trim($key);

        if (empty($key)) {
            throw new EncryptionKeyMissing("Encryption Key missing while decrypting");
        }

        if (empty($crypttext)) {
            throw new DecryptTextMissing("Empty text given to decrypt");
        }

        $key = md5($key);

        $crypttext = base64_decode($crypttext);

        $iv = substr($crypttext, 0, $this->_ivLength);

        $encrypted = substr($crypttext, $this->_ivLength);
        $result    = mcrypt_decrypt($this->_algorithm, $key, $encrypted, MCRYPT_MODE_CBC, $iv);

        if (mb_detect_encoding($result) === 'ASCII') {
            return $result;
        }

        // not able to decrypt
        throw new DecryptException("Unable to decrypt the {$crypttext} with {$key}");
    }
}