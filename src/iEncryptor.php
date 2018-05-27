<?php

namespace TwoFish\Encryption;

/**
 * @version          1.0.0
 * @author           Ajit Singh <ajitya2002@gmail.com.com>
 * @date             05/27/2018
 * @license          MIT
 *
 */

interface iEncryptor
{

    public function encrypt($plaintext, $key = null);

    public function decrypt($crypttext, $key = null);
}