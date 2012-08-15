<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/**
 * Name: CI Bcrypt Simple
 *
 * Author: Rachel Baker
 *         rachel@rachelbaker.me
 *         @rachelbaker
 *
 * Library is based on "Simple PHP 5.3+ Bcrypt class and functions" by Marco Arment <me@marco.org>.
 * Original Source: https://gist.github.com/1053158/
 *
 * Created: August 04, 2012
 *
 * Description: Modified Marco's Simple PHP Bcrypt Class to use as a Code Igniter Library for password hashing
 *
 * Requirements: PHP 5.3+
 *
 * License:
 * DON'T BE A DICK PUBLIC LICENSE
 * Version 1, December 2009
 *
 * Copyright (C) 2009 Philip Sturgeon email@philsturgeon.co.uk
 * Everyone is permitted to copy and distribute verbatim or modified copies of this license document, and changing it is allowed as long as the name is changed.
 *
 * Usage example:
 *
 * // Load library in your models or controllers
 * $this->load->library('bcrypt');
 *
 * // In a registration or password-change form:
 * $hash_for_user = $this->bcrypt->hash($_POST['entered_password']);
 *
 * // In a login form:
 * $password_check = $this->bcrypt->check($_POST['entered_password'], $stored_hash_for_user);
 *
 *
*/

class Bcrypt
{
    static public $VERSION = "v0.1.0";

    const DEFAULT_WORK_FACTOR = 8;

    function hash($password, $work_factor = 0)
    {
        if (version_compare(PHP_VERSION, '5.3') < 0) throw new Exception('Bcrypt requires PHP 5.3 or above');

        if (! function_exists('openssl_random_pseudo_bytes')) {
            throw new Exception('Bcrypt requires openssl PHP extension');
        }

        if ($work_factor < 4 || $work_factor > 31) $work_factor = self::DEFAULT_WORK_FACTOR;
        $salt =
            '$2a$' . str_pad($work_factor, 2, '0', STR_PAD_LEFT) . '$' .
            substr(
                strtr(base64_encode(openssl_random_pseudo_bytes(16)), '+', '.'),
                0, 22
            )
        ;
        return crypt($password, $salt);
    }

    function check($password, $stored_hash)
    {
        if (version_compare(PHP_VERSION, '5.3') < 0) throw new Exception('Bcrypt requires PHP 5.3 or above');

        return crypt($password, $stored_hash) == $stored_hash;
    }

}