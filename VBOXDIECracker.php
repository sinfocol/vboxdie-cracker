<?php

/*
 *  Copyright (C) 2015 Daniel Correa
 *
 *  http://www.sinfocol.org/
 *  http://null-life.com/
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
 
/*
 * Requirements
 *
 * PHP >= 5.2.0
 * OpenSSL >= 1.0.1
 */

/**
 * process_keystore
 *
 * Process encoded KeyStore and verify some of their values
 * Returns an array with the values defined in the format
 */
function process_keystore($encoded_keystore) {
    $keystore = base64_decode($encoded_keystore);

    $keystore_format =
        array(
            'Iheader',                      // 4 bytes keystore header
            'nversion',                     // 2 bytes version
            'a32algorithm',                 // 32 bytes algorithm name
            'a32kdf',                       // 32 bytes key derivation function name
            'Igeneric_key_length',          // 4 bytes generic length
                                                // first PBKDF2 output length
                                                // second PBKDF2 input length
                                                // EVP decrypted string length
            'a32final_hash',                // 32 bytes final hash, comparison done here
            'Ipbkdf2_2_key_length',         // 4 bytes second PBKDF2 output length
            'a32pbkdf2_2_salt',             // 32 bytes second PBKDF2 salt
            'Ipbkdf2_2_iterations',         // 4 bytes second PBKDF2 iterations
            'a32pbkdf2_1_salt',             // 32 bytes first PBKDF2 salt
            'Ipbkdf2_1_iterations',         // 4 bytes first PBKDF2 iterations
            'Ievp_decrypt_input_length',    // 4 bytes EVP input length
            'a*pbkdf2_2_encrypted_password' // 64 bytes encrypted password for PBKDF2 2
        );

    $keystore = unpack(implode('/', $keystore_format), $keystore);

    // Check keystore header
    if ($keystore['header'] !== 0x454E4353) {
        return false;
    }

    // Check method and hash constants
    if (!get_openssl_method($keystore)) {
        return false;
    }

    if (!get_hash_algorithm($keystore)) {
        return false;
    }

    return $keystore;
}

/**
 * crack_keystore
 *
 * Makes a bruteforce to find the final hash contained in the KeyStore
 * Returns the plaintext password used to encrypt de disk of the virtual machine
 */
function crack_keystore($keystore, $wordlist) {
    $fp = fopen($wordlist, 'r');
    if (is_resource($fp)) {
        $hash = get_hash_algorithm($keystore);
        $method = get_openssl_method($keystore);

        while (!feof($fp)) {
            $user_password = trim(fgets($fp));

            $EVP_password = hash_pbkdf2($hash, $user_password, $keystore['pbkdf2_1_salt'], $keystore['pbkdf2_1_iterations'], $keystore['generic_key_length'], true);

            $decrypted_password = openssl_decrypt(substr($keystore['pbkdf2_2_encrypted_password'], 0, $keystore['evp_decrypt_input_length']), $method, $EVP_password, OPENSSL_RAW_DATA, '');
            if ($decrypted_password === false) {
                continue;
            }

            $final_hash = hash_pbkdf2($hash, $decrypted_password, $keystore['pbkdf2_2_salt'], $keystore['pbkdf2_2_iterations'], $keystore['pbkdf2_2_key_length'], true);
            if ($final_hash === $keystore['final_hash']) {
                return $user_password;
            }
        }

        return false;
    } else {
        return false;
    }
}

/**
 * print_keystore
 *
 * Prints the values of the decoded KeyStore
 */
function print_keystore($keystore) {
    printf("\t%-30s%s\n", 'Header',                       dechex($keystore['header']) . " (SCNE)");
    printf("\t%-30s%s\n", 'Version',                      $keystore['version']);
    printf("\t%-30s%s\n", 'Algorithm',                    trim($keystore['algorithm']));
    printf("\t%-30s%s\n", 'KDF',                          trim($keystore['kdf']));
    printf("\t%-30s%s\n", 'Key length',                   $keystore['generic_key_length']);
    printf("\t%-30s%s\n", 'Final hash',                   bin2hex($keystore['final_hash']));
    printf("\t%-30s%s\n", 'PBKDF2 2 Key length',          $keystore['pbkdf2_2_key_length']);
    printf("\t%-30s%s\n", 'PBKDF2 2 Salt',                bin2hex($keystore['pbkdf2_2_salt']));
    printf("\t%-30s%s\n", 'PBKDF2 2 Iterations',          $keystore['pbkdf2_2_iterations']);
    printf("\t%-30s%s\n", 'PBKDF2 1 Salt',                bin2hex($keystore['pbkdf2_1_salt']));
    printf("\t%-30s%s\n", 'PBKDF2 1 Iterations',          $keystore['pbkdf2_1_iterations']);
    printf("\t%-30s%s\n", 'EVP buffer length',            $keystore['evp_decrypt_input_length']);

    $encrypted_length = strlen($keystore['pbkdf2_2_encrypted_password']);
    printf("\t%-30s%s\n", 'PBKDF2 2 encrypted password',  bin2hex(substr($keystore['pbkdf2_2_encrypted_password'], 0, $encrypted_length / 2)));
    printf("\t%-30s%s\n", '',                             bin2hex(substr($keystore['pbkdf2_2_encrypted_password'], $encrypted_length / 2)));
}

/**
 * get_openssl_method
 *
 * Returns the method to be used by openssl_decrypt
 */
function get_openssl_method($keystore) {
    switch (trim($keystore['algorithm'])) {
        case 'AES-XTS128-PLAIN64':
            return 'aes-128-xts';
            break;
        case 'AES-XTS256-PLAIN64';
            return 'aes-256-xts';
            break;
        default:
            return false;
    }
}

/**
 * get_hash_algorithm
 *
 * Returns the hash to be used by PBKDF2
 */
function get_hash_algorithm($keystore) {
    switch (trim($keystore['kdf'])) {
        case 'PBKDF2-SHA1':
            return 'sha1';
            break;
        case 'PBKDF2-SHA256';
            return 'sha256';
            break;
        case 'PBKDF2-SHA512';
            return 'sha512';
            break;
        default:
            return false;
    }
}

/**
 * get_hash_algorithm
 *
 * Process the VirtualBox configuration file
 * Shows if any of the disks defined in the configuration are encrypted
 */
function process_configuration_file($path, $wordlist) {
    printf("[+] Reading data from: %s\n", $path);

    // Load file using simpleXML
    $vboxconf = @simplexml_load_file($path);

    if ($vboxconf === false) {
        printf("[-] XML parsing failed for: %s\n", $path);
        return false;
    }

    // Register VBOX namespace to avoid issues with xpath method
    $namespaces = array_values($vboxconf->getNamespaces());
    $vboxconf->registerXPathNamespace('vbox', $namespaces[0]);

    // Get the list of all the hard disks available on the config file
    $hardDisks = $vboxconf->xpath('//vbox:HardDisks');

    // Iterate over each disk
    foreach ($hardDisks[0] as $hardDisk) {
        // Get disk location
        $location = (string) $hardDisk->attributes()->location;
        printf("%s\n", str_repeat('-', 64));
        printf("[+] Checking hard disk encryption for: %s\n", $location);

        $keyID = $encoded_keystore = NULL;
        // Check for encryption disk properties
        foreach ($hardDisk->Property as $property) {
            $attributes = $property->attributes();
            $name = (string) $attributes->name;
            $value = (string) $attributes->value;

            switch ($name) {
                case 'CRYPT/KeyId':
                    $keyID = $value;
                    break;
                case 'CRYPT/KeyStore':
                    $encoded_keystore = $value;
                    break;
            }
        }

        // KeyStore found on disk!
        if ($encoded_keystore === NULL) {
            printf("[-] Hard disk is not encrypted\n");
            continue;
        }

        printf("[+] Hard disk is encrypted\n");
        printf("[+] KeyStore encoded string:\n");
        printf("%s\n", preg_replace('/^/m', "\t", $encoded_keystore));

        // Process the KeyStore
        $keystore = process_keystore($encoded_keystore);
        if ($keystore === false) {
            printf("[-] Invalid KeyStore found\n");
            continue;
        }

        // Print the KeyStore
        echo "[+] KeyStore contents:\n";
        print_keystore($keystore);

        // Check if wordlist parameter was provided and if it exists
        if (empty($wordlist) or !file_exists($wordlist)) {
            printf("[-] Wordlist not provided or not found, cracking halted\n");
            continue;
        }

        // Start cracking
        $start = microtime(true);
        $result = crack_keystore($keystore, $wordlist);
        $end = microtime(true);

        // Cracking process end, let see the time and the result
        printf("[+] Cracking finished, measured time: %g seconds\n", $end - $start);
        if ($result !== false) {
            printf("[!] KeyStore password found: %s\n", $result);
        } else {
            printf("[-] KeyStore password not found\n");
        }
    }
}

function main($argv) {
    printf("VirtualBox Disk Image Encryption cracker\n\n");

    if (empty($argv[1])) {
        printf("Usage: %s disk_image.vbox [wordlist]", $argv[0]);
        return;
    }

    process_configuration_file($argv[1], @$argv[2]);
}

main($argv);
