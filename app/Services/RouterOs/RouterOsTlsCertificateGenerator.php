<?php

namespace App\Services\RouterOs;

use RuntimeException;

/**
 * Issues a short-lived, device-specific API-SSL certificate on the My Mate server.
 *
 * The private key exists only in memory and in the caller's temporary tmpfs directory
 * while it is being transferred over an authenticated SSH connection. It must never be
 * persisted to the database, logs or an ordinary disk-based temporary directory.
 */
class RouterOsTlsCertificateGenerator
{
    /** @return array{certificate:string,private_key:string,fingerprint:string,expires_at:int,name:string} */
    public function issue(string $ip, string $workDir): array
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            throw new RuntimeException('A valid management IP is required for certificate issuance.');
        }

        $name = 'mymate-'.bin2hex(random_bytes(12));
        $configPath = $workDir.'/openssl.cnf';
        $config = "[ req ]\n".
            "distinguished_name = subject\n".
            "prompt = no\n".
            "[ subject ]\n".
            "CN = {$name}\n".
            "[ leaf ]\n".
            "basicConstraints = critical,CA:FALSE\n".
            "keyUsage = critical,digitalSignature,keyEncipherment\n".
            "extendedKeyUsage = serverAuth\n".
            "subjectAltName = IP:{$ip}\n";

        if (file_put_contents($configPath, $config, LOCK_EX) === false || ! chmod($configPath, 0600)) {
            throw new RuntimeException('Could not prepare the temporary OpenSSL configuration.');
        }

        // RSA 2048 is deliberately generated on the server for legacy RouterOS 6 CPEs.
        // Old devices only import the key; they do not perform expensive key generation.
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        if ($key === false) {
            throw new RuntimeException('Could not generate the RouterOS TLS private key.');
        }

        $options = ['config' => $configPath, 'digest_alg' => 'sha256'];
        $csr = openssl_csr_new(['commonName' => $name], $key, $options + ['req_extensions' => 'leaf']);
        if ($csr === false) {
            throw new RuntimeException('Could not generate the RouterOS certificate request.');
        }

        $certificate = openssl_csr_sign(
            $csr, null, $key, 365, $options + ['x509_extensions' => 'leaf'],
            random_int(1, PHP_INT_MAX),
        );
        if ($certificate === false || ! openssl_x509_export($certificate, $pem)
            || ! openssl_pkey_export($key, $privateKey)) {
            throw new RuntimeException('Could not sign or export the RouterOS certificate.');
        }

        $parsed = openssl_x509_parse($certificate);
        $fingerprint = openssl_x509_fingerprint($certificate, 'sha256');
        if (! is_array($parsed) || ! is_string($fingerprint)
            || ! str_contains((string) ($parsed['extensions']['subjectAltName'] ?? ''), $ip)) {
            throw new RuntimeException('The generated RouterOS certificate failed validation.');
        }

        return [
            'name' => $name,
            'certificate' => $pem,
            'private_key' => $privateKey,
            'fingerprint' => strtolower($fingerprint),
            'expires_at' => (int) $parsed['validTo_time_t'],
        ];
    }
}
