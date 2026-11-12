<?php

namespace Tests\Feature;

use App\Services\RouterOs\RouterOsTlsCertificateGenerator;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class RouterOsTlsCertificateTest extends TestCase
{
    public function test_server_generates_matching_rsa_key_and_ip_san(): void
    {
        $dir = sys_get_temp_dir().'/mymate-cert-test-'.bin2hex(random_bytes(8));
        mkdir($dir, 0700);
        try {
            $identity = (new RouterOsTlsCertificateGenerator)->issue('192.0.2.15', $dir);
            $certificate = openssl_x509_read($identity['certificate']);
            $this->assertNotFalse($certificate);
            $this->assertTrue(openssl_x509_check_private_key($certificate, $identity['private_key']));
            $this->assertSame(
                strtolower(openssl_x509_fingerprint($certificate, 'sha256')),
                $identity['fingerprint'],
            );

            $details = openssl_x509_parse($certificate);
            $this->assertStringContainsString('IP Address:192.0.2.15', $details['extensions']['subjectAltName']);
            $this->assertSame('CA:FALSE', $details['extensions']['basicConstraints']);
            $this->assertStringContainsString('TLS Web Server Authentication', $details['extensions']['extendedKeyUsage']);
            $this->assertGreaterThan(time() + 300 * 86400, $identity['expires_at']);
            $this->assertSame(2048, openssl_pkey_get_details(openssl_pkey_get_private($identity['private_key']))['bits']);
        } finally {
            @unlink($dir.'/openssl.cnf');
            @rmdir($dir);
        }
    }

    public function test_invalid_management_ip_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        (new RouterOsTlsCertificateGenerator)->issue('localhost;reboot', sys_get_temp_dir());
    }

    public function test_every_certificate_has_a_unique_subject(): void
    {
        $dir = sys_get_temp_dir().'/mymate-cert-test-'.bin2hex(random_bytes(8));
        mkdir($dir, 0700);
        try {
            $generator = new RouterOsTlsCertificateGenerator;
            $a = $generator->issue('192.0.2.16', $dir);
            $b = $generator->issue('192.0.2.16', $dir);
            $this->assertNotSame($a['name'], $b['name']);
            $this->assertNotSame($a['fingerprint'], $b['fingerprint']);
        } finally {
            @unlink($dir.'/openssl.cnf');
            @rmdir($dir);
        }
    }
}
