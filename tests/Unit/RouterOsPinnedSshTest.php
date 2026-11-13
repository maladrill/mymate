<?php

namespace Tests\Unit;

use App\Services\RouterOs\RouterOsPinnedSsh;
use PHPUnit\Framework\TestCase;

class RouterOsPinnedSshTest extends TestCase
{
    private function key(string $seed): string
    {
        return base64_encode(str_repeat($seed, 48));
    }

    public function test_only_exact_pinned_host_and_key_are_accepted(): void
    {
        $key = $this->key('A');
        $known = "192.0.2.10 ssh-rsa {$key}\n";
        $remote = "rsa-sha2-256 {$key}";

        $this->assertTrue(RouterOsPinnedSsh::hostKeyMatches($known, '192.0.2.10', 22, $remote));
        $this->assertFalse(RouterOsPinnedSsh::hostKeyMatches($known, '192.0.2.11', 22, $remote));
        $this->assertFalse(RouterOsPinnedSsh::hostKeyMatches($known, '192.0.2.10', 2222, $remote));
        $this->assertFalse(RouterOsPinnedSsh::hostKeyMatches($known, '192.0.2.10', 22, 'ssh-rsa '.$this->key('B')));
    }

    public function test_nondefault_port_requires_bracketed_host_entry(): void
    {
        $key = $this->key('B');
        $known = "[192.0.2.20]:2222 ssh-ed25519 {$key}\n";
        $this->assertTrue(
            RouterOsPinnedSsh::hostKeyMatches($known, '192.0.2.20', 2222, "ssh-ed25519 {$key}"),
        );
        $this->assertFalse(
            RouterOsPinnedSsh::hostKeyMatches($known, '192.0.2.20', 22, "ssh-ed25519 {$key}"),
        );
    }

    public function test_wildcards_and_untrusted_host_certificate_authorities_are_rejected(): void
    {
        $key = $this->key('C');
        $remote = "ssh-rsa {$key}";
        $this->assertFalse(RouterOsPinnedSsh::hostKeyMatches("* ssh-rsa {$key}", '192.0.2.50', 22, $remote));
        $this->assertFalse(RouterOsPinnedSsh::hostKeyMatches("@cert-authority 192.0.2.50 ssh-rsa {$key}", '192.0.2.50', 22, $remote));
        $this->assertFalse(RouterOsPinnedSsh::hostKeyMatches("192.0.2.50 ssh-rsa BAD-B64!!!!", '192.0.2.50', 22, $remote));
    }

    public function test_a_later_valid_key_can_match_without_accepting_wrong_keys(): void
    {
        $key = $this->key('D');
        $known = "192.0.2.60 ssh-rsa ".$this->key('X')."\n".
            "192.0.2.60 ssh-rsa {$key}\n";
        $this->assertTrue(RouterOsPinnedSsh::hostKeyMatches($known, '192.0.2.60', 22, "ssh-rsa {$key}"));
    }
}
