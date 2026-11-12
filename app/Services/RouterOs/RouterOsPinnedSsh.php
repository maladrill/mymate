<?php

namespace App\Services\RouterOs;

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Net\SCP;
use RuntimeException;
use Throwable;

/**
 * Authenticated RouterOS SSH/SCP transport.
 *
 * The server host key is matched against a pre-verified OpenSSH known_hosts entry
 * before ANY user credential is transmitted. Passwords and private keys remain in
 * process memory; neither is passed to a shell or written to a process argument.
 */
class RouterOsPinnedSsh
{
    private SCP $ssh;

    public function __construct(
        string $host,
        string $username,
        ?string $privateKey,
        ?string $password,
        string $knownHostsPath,
        int $port = 22,
    ) {
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false
            || ! preg_match('/^[A-Za-z0-9_.+-]{1,128}$/D', $username)
            || $port < 1 || $port > 65535) {
            throw new RuntimeException('Invalid RouterOS SSH target.');
        }

        if (! is_file($knownHostsPath) || ! is_readable($knownHostsPath)
            || is_link($knownHostsPath) || ((fileperms($knownHostsPath) ?: 0) & 0022) !== 0) {
            throw new RuntimeException('A secure, pre-verified SSH known_hosts file is required.');
        }
        $knownHosts = file_get_contents($knownHostsPath);
        if (! is_string($knownHosts) || strlen($knownHosts) < 20 || strlen($knownHosts) > 1048576) {
            throw new RuntimeException('The SSH known_hosts file is empty or too large.');
        }

        if (! class_exists(SCP::class)) {
            throw new RuntimeException('The phpseclib SSH/SCP dependency is unavailable.');
        }

        $ssh = new SCP($host, $port, 10);
        $ssh->setTimeout(45);

        try {
            $serverKey = $ssh->getServerPublicHostKey();
            if (! is_string($serverKey) || ! self::hostKeyMatches($knownHosts, $host, $port, $serverKey)) {
                throw new RuntimeException('The RouterOS SSH host key is unknown or does not match the trusted key.');
            }

            // Prefer the explicitly configured private key; never silently downgrade
            // to password login if key authentication was configured but failed.
            if ($privateKey !== null && $privateKey !== '') {
                $key = PublicKeyLoader::load($privateKey, $password ?? '');
                $authenticated = $ssh->login($username, $key);
            } elseif ($password !== null && $password !== '') {
                $authenticated = $ssh->login($username, $password);
            } else {
                throw new RuntimeException('SSH password or private key is required.');
            }

            if (! $authenticated) {
                throw new RuntimeException('RouterOS SSH authentication failed.');
            }
        } catch (Throwable $e) {
            $ssh->disconnect();
            if ($e instanceof RuntimeException) {
                throw $e;
            }
            throw new RuntimeException('RouterOS SSH setup failed.', 0, $e);
        }

        $this->ssh = $ssh;
    }

    /**
     * Match the actual SSH host public key blob against a pinned known_hosts entry.
     *
     * No wildcard, hashed-name, CA, or SSH host-certificate entries are accepted.
     * Operators must verify and explicitly pin the CPE public host key out-of-band.
     */
    public static function hostKeyMatches(string $knownHosts, string $host, int $port, string $serverKey): bool
    {
        $parts = preg_split('/\s+/', trim($serverKey));
        if (! is_array($parts) || count($parts) < 2) {
            return false;
        }
        $actual = base64_decode($parts[1], true);
        if ($actual === false || strlen($actual) < 32) {
            return false;
        }
        $expectedHost = $port === 22 ? $host : '['.$host.']:'.$port;

        foreach (preg_split('/\R/', $knownHosts) ?: [] as $line) {
            $fields = preg_split('/\s+/', trim($line));
            if (! is_array($fields) || count($fields) < 3
                || str_starts_with($fields[0], '#')
                || str_starts_with($fields[0], '@')) {
                continue;
            }
            if (! in_array($expectedHost, explode(',', $fields[0]), true)) {
                continue;
            }

            $pinned = base64_decode($fields[2], true);
            if ($pinned !== false && strlen($pinned) >= 32
                && hash_equals(hash('sha256', $pinned), hash('sha256', $actual))) {
                return true;
            }
        }

        return false;
    }

    public function execute(string $command): string
    {
        try {
            $result = $this->ssh->exec($command);
            if (! is_string($result)) {
                throw new RuntimeException('The RouterOS SSH command did not complete.');
            }
            $status = $this->ssh->getExitStatus();
            if ($status !== null && $status !== 0) {
                throw new RuntimeException('The RouterOS SSH command failed.');
            }

            return trim($result);
        } catch (Throwable $e) {
            throw new RuntimeException('RouterOS SSH command execution failed.', 0, $e);
        }
    }

    public function upload(string $localFile, string $remoteFile): void
    {
        if (! preg_match('/^[A-Za-z0-9_-]+[.](crt|key)$/D', $remoteFile)
            || ! is_file($localFile) || ! is_readable($localFile)) {
            throw new RuntimeException('Invalid RouterOS certificate transfer.');
        }
        try {
            if (! $this->ssh->put($remoteFile, $localFile, SCP::SOURCE_LOCAL_FILE)) {
                throw new RuntimeException('The RouterOS SCP upload failed.');
            }
        } catch (Throwable $e) {
            throw new RuntimeException('RouterOS SCP upload failed.', 0, $e);
        }
    }

    public function __destruct()
    {
        if (isset($this->ssh)) {
            $this->ssh->disconnect();
        }
    }
}
