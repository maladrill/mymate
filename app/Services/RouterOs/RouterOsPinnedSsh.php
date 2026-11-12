<?php

namespace App\Services\RouterOs;

use RuntimeException;
use Symfony\Component\Process\Process;

/**
 * Runs RouterOS SSH and legacy SCP with strict, pre-provisioned host-key checking.
 *
 * No passwords or keys appear in process arguments, logs, or API responses.
 * In particular, never use ssh-keyscan output as an automatically trusted key.
 */
class RouterOsPinnedSsh
{
    public function __construct(
        private string $host,
        private string $username,
        private string $keyPath,
        private string $knownHostsPath,
        private int $port = 22,
    ) {
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false
            || ! preg_match('/^[A-Za-z0-9_.+-]{1,128}$/D', $username)
            || $port < 1 || $port > 65535) {
            throw new RuntimeException('Invalid RouterOS SSH target.');
        }
        if (! is_file($keyPath) || ! is_file($knownHostsPath)
            || ! is_readable($keyPath) || ! is_readable($knownHostsPath)
            || filesize($knownHostsPath) === 0) {
            throw new RuntimeException('SSH identity and trusted known_hosts file are required.');
        }
    }

    /** @return array<int, string> */
    private function options(): array
    {
        return [
            '-o', 'BatchMode=yes',
            '-o', 'IdentitiesOnly=yes',
            '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile='.$this->knownHostsPath,
            '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'ConnectTimeout=10',
            '-o', 'NumberOfPasswordPrompts=0',
            '-o', 'LogLevel=ERROR',
            '-i', $this->keyPath,
        ];
    }

    public function execute(string $command): string
    {
        $args = ['ssh', ...$this->options(), '-p', (string) $this->port,
            '-l', $this->username, $this->host, $command];

        return $this->run($args);
    }

    public function upload(string $localFile, string $remoteFile): void
    {
        // The remote path is deliberately flat, random, and contains no shell metacharacters.
        if (! preg_match('/^[A-Za-z0-9_-]+[.](crt|key)$/D', $remoteFile)) {
            throw new RuntimeException('Invalid temporary RouterOS file name.');
        }
        $args = ['scp', '-O', ...$this->options(), '-P', (string) $this->port,
            $localFile, $this->username.'@'.$this->host.':'.$remoteFile];
        $this->run($args);
    }

    private function run(array $arguments): string
    {
        $process = new Process($arguments);
        $process->setTimeout(45);
        $process->run();
        if (! $process->isSuccessful()) {
            // SSH/SCP error details can include remote output; never echo them into the UI.
            throw new RuntimeException('Pinned SSH/SCP operation failed (exit '.$process->getExitCode().').');
        }

        return trim($process->getOutput());
    }
}
