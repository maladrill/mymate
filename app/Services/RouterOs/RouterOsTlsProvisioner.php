<?php

namespace App\Services\RouterOs;

use App\Models\Device;
use App\Support\EngineLog;
use Illuminate\Support\Facades\Cache;
use RuntimeException;
use Throwable;

/**
 * One-time, SSH-authenticated installation of a server-generated API-SSL identity.
 *
 * No network bootstrap via plaintext RouterOS API is permitted. The administrator
 * supplies a previously verified SSH known_hosts file; host-key trust is never TOFU.
 */
class RouterOsTlsProvisioner
{
    public function __construct(private RouterOsTlsCertificateGenerator $generator) {}

    /** @return array{fingerprint:string,expires_at:int} */
    public function enrol(Device $device, string $knownHostsPath): array
    {
        $lock = Cache::lock('routeros-tls-enrol:'.$device->id, 900);
        if (! $lock->get()) {
            throw new RuntimeException('TLS enrollment is already running for this device.');
        }

        try {
            return $this->run($device, $knownHostsPath);
        } finally {
            $lock->release();
        }
    }

    /** @return array{fingerprint:string,expires_at:int} */
    private function run(Device $device, string $knownHostsPath): array
    {
        $device->refresh();
        $host = (string) $device->mgmt_ip;
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            throw new RuntimeException('TLS enrollment currently requires an IPv4 management address.');
        }
        if ($device->routeros_tls_enrolled_at !== null) {
            throw new RuntimeException('The device is already enrolled; certificate rotation requires a separate operation.');
        }

        $managerIp = (string) config('mymate.routeros.tls_manager_ip', '');
        if (filter_var($managerIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false
            || in_array($managerIp, ['0.0.0.0', '255.255.255.255'], true)) {
            throw new RuntimeException('A specific RouterOS API-SSL manager source IPv4 is required.');
        }

        $device->loadMissing('sshCredential');
        $credential = $device->sshCredential;
        if ($credential === null || $credential->type !== 'ssh' || ! filled($credential->private_key)) {
            throw new RuntimeException('A dedicated SSH credential with a private key is required.');
        }

        // Restrict all working files, including the SSH identity, to Linux tmpfs.
        // Fail closed if /dev/shm is unavailable; never silently spill secrets to disk.
        if (! is_dir('/dev/shm') || ! is_writable('/dev/shm') || is_link('/dev/shm')) {
            throw new RuntimeException('A writable /dev/shm tmpfs is required.');
        }
        $workDir = '/dev/shm/mymate-tls-'.bin2hex(random_bytes(12));
        if (! mkdir($workDir, 0700) || ! chmod($workDir, 0700)) {
            throw new RuntimeException('Unable to allocate private TLS workspace.');
        }

        $identity = null;
        $activationAttempted = false;
        $previouslyDisabled = true;
        $previousAcl = '';
        $remoteFiles = [];
        try {
            $keyPath = $workDir.'/ssh_identity';
            $this->writePrivateFile($keyPath, (string) $credential->private_key);

            $ssh = new RouterOsPinnedSsh(
                $host,
                (string) $credential->username,
                $keyPath,
                $knownHostsPath,
                (int) config('mymate.routeros.tls_ssh_port', 22),
            );

            // Do not replace certificates that an administrator may already rely on.
            $state = $ssh->execute(':put ("MYMATE_CERT=" . [/ip service get [find where name="api-ssl"] certificate])');
            if (! str_contains($state, 'MYMATE_CERT=')) {
                throw new RuntimeException('Unable to read API-SSL certificate assignment.');
            }
            $assigned = trim(substr($state, strrpos($state, 'MYMATE_CERT=') + strlen('MYMATE_CERT=')));
            if ($assigned !== '' && strtolower($assigned) !== 'none') {
                throw new RuntimeException('API-SSL already has a certificate; enrollment will not replace it.');
            }
            $disabled = $ssh->execute(':put ("MYMATE_DISABLED=" . [/ip service get [find where name="api-ssl"] disabled])');
            if (preg_match('/MYMATE_DISABLED=(?:false|no)(?:\s|$)/i', $disabled) === 1) {
                $previouslyDisabled = false;
            } elseif (preg_match('/MYMATE_DISABLED=(?:true|yes)(?:\s|$)/i', $disabled) !== 1) {
                throw new RuntimeException('Unable to read the existing API-SSL service state.');
            }
            $port = $ssh->execute(':put ("MYMATE_PORT=" . [/ip service get [find where name="api-ssl"] port])');
            if (! preg_match('/MYMATE_PORT=8729(?:\s|$)/', $port)) {
                throw new RuntimeException('API-SSL must listen on TCP port 8729 for enrollment.');
            }

            $addresses = $ssh->execute(':put ("MYMATE_ADDR=" . [/ip service get [find where name="api-ssl"] address])');
            if (! str_contains($addresses, 'MYMATE_ADDR=')) {
                throw new RuntimeException('Unable to read the existing API-SSL allow-list.');
            }
            $previousAcl = trim(substr($addresses, strrpos($addresses, 'MYMATE_ADDR=') + strlen('MYMATE_ADDR=')));
            if (strlen($previousAcl) > 1024 || ! preg_match('/^[0-9a-fA-F:.,\/ ]*$/D', $previousAcl)) {
                throw new RuntimeException('The existing API-SSL allow-list is not safely parseable.');
            }
            // Preserve specific, existing admin ACL entries. Never preserve a
            // wildcard ACL on a newly activated management interface.
            $newAcl = ($previousAcl === '' || str_contains($previousAcl, '0.0.0.0/0')
                || str_contains($previousAcl, '::/0'))
                ? $managerIp.'/32'
                : $previousAcl.','.$managerIp.'/32';

            $identity = $this->generator->issue($host, $workDir);
            $prefix = $identity['name'];
            $certFile = $prefix.'.crt';
            $privateFile = $prefix.'.key';
            $this->writePrivateFile($workDir.'/'.$certFile, $identity['certificate']);
            $this->writePrivateFile($workDir.'/'.$privateFile, $identity['private_key']);

            $ssh->upload($workDir.'/'.$certFile, $certFile);
            $remoteFiles[] = $certFile;
            $ssh->upload($workDir.'/'.$privateFile, $privateFile);
            $remoteFiles[] = $privateFile;

            // The device imports an already generated key; no key generation is done on the CPE.
            $ssh->execute('/certificate import file-name="'.$certFile.'" passphrase=""');
            $ssh->execute('/certificate import file-name="'.$privateFile.'" passphrase=""');

            $script = ':local certs [/certificate find where common-name="'.$prefix.'"]; '.
                ':if ([:len $certs] != 1) do={:error "Certificate not found or ambiguous"}; '.
                '/ip service set [find where name="api-ssl"] certificate=$certs address="'.$newAcl.'" disabled=no; '.
                ':put "MYMATE_TLS_APPLIED"';

            // Mark before sending the command: a lost SSH response does not prove
            // the remote change did not happen.
            $activationAttempted = true;
            $result = $ssh->execute($script);
            if (! str_contains($result, 'MYMATE_TLS_APPLIED')) {
                throw new RuntimeException('RouterOS did not confirm API-SSL certificate activation.');
            }

            // Verify both the server's self-signed trust anchor and its IP subjectAltName.
            $this->verifyEndpoint($host, $workDir.'/'.$certFile, $identity['fingerprint']);

            // Save the public trust anchor atomically, without persisting private key material.
            $trustDir = storage_path('app/routeros-tls');
            if (! is_dir($trustDir) && ! mkdir($trustDir, 0700, true) && ! is_dir($trustDir)) {
                throw new RuntimeException('Cannot create RouterOS TLS trust directory.');
            }
            chmod($trustDir, 0700);
            $trustFile = $trustDir.'/device-'.$device->id.'.pem';
            $staged = $trustFile.'.'.bin2hex(random_bytes(8)).'.tmp';
            $this->writePrivateFile($staged, $identity['certificate']);
            if (is_file($trustFile) || ! rename($staged, $trustFile)) {
                @unlink($staged);
                throw new RuntimeException('Cannot persist the RouterOS TLS trust anchor.');
            }

            try {
                $device->forceFill([
                    'routeros_tls_enrolled_at' => now(),
                    'routeros_tls_fingerprint' => $identity['fingerprint'],
                    'routeros_tls_expires_at' => date('Y-m-d H:i:s', $identity['expires_at']),
                ])->save();
            } catch (Throwable $e) {
                @unlink($trustFile);
                throw $e;
            }

            EngineLog::info('routeros tls: certificate enrolled', [
                'device_id' => $device->id, 'fingerprint' => $identity['fingerprint'],
            ]);

            return ['fingerprint' => $identity['fingerprint'], 'expires_at' => $identity['expires_at']];
        } catch (Throwable $e) {
            // Fail closed and restore the original certificate-less service state.
            if ($activationAttempted && isset($ssh)) {
                try {
                    $ssh->execute('/ip service set [find where name="api-ssl"] certificate=none address="'.
                        $previousAcl.'" disabled='.($previouslyDisabled ? 'yes' : 'no'));
                } catch (Throwable) {
                    EngineLog::error('routeros tls: automatic service restoration failed', [
                        'device_id' => $device->id,
                    ]);
                }
            }
            if (isset($prefix, $ssh)) {
                try {
                    $ssh->execute('/certificate remove [find where common-name="'.$prefix.'"]');
                } catch (Throwable) {
                    EngineLog::warning('routeros tls: temporary imported certificate cleanup failed', [
                        'device_id' => $device->id,
                    ]);
                }
            }
            EngineLog::warning('routeros tls: enrollment failed', [
                'device_id' => $device->id,
                'reason' => $e instanceof RuntimeException ? $e->getMessage() : $e::class,
            ]);
            throw $e;
        } finally {
            if (isset($ssh)) {
                foreach ($remoteFiles as $remoteFile) {
                    try {
                        $ssh->execute('/file remove [find where name="'.$remoteFile.'"]');
                    } catch (Throwable) {
                        EngineLog::warning('routeros tls: remote temporary file cleanup failed', [
                            'device_id' => $device->id,
                        ]);
                    }
                }
            }
            foreach (glob($workDir.'/*') ?: [] as $file) {
                if (is_file($file) && ! is_link($file)) {
                    @unlink($file);
                }
            }
            @rmdir($workDir);
        }
    }

    private function writePrivateFile(string $path, string $content): void
    {
        $handle = @fopen($path, 'xb');
        if ($handle === false) {
            throw new RuntimeException('Cannot create a private temporary file.');
        }
        chmod($path, 0600);
        try {
            if (fwrite($handle, $content) !== strlen($content)) {
                throw new RuntimeException('Cannot write a complete temporary file.');
            }
        } finally {
            fclose($handle);
        }
    }

    private function verifyEndpoint(string $host, string $certificateFile, string $fingerprint): void
    {
        $context = stream_context_create(['ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'peer_name' => $host,
            'cafile' => $certificateFile,
            'allow_self_signed' => true,
            'capture_peer_cert' => true,
            'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
        ]]);

        $socket = @stream_socket_client(
            'tls://'.$host.':8729', $code, $message, 10, STREAM_CLIENT_CONNECT, $context,
        );
        if (! is_resource($socket)) {
            throw new RuntimeException('API-SSL certificate verification failed.');
        }
        try {
            $options = stream_context_get_options($socket);
            $peer = $options['ssl']['peer_certificate'] ?? null;
            $actual = $peer !== null ? openssl_x509_fingerprint($peer, 'sha256') : false;
            if (! is_string($actual) || ! hash_equals($fingerprint, strtolower($actual))) {
                throw new RuntimeException('API-SSL certificate fingerprint mismatch.');
            }
        } finally {
            fclose($socket);
        }
    }
}
