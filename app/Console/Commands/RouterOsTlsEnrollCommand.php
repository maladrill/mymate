<?php

namespace App\Console\Commands;

use App\Models\Device;
use App\Services\RouterOs\RouterOsTlsProvisioner;
use Illuminate\Console\Command;
use Throwable;

/**
 * Enroll a RouterOS device with an API-SSL certificate generated on this server.
 *
 * SSH host key MUST be verified independently and installed in known_hosts in advance.
 * The target must have a dedicated SSH key credential assigned as ssh_credential_id.
 */
class RouterOsTlsEnrollCommand extends Command
{
    protected $signature = 'mymate:routeros:tls-enrol
        {device : Numeric My Mate device ID}
        {--known-hosts= : Absolute path to a pre-verified OpenSSH known_hosts file}
        {--confirm : Confirm certificate installation and API-SSL activation}';

    protected $description = 'Enroll a CPE API-SSL identity with server-generated TLS material over pinned SSH.';

    public function handle(RouterOsTlsProvisioner $provisioner): int
    {
        $deviceId = filter_var($this->argument('device'), FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        $knownHosts = $this->option('known-hosts');

        if ($deviceId === false || ! is_string($knownHosts) || ! str_starts_with($knownHosts, '/')
            || ! is_file($knownHosts) || ! is_readable($knownHosts) || ! $this->option('confirm')) {
            $this->error('Specify a device ID, --known-hosts=/absolute/path and --confirm.');

            return self::FAILURE;
        }

        $device = Device::find($deviceId);
        if ($device === null) {
            $this->error('The selected device does not exist.');

            return self::FAILURE;
        }

        try {
            $result = $provisioner->enrol($device, $knownHosts);
        } catch (Throwable $e) {
            // Keep error messages devoid of SSH output and any secret material.
            $this->error('TLS enrollment failed: '.$e->getMessage());

            return self::FAILURE;
        }

        $this->info('RouterOS API-SSL enrollment verified. Certificate SHA-256: '.$result['fingerprint']);

        return self::SUCCESS;
    }
}
