<?php

namespace App\Jobs;

use App\Models\Device;
use App\Services\RouterOs\RouterOsTlsProvisioner;
use App\Support\EngineLog;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Throwable;

/**
 * Serializes one TLS enrollment on the isolated upgrade queue. No automatic retries:
 * a partially applied certificate operation must be inspected before resubmission.
 */
class RouterOsTlsEnrollJob implements ShouldQueue
{
    use Queueable;

    public int $tries = 1;

    public int $timeout = 420;

    public function __construct(public int $deviceId, public int $operatorId)
    {
        $this->onQueue('upgrade');
    }

    public function handle(RouterOsTlsProvisioner $provisioner): void
    {
        $device = Device::find($this->deviceId);
        if ($device === null || $device->routeros_tls_status !== 'queued') {
            return;
        }

        $device->forceFill(['routeros_tls_status' => 'running'])->save();

        try {
            $provisioner->enrol($device, (string) config('mymate.routeros.tls_known_hosts'));
            $device->refresh()->forceFill([
                'routeros_tls_status' => 'verified',
                'routeros_tls_error' => null,
            ])->save();
            EngineLog::info('routeros tls: enrollment succeeded', [
                'device_id' => $device->id, 'operator_id' => $this->operatorId,
            ]);
        } catch (Throwable $e) {
            $device->refresh()->forceFill([
                'routeros_tls_status' => 'failed',
                'routeros_tls_error' => 'TLS enrollment failed; inspect the server audit log.',
            ])->save();
            EngineLog::error('routeros tls: job failed', [
                'device_id' => $device->id,
                'operator_id' => $this->operatorId,
                'exception' => $e::class,
            ]);
            throw $e;
        }
    }

    public function failed(Throwable $e): void
    {
        Device::whereKey($this->deviceId)->whereIn('routeros_tls_status', ['queued', 'running'])->update([
            'routeros_tls_status' => 'failed',
            'routeros_tls_error' => 'Enrollment was interrupted or timed out.',
        ]);
    }
}
