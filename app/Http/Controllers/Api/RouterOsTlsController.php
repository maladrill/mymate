<?php

namespace App\Http\Controllers\Api;

use App\Enums\PollMethod;
use App\Http\Controllers\Controller;
use App\Jobs\RouterOsTlsEnrollJob;
use App\Models\Device;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

/**
 * Starts administrator-approved certificate enrollment.
 *
 * Trusted SSH host identities are server-side configuration. Never allow an API
 * caller to supply known_hosts, a CA path, a certificate, or a private key.
 */
class RouterOsTlsController extends Controller
{
    public function store(Request $request, Device $device): JsonResponse
    {
        if ($device->poll_method !== PollMethod::RouterOs || $device->agent_id !== null
            || ! filter_var($device->mgmt_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return response()->json(['message' => 'Only centrally managed IPv4 RouterOS devices can be enrolled.'], 422);
        }
        if ($device->routeros_tls_enrolled_at !== null) {
            return response()->json(['message' => 'This device is enrolled; certificate rotation is a separate operation.'], 409);
        }

        $knownHosts = config('mymate.routeros.tls_known_hosts');
        if (! is_string($knownHosts) || ! str_starts_with($knownHosts, '/')
            || ! is_file($knownHosts) || ! is_readable($knownHosts) || filesize($knownHosts) === 0) {
            return response()->json(['message' => 'Trusted RouterOS SSH known_hosts is not configured.'], 503);
        }

        $device->loadMissing('sshCredential');
        if ($device->sshCredential === null || $device->sshCredential->type !== 'ssh'
            || ! filled($device->sshCredential->private_key)) {
            return response()->json(['message' => 'A dedicated SSH key credential is required.'], 422);
        }

        // Row lock makes two simultaneous POSTs unable to enqueue duplicate jobs.
        $claimed = DB::transaction(function () use ($device): bool {
            $locked = Device::whereKey($device->id)->lockForUpdate()->firstOrFail();
            if ($locked->routeros_tls_enrolled_at !== null) {
                return false;
            }
            if (in_array($locked->routeros_tls_status, ['queued', 'running'], true)
                && $locked->routeros_tls_attempted_at?->greaterThan(now()->subMinutes(30))) {
                return false;
            }
            $locked->forceFill([
                'routeros_tls_status' => 'queued',
                'routeros_tls_attempted_at' => now(),
                'routeros_tls_error' => null,
            ])->save();

            return true;
        });

        if (! $claimed) {
            return response()->json(['message' => 'Enrollment is already pending or completed.'], 409);
        }

        RouterOsTlsEnrollJob::dispatch($device->id, (int) $request->user()->id)->afterCommit();

        return response()->json(['status' => 'queued', 'device_id' => $device->id], 202);
    }
}
