<?php

namespace Tests\Feature;

use App\Enums\PollMethod;
use App\Jobs\RouterOsTlsEnrollJob;
use App\Models\Credential;
use App\Models\Device;
use App\Models\User;
use App\Services\RouterOs\RouterOsClientException;
use App\Services\RouterOs\RouterOsTarget;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

class RouterOsTlsApiTest extends TestCase
{
    use RefreshDatabase;

    private function device(): Device
    {
        $credential = Credential::factory()->routeros()->create();
        $ssh = Credential::factory()->ssh()->create([
            'username' => 'mymate-enroll',
            'private_key' => 'TEST-ONLY-KEY',
        ]);

        return Device::factory()->create([
            'poll_method' => PollMethod::RouterOs,
            'credential_id' => $credential->id,
            'ssh_credential_id' => $ssh->id,
        ]);
    }

    private function verifiedAdmin(): User
    {
        $admin = User::factory()->admin()->create();
        $admin->passkeys()->create([
            'name' => 'Test passkey',
            'credential_id' => rtrim(base64_encode('mymate-test-passkey'), '='),
            'credential' => ['type' => 'public-key'],
        ]);

        return $admin;
    }

    public function test_plaintext_routeros_api_is_denied_by_production_policy(): void
    {
        config()->set('mymate.routeros.require_tls', true);
        $device = $this->device();

        $this->expectException(RouterOsClientException::class);
        RouterOsTarget::fromDevice($device);
    }

    public function test_tls_port_uses_certificate_verification_without_custom_anchor(): void
    {
        config()->set('mymate.routeros.require_tls', true);
        $device = $this->device();
        $device->credential->update(['api_port' => 8729]);

        $target = RouterOsTarget::fromDevice($device->fresh());
        $this->assertSame(8729, $target->port);
        $this->assertTrue($target->ssl);
        $this->assertNull($target->caFile);
    }

    public function test_admin_cannot_enroll_without_a_verified_passkey(): void
    {
        $device = $this->device();
        $this->actingAsUser()
            ->postJson("/api/devices/{$device->id}/tls-enrol")
            ->assertForbidden();
    }

    public function test_enrollment_rejects_missing_trusted_ssh_hosts(): void
    {
        $device = $this->device();
        config()->set('mymate.routeros.tls_known_hosts', '');
        $admin = $this->verifiedAdmin();

        $this->actingAs($admin)->withSession(['passkey_verified' => true])
            ->postJson("/api/devices/{$device->id}/tls-enrol")
            ->assertStatus(503);
    }

    public function test_verified_admin_can_queue_exactly_one_enrollment(): void
    {
        Queue::fake();
        $device = $this->device();
        $knownHosts = sys_get_temp_dir().'/mymate-known-hosts-'.bin2hex(random_bytes(6));
        file_put_contents($knownHosts, '192.0.2.10 ssh-rsa TEST-ONLY-HOST-KEY');
        try {
            config()->set('mymate.routeros.tls_known_hosts', $knownHosts);
            config()->set('mymate.routeros.tls_manager_ip', '192.0.2.1');
            $admin = $this->verifiedAdmin();
            $this->actingAs($admin)->withSession(['passkey_verified' => true]);

            $this->postJson("/api/devices/{$device->id}/tls-enrol")
                ->assertStatus(202)
                ->assertJsonPath('status', 'queued');
            $this->postJson("/api/devices/{$device->id}/tls-enrol")
                ->assertStatus(409);

            Queue::assertPushed(RouterOsTlsEnrollJob::class, 1);
            $this->assertSame('queued', $device->fresh()->routeros_tls_status);
        } finally {
            @unlink($knownHosts);
        }
    }
}
