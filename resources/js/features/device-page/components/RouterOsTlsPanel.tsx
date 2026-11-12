import { useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../../../lib/apiClient';
import { useCurrentUser } from '../../auth/api/auth';
import { deviceKeys } from '../../devices/api/getDevices';
import { pushToast } from '../../../lib/toast';
import type { Device } from '../../../types';
import { Card } from './ui';

/**
 * Certificate bootstrap is a privileged, asynchronous operation.
 * The server uses a pre-verified SSH host key; the browser never handles keys or PEM.
 */
export function RouterOsTlsPanel({ device }: { device: Device }) {
    const { data: user } = useCurrentUser();
    const qc = useQueryClient();
    const tls = device.routeros_tls;
    const enrolled = !!tls?.enrolled;
    const running = tls?.status === 'queued' || tls?.status === 'running';
    const request = useMutation({
        mutationFn: async (): Promise<void> => {
            await apiClient.post(`/devices/${device.id}/tls-enrol`, {});
        },
        onSuccess: () => {
            qc.invalidateQueries({ queryKey: deviceKeys.detail(device.id) });
            pushToast({ title: 'API-SSL certificate enrollment queued', tone: 'up' });
        },
        onError: (error) => {
            const response = error as { response?: { data?: { message?: string } } };
            pushToast({
                title: 'Certificate enrollment was not started',
                detail: response.response?.data?.message ?? 'Check SSH trust and administrator MFA.',
                tone: 'down',
            });
        },
    });

    function enroll() {
        if (!window.confirm(
            `Generate a new TLS private key on My Mate and install it on ${device.name} (${device.mgmt_ip}) over pinned SSH?\n\n` +
            'The CPE must already have a trusted SSH host key and a dedicated SSH key credential.'
        )) return;
        request.mutate();
    }

    return (
        <Card title="RouterOS API-SSL">
            <div className="space-y-2 text-xs text-white/70">
                <p>
                    {enrolled
                        ? 'Verified TLS identity enrolled. API access requires the pinned server certificate.'
                        : running
                            ? 'Enrollment is in progress. The server is preparing and installing the TLS certificate.'
                            : 'No My Mate-managed TLS identity enrolled for this device.'}
                </p>
                {tls?.status === 'failed' && <p className="text-rose-300">{tls.error ?? 'Certificate enrollment failed.'}</p>}
                {tls?.expires_at && (
                    <p>Certificate expiry: <span className="font-mono">{new Date(tls.expires_at).toLocaleString()}</span></p>
                )}
                {tls?.fingerprint && (
                    <p className="break-all font-mono text-[10px] text-white/40">SHA-256: {tls.fingerprint}</p>
                )}
                {user?.is_admin && !enrolled && (
                    <button
                        type="button"
                        onClick={enroll}
                        disabled={running || request.isPending || device.ssh_credential_id === null}
                        className="rounded-lg bg-emerald-500/15 px-3 py-2 text-xs font-medium text-emerald-300 ring-1 ring-emerald-400/25 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                        {running ? 'Enrolling...' : 'Generate and install certificate'}
                    </button>
                )}
                {!enrolled && device.ssh_credential_id === null && user?.is_admin && (
                    <p className="text-amber-300">Assign a dedicated SSH key credential before enrollment.</p>
                )}
                <p className="text-white/35">
                    Certificate generation runs on My Mate. Transfer uses authenticated SSH/SCP; no plaintext RouterOS API is used.
                </p>
            </div>
        </Card>
    );
}
