# RouterOS API-SSL enrollment (server-generated certificates)

This feature is for centrally managed RouterOS 6/7 CPEs. It generates a **unique RSA-2048/SHA-256 TLS certificate and private key on My Mate**, transfers both files to the CPE by **host-key-verified SSH/SCP**, imports them, enables API-SSL, verifies the TLS endpoint, and stores **only the public certificate** as a local trust anchor.

**Do not use against production CPEs until RouterOS 6 and 7 hardware tests have passed.** No automatic rollback of RouterOS firmware is implemented by this feature.

## Security boundaries

- Never bootstrap device trust through unsecured RouterOS API (TCP/8728).
- The first SSH host key must be verified independently, for example during onsite provisioning or against an authenticated inventory. Do not automatically trust `ssh-keyscan` output.
- A dedicated SSH credential with a **private key** must already be assigned to `ssh_credential_id` for the selected CPE.
- The SSH user requires sufficient access to import certificates, modify `/ip service`, and transfer/remove temporary files. Test an appropriately minimal RouterOS group on each supported version; do not automatically use the built-in `full` group.
- The My Mate account generating the certificate must run on Linux with writable `/dev/shm` (tmpfs). If tmpfs is unavailable, provisioning fails closed.
- Certificates are RSA-2048 for compatibility with older, resource-constrained devices. Key generation and signing occur on the server.
- The private key is copied to RouterOS during import and then the temporary remote file is deleted. The imported key remains in the device certificate store. Neither the private key nor SSH identity is persisted unencrypted by My Mate.
- A successful TLS connection must validate the IP `subjectAltName`, chain to the exact stored certificate, and match its SHA-256 fingerprint.
- The server keeps the public trust anchor at `storage/app/routeros-tls/device-<id>.pem`. Back it up together with the database. The application refuses to connect if it is lost or modified.
- Enrollment is a one-time operation. Existing certificates are not replaced; rotation is a separate future workflow.

## Deployment configuration

For the production instance, set:

```dotenv
MYMATE_ROUTEROS_REQUIRE_TLS=true
MYMATE_ROUTEROS_SSH_KNOWN_HOSTS=/etc/mymate/routeros_known_hosts
MYMATE_ROUTEROS_MANAGER_IP=<MYMATE_MANAGEMENT_SOURCE_IPV4>
MYMATE_ROUTEROS_SSH_PORT=22
```

Replace the placeholder with the exact IPv4 address **observed by CPEs** as the source of My Mate's management connections. This is not necessarily the VM interface address if SNAT is involved.

The `known_hosts` file contains only previously verified public host keys. It must be readable by the service account, but writable only by administrators. For Docker, mount this file read-only and ensure `MYMATE_ROUTEROS_SSH_KNOWN_HOSTS` points to its path **inside the container**. Include the following additions in a local, non-committed Compose override:

```yaml
services:
  app:
    environment:
      MYMATE_ROUTEROS_REQUIRE_TLS: "true"
      MYMATE_ROUTEROS_SSH_KNOWN_HOSTS: /etc/mymate/routeros_known_hosts
      MYMATE_ROUTEROS_MANAGER_IP: "${MYMATE_ROUTEROS_MANAGER_IP:?management source IPv4 required}"
      MYMATE_ROUTEROS_SSH_PORT: "22"
    volumes:
      - ./secrets/routeros_known_hosts:/etc/mymate/routeros_known_hosts:ro
```

Install `openssh-client` on source/.deb installations. The fork's Dockerfile includes it.

The private SSH login key is stored as an encrypted My Mate credential, assigned as the device's dedicated SSH credential. Use a passphrase-free, dedicated automation identity held in an access-controlled secret store; do not reuse personal operators' SSH keys. Its scope must be limited to the device and management network.

## Initiate enrollment

1. Verify the CPE's SSH host key out-of-band; place it in the server's trusted `known_hosts`.
2. Confirm that `api-ssl` listens on 8729 and either has no certificate or is intentionally left unconfigured. Existing certificate assignments are never overwritten.
3. Add the CPE and its RouterOS credential to My Mate; assign its dedicated SSH key credential.
4. Configure the management source address and known-hosts file.
5. Sign in as an administrator with a **verified passkey**. Open the CPE Overview and choose **Generate and install certificate**.
6. The background `upgrade` queue performs the enrollment and updates the device's TLS state. It will not retry automatically after an unknown outcome.

For an operator with authenticated shell access, the same action is available through:

```bash
php artisan mymate:routeros:tls-enrol <DEVICE_ID> \
  --known-hosts=/etc/mymate/routeros_known_hosts \
  --confirm
```

This command deliberately never takes raw passwords, private key bytes, or a certificate as arguments.

## RouterOS behavior

- The application uses legacy `scp -O` so older RouterOS devices do not require SFTP support.
- Import runs once for the public certificate and once for its private key.
- Imported certificate selection is based on a random per-device common name.
- The pre-existing `api-ssl` enabled state and access list are captured.
- The newly enabled API-SSL service is bound to an allow-list containing the configured management source IPv4. A pre-existing wildcard ACL is **not** preserved.
- On failed verification, an SSH cleanup attempt restores the original service state and removes the newly imported certificate. If SSH is unavailable at this stage, manual inspection is necessary.
- The existing plaintext `api` service is not changed automatically to avoid unexpectedly disrupting other applications. Disable and firewall TCP/8728 through a controlled separate change.
- Certificate renewal and migration from an existing manually installed certificate are not supported in this initial release.

## Acceptance tests

Before production rollout, test on both RouterOS 6.49.x and supported RouterOS 7.x hardware:

- Valid pinned SSH host key succeeds; unknown or changed host key fails.
- Unencrypted RouterOS API is refused by the application in production.
- The certificate private key is generated on My Mate and imported on the CPE.
- A correctly enrolled device can authenticate through verified API-SSL on 8729.
- Wrong certificate, wrong IP SAN, expired certificate and missing trust-anchor file are rejected.
- A failure after activation restores the previous service state or produces a clear incident requiring manual recovery.
- CPE does not retain temporary `.key` or `.crt` files after a successful transfer.
- A concurrent request cannot start the same enrollment twice.
- No private keys or passwords occur in application logs, API payloads, or debug reports.

## Operational limitations

The first trust anchor cannot be created securely from an unauthenticated connection. If the CPE has no verified SSH key or usable secured management channel, enrollment must be done through an independently authenticated provisioning process.

The current implementation uses **individual self-signed certificates** trusted by exact certificate and IP. Future CA-based enrollment and renewal can be added without replacing the secure SSH bootstrap model.
