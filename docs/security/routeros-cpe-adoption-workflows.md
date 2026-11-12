# MikroTik CPE adoption workflows

This specification defines two separate and auditable adoption workflows. It does
not authorize unattended first-use trust of an arbitrary SSH host on the public
Internet. It does not change the firmware rollback feature.

## Scope and invariants

- My Mate runs as the central credential and update orchestrator; Zabbix remains
  the monitoring source of truth.
- No remote My Mate agents are required.
- Every CPE must have an independently validated identity or an explicitly
  documented exception before its SSH password is transmitted.
- Never accept an unknown or changed SSH host key merely because the device
  responds at the expected IP, MAC, DNS name, or serial number.
- Routers receive a dedicated, unique management identity. Keys, TLS
  certificates and passwords are generated on the My Mate server.
- SSH host keys are device identities; SSH user public keys are credentials.
  These cannot be interchanged.
- All sensitive operations are audited. No secrets appear in logs or
  user-facing API responses.

## Workflow A: new CPE in isolated provisioning network

1. A technician connects one CPE to a physically identified provisioning port
   or isolated session in a dedicated VLAN.
2. The provisioning controller correlates port identity, observed MAC, model
   and serial from the purchase/receiving inventory. A duplicate or unexpected
   device moves to a quarantined state; no password is transmitted.
3. The controller retrieves the device SSH host public key but marks it
   untrusted until the isolated physical connection is confirmed. A remote
   public-Internet IP does not qualify for this automated confirmation.
4. The controller authenticates with the device's individual factory password
   or an approved staging credential.
5. Generate a per-device SSH user key pair on My Mate; install only the
   public key on the RouterOS CPE. Retain the encrypted private key in a
   strictly scoped credential store.
6. Create a unique CPE operator account and high-entropy password, grant only
   verified RouterOS permissions required by the use case. Keep an independent
   break-glass recovery path. Never use an identical permanent password across
   the entire fleet.
7. Generate the API-SSL identity (certificate and private key) on My Mate,
   transfer over SSH/SCP, import and verify TLS with a pinned per-device
   trust anchor and the expected SAN.
8. Apply a versioned configuration template with explicit parameters for the
   device and customer. Take a pre-change snapshot when applicable. Check
   consistency and service access before committing final credentials.
9. Open fresh SSH and API-SSL connections using the new identities; verify
   management ACLs and Zabbix reachability.
10. Only then disable the default/factory account and unnecessary management
    services. Confirm final access and record provisioning metadata.
11. Associate the CPE with its customer/service inventory record and move to
    READY. Any partial failure leaves the device quarantined for inspection.

The initial provisioning network must prohibit unauthorized clients, MAC
spoofing, routing from customer networks and lateral access among devices.

MikroTik Netinstall provisioning scripts (Linux) or FlashFig can provide
an upstream hardware provisioning stage; My Mate must verify the final result.

## Workflow B: existing remote CPEs (hundreds of devices)

### Trust source classification

B1. Already trusted: An existing authenticated and integrity-protected channel
can retrieve or validate the RouterOS SSH server identity. Examples include
a previously pinned SSH host key and an existing independently
authenticated private management session. Batch import is allowed only if
the source can prove the reported fingerprint belongs to that device.

B2. Operationally constrained: The CPE is accessed through an ISP-controlled
management tunnel or verified subscriber access circuit, and its management
source, service identifier, MAC and serial match a previously recorded
inventory. These operational signals reduce exposure, but do not alone
cryptographically authenticate the SSH host. Additional approval and
documented risk classification are required before accepting a new host key.

B3. Public Internet without a pre-existing trust anchor: No automated
cryptographic proof is possible from only an IP and SSH password. Offer
out-of-band verification (local/remote console through an existing trusted
channel), a previously recorded key, or a separately authenticated
device-initiated enrollment bootstrap. A site-initiated bootstrap must be
installed through an already trusted channel; it cannot manufacture
first-contact authenticity from an unauthenticated remote login.

### Recommended batch migration

1. Import CPE records, exact known addresses, version, model/serial where
   previously established, customer/site, and credential references. Never
   copy plaintext passwords into import logs or exports.
2. Merge existing trusted host-key entries gathered from admin bastions or
   other authoritative management systems. An arbitrary ssh-keyscan result
   is a *candidate*, never a verified host key.
3. Classify each device as VERIFIED, CANDIDATE, CONFLICT, or MANUAL_REVIEW.
   In VERIFIED the attestation source and time are recorded.
4. Capture candidate SSH public keys *without logging in* and compare them
   to the expected trusted material. Host-key changes are quarantined.
5. Run a small verified canary batch with bounded concurrency and a
   maintenance window. Preserve existing network access during migration.
6. Install a per-device SSH user key and/or API-SSL certificate, then confirm
   newly established trust through a separate fresh connection.
7. Rotate any existing shared or legacy CPE credential only after successful
   new-authentication tests; remove temporary bootstrap permissions.
8. Audit results by host and batch; continue to the next group only when
   required Zabbix health checks pass.

If only a direct public Internet connection and a previously untrusted SSH
server are available, do NOT silently mark the device VERIFIED. Any optional
TOFU migration must be separately approved by security and the operator,
visibly labeled as an exception and audited. It must not be the default.

### Suggested state machine

DISCOVERED -> IDENTIFIED -> HOST_KEY_CANDIDATE -> HOST_KEY_VERIFIED ->
AUTHENTICATED -> BOOTSTRAPPING -> TLS_VERIFIED ->
NEW_CREDENTIALS_VERIFIED -> READY

Terminal or review states:
HOST_KEY_MISMATCH, UNKNOWN_IDENTITY, AUTH_FAILED, FAILED,
REQUIRES_MANUAL_REVIEW.

Important: an SSH host fingerprint observed after an **unverified SSH login**
is not independent evidence; neither are device-reported serials or MACs
retrieved over the same unauthenticated channel. A MITM may proxy them.

## Minimum proposed model

- device_id, expected management address, inventory serial and MAC
- SSH host public key and SHA-256 fingerprint
- SSH host key algorithm and verification source
- verified_at, verified_by, verification evidence reference
- adoption mode (PROVISIONING / TRUSTED_REMOTE / REVIEW_REQUIRED)
- workflow state and immutable event log
- configured SSH auth mode (password/key), credential references only
- certificate fingerprint, SAN, expiry and trust-anchor path
- configuration template version and last validation result

Do not expose credentials, password hashes or exported private keys in the
adoption status API.

## Implementation boundaries

The existing pull request currently provides authenticated SSH password/key
access **after** host-key pinning and server-generated API-SSL certificate
installation. It does not yet implement the full router configuration templates,
per-device permanent SSH user key generation, password rotation, new-device
port attestation, or unattended bulk remote adoption described here.

Implement each workflow as a separate, reviewable extension with unit and
real-hardware acceptance tests for RouterOS 6.49.x and 7.x.
