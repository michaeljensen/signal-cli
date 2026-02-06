# Security Audit Report: signal-cli

**Date:** 2026-02-06
**Scope:** Full codebase review of signal-cli (src/ and lib/ — 407 Java source files)
**Methodology:** Static analysis across 7 categories: hardcoded secrets, data leakage, backdoors, cryptography, injection, network security, and input validation

---

## Executive Summary

The signal-cli codebase is **clean of backdoors, malicious code, and intentional security compromises**. No hidden functionality, data exfiltration paths, or weakened cryptography was found. All network connections go exclusively to legitimate Signal infrastructure (`*.signal.org`).

However, the audit identified several security gaps in data-at-rest protection, logging hygiene, input validation, and daemon interface authentication that represent real risk for production deployments.

---

## Severity Summary

| Severity | Count | Key Themes |
|----------|-------|------------|
| **CRITICAL** | 3 | Log scrubbing off by default; account secrets in plaintext JSON; JSON-RPC input logged at TRACE |
| **HIGH** | 5 | No HTTP/TCP daemon auth; phone numbers logged in plaintext; temp files in world-readable `/tmp`; no encryption-at-rest for stored data |
| **MEDIUM** | 7 | Path traversal in attachment retrieval; D-Bus arbitrary file read; no request size limits; no CORS; incomplete scrubber coverage |
| **LOW** | 9 | Informational items, minor TODOs, benign toString() methods |

---

## Category 1: Hardcoded Secrets

**Verdict: CLEAN** — No real secrets found.

| Finding | File | Assessment |
|---------|------|------------|
| TrustStore password `"whisper"` | `lib/.../config/WhisperTrustStore.java:16` | Standard public trust store password, same as official Signal Android. Contains only public CA certificates. |
| Server public keys + enclave hashes | `lib/.../config/LiveConfig.java:28-54` | Public parameters identical to official Signal app. Not secrets. |
| Test PIN `456test_pin_foo123` | `run_tests.sh:11` | Synthetic test data for staging environment only. |
| User-Agent `Signal-Android/7.73.0` | `src/.../BaseConfig.java:10-11` | By design — CLI must identify as a Signal client. Overridable via `SIGNAL_CLI_USER_AGENT` env var. |

No `.env` files, private keys, AWS credentials, third-party API tokens, or signing passwords were found.

---

## Category 2: Data Leakage

### CRITICAL: Log Scrubbing is Opt-In, Not Default

**File:** `src/.../logging/LogConfigurator.java:24`

```java
private static boolean scrubSensitiveInformation = false;
```

The `--scrub-log` flag must be explicitly passed. By default, all sensitive data below is logged in plaintext.

### CRITICAL: Account File Contains All Secrets in Plaintext JSON

**File:** `lib/.../storage/SignalAccount.java:989-1011`

The account state file includes password, registration lock PIN, pin master key, storage key, account entropy pool, media root backup key, profile key, and identity key pairs — all serialized as plaintext JSON. Protected only by POSIX file permissions (600), with no encryption-at-rest.

### CRITICAL: Raw JSON-RPC Input Logged at TRACE

**File:** `src/.../jsonrpc/JsonRpcReader.java:66`

```java
logger.trace("Incoming JSON-RPC message: {}", input);
```

At TRACE verbosity (`-vvv`), every JSON-RPC command including message content, phone numbers, and attachment paths is logged verbatim.

### HIGH: Phone Numbers Logged in Multiple Locations

| File | Line | Context |
|------|------|---------|
| `lib/.../internal/ManagerImpl.java` | 254 | Phone number normalization |
| `lib/.../api/RecipientIdentifier.java` | 46 | Number normalization |
| `lib/.../helper/RecipientHelper.java` | 59, 63 | UUID lookup failures |
| `src/.../commands/DaemonCommand.java` | 102 | Daemon startup |
| `lib/.../internal/ProvisioningManagerImpl.java` | 106 | Device linking |
| `lib/.../SignalAccountFiles.java` | 72, 75 | Account loading errors |

### HIGH: Temp Files Created Without Restricted Permissions

**File:** `lib/.../util/IOUtils.java:23-27`

```java
public static File createTempFile() throws IOException {
    final var tempFile = File.createTempFile("signal-cli_tmp_", ".tmp");
    tempFile.deleteOnExit();
    return tempFile;
}
```

Temp files containing group data, contacts, attachments, and avatars are created in the system `/tmp` directory with default umask permissions (potentially world-readable). The `deleteOnExit()` JVM hook is unreliable if the process is killed. Unlike `createPrivateFile()` (used elsewhere), these do not set owner-only permissions.

**Affected locations:**
- `lib/.../helper/SyncHelper.java:108,155` — Contact and group sync data
- `lib/.../helper/AttachmentHelper.java:124` — Attachment data
- `lib/.../helper/GroupHelper.java:532` — Group avatars
- `lib/.../helper/ProfileHelper.java:447` — Profile avatars

### MEDIUM: Scrubber Does Not Cover All Sensitive Data

**File:** `src/.../logging/Scrubber.java`

The scrubber covers: E164 phone numbers, UUIDs, email addresses, group IDs, domain names, IPv4 addresses. It does **not** scrub: message content/body text, cryptographic keys, registration lock PINs, file paths, or account entropy pools.

### MEDIUM: No Encryption-at-Rest for Stored Files

Attachments, avatars, sticker packs, message cache envelopes, and storage manifests are all written to disk without encryption:
- `lib/.../storage/AttachmentStore.java:53`
- `lib/.../storage/AvatarStore.java:65`
- `lib/.../storage/stickerPacks/StickerPackStore.java:47,56`
- `lib/.../util/MessageCacheUtils.java:112-119`
- `lib/.../storage/SignalAccount.java:1684-1689`

### MEDIUM: Internal Exception Details Exposed via D-Bus/JSON-RPC

Internal Java class names are included in error responses sent to clients:

```java
// src/.../Signal.java:690
super("Failure: " + e.getMessage() + " (" + e.getClass().getSimpleName() + ")");
```

Found in: `Signal.java:690`, `DbusSignalControlImpl.java:82,102,120,139,151`, `SignalJsonRpcCommandHandler.java:264,271`, `DbusManagerImpl.java:402`

---

## Category 3: Backdoors & Hidden Functionality

**Verdict: CLEAN** — No backdoors found.

- No hidden command handlers or undocumented RPC methods
- All 42 commands explicitly registered in `Commands.java:12-67`
- No dynamic class loading, reflection-based method calls, or obfuscated code
- No process spawning (`Runtime.exec()`, `ProcessBuilder`)
- No data exfiltration paths — all data writes are to expected directories
- No authentication bypasses (except documented `--trust-new-identities=always` flag)
- No file system access outside expected directories
- Only 4 environment variables, all documented and non-security-critical

---

## Category 4: Cryptographic Practices

**Verdict: STRONG** — Cryptography is properly implemented.

- All random number generation uses `SecureRandom` (via `NativePRNG` or `SHA1PRNG`)
- No weak algorithms (MD5, SHA1 for signing, DES, RC4, ECB mode) found
- No custom TrustManager or HostnameVerifier overrides
- Certificate pinning via embedded `whisper.store` trust store — cannot be disabled
- Key generation uses standard libsignal primitives (`ECKeyPair.generate()`, `KEMKeyPair.generate(KEMKeyType.KYBER_1024)`)

**Minor finding:** `AccountsStore.java:145` uses `new Random()` (not `SecureRandom`) for generating account directory names. Non-security-critical.

**`SignalBackwardsCompatProvider`** (`src/.../util/SecurityProvider.java`) simply registers BouncyCastle's BKS keystore support — no custom cryptographic logic or weakening.

---

## Category 5: Injection Vulnerabilities & Input Validation

### MEDIUM: Path Traversal in Attachment Retrieval

**File:** `lib/.../storage/AttachmentStore.java:46-48`

```java
public StreamDetails retrieveAttachment(final String id) throws IOException {
    final var attachmentFile = new File(attachmentsPath, id);
    return Utils.createStreamDetailsFromFile(attachmentFile);
}
```

The `id` parameter comes directly from user input (`GetAttachmentCommand.java:43`). No validation rejects `../` sequences. A value like `../../etc/passwd` escapes the attachments directory. Reachable via CLI, JSON-RPC, and D-Bus.

### MEDIUM: D-Bus sendMessage Allows Arbitrary File Reads

**File:** `src/.../dbus/DbusSignalImpl.java:230-262`

The `attachments` list in `sendMessage` contains file paths passed directly to `new File(value)`. A D-Bus client can supply `/etc/shadow` as an attachment path, causing signal-cli to read and upload it to Signal servers.

### MEDIUM: No Request Size Limits on JSON-RPC/HTTP

**Files:** `src/.../jsonrpc/JsonRpcReader.java:48-73`, `src/.../http/HttpServerHandler.java:117-131`

Neither the JSON-RPC reader nor the HTTP server imposes limits on incoming request size. A malicious client can send arbitrarily large payloads causing `OutOfMemoryError`.

### LOW: SQL — All User Data Uses PreparedStatement

Two instances of string concatenation in SQL were found (`Database.java:88` for `PRAGMA user_version` and `RecipientStore.java:422-426` for `IN` clause), but both use `long` values from internal sources that cannot contain SQL metacharacters.

### No XML/XXE, Deserialization, or Command Injection

The codebase uses no XML parsing, no `ObjectInputStream`, and no `Runtime.exec()` / `ProcessBuilder`.

---

## Category 6: Network Security

**Verdict: STRONG** for remote traffic. **MEDIUM RISK** for local daemon interfaces.

### All Endpoints Are Legitimate

Every URL in the codebase resolves to official Signal infrastructure:
- `https://chat.signal.org` (+ cdn, cdn2, cdn3, storage, cdsi, svr2)
- Staging variants: `*.staging.signal.org`
- No hardcoded IP addresses anywhere

### TLS/Certificate Pinning: Properly Enforced

- Custom `WhisperTrustStore` loaded from embedded `whisper.store` (BKS format)
- Contains exactly 2 certificates: original TextSecure CA + current Signal Messenger CA
- Used for all Signal service connections — system CA store is bypassed
- Cannot be disabled via CLI arguments or environment variables
- No `TrustManager`, `HostnameVerifier`, or `CertificatePinner` overrides in codebase

### HIGH: HTTP/TCP Daemon Interfaces Lack Authentication

**File:** `src/.../http/HttpServerHandler.java:55-68`

The HTTP server (`--http`) and TCP JSON-RPC socket (`--tcp`) have **no authentication**. Anyone who can reach the port can:
- Send messages as the registered Signal account
- Read received messages via SSE
- Execute any JSON-RPC command

Default bindings are `localhost` (safe), but the user can bind to `0.0.0.0` with no warning.

The HTTP server also:
- Uses plain HTTP (not HTTPS)
- Has no CORS headers (browser-based CSRF possible against localhost)
- Has no request body size limits

### Unix Domain Socket: Properly Secured

The Unix socket mode is the most secure local interface — directory created with owner-only permissions (700), peer credentials are logged.

---

## Category 7: Informational Findings

| Finding | File | Note |
|---------|------|------|
| 15+ TODO comments indicating incomplete features | Various | Pre-key handling, badge support, retry logic, trust decisions |
| `deleteOnExit()` used for socket paths | `src/.../util/IOUtils.java:154` | Unreliable if process killed |
| `new Random()` for directory names | `lib/.../storage/accounts/AccountsStore.java:145` | Non-security use |
| `System.err.println(e.getMessage())` | `src/.../Main.java:58-64` | Potentially exposes internal details |
| LibSignal logs forwarded without filtering | `lib/.../internal/LibSignalLogger.java:20-28` | May contain protocol-level sensitive data |

---

## Top Recommendations (Priority Order)

1. **Enable log scrubbing by default** — The `--scrub-log` flag should be on by default, with a `--no-scrub-log` to disable.
2. **Add authentication to HTTP/TCP daemon** — At minimum, require an API token header.
3. **Validate attachment IDs for path traversal** — Reject IDs containing `..` or `/`.
4. **Use `createPrivateFile` permissions for temp files** — Owner-only (600) instead of default umask.
5. **Add request size limits** to JSON-RPC reader and HTTP server.
6. **Warn when binding to non-loopback** — Display a security warning if `--tcp` or `--http` is bound to a non-localhost address.
7. **Consider encryption-at-rest** for the account JSON file (contains all key material).
8. **Extend the Scrubber** to cover message content, cryptographic keys, and file paths.
9. **Remove internal class names from error responses** — Don't expose `e.getClass().getSimpleName()` to D-Bus/JSON-RPC clients.
10. **Add CORS headers** to the HTTP server to prevent browser-based CSRF.
