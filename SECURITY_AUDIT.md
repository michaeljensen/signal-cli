# Security Audit Report: signal-cli

**Date:** 2026-02-06
**Scope:** Full codebase review of signal-cli (src/ and lib/ — 407 Java source files)
**Methodology:** Two-pass static analysis across 8 categories: hardcoded secrets, data leakage, backdoors, cryptography, injection, network security, input validation, and deep-dive (obfuscation, supply chain, covert channels)

---

## Executive Summary

The signal-cli codebase is **clean of backdoors, malicious code, and intentional security compromises**. No hidden functionality, data exfiltration paths, or weakened cryptography was found. All network connections go exclusively to legitimate Signal infrastructure (`*.signal.org`).

However, the audit identified several security gaps in data-at-rest protection, logging hygiene, input validation, and daemon interface authentication that represent real risk for production deployments.

---

## Severity Summary

| Severity | Count | Key Themes |
|----------|-------|------------|
| **CRITICAL** | 3 | Log scrubbing off by default; account secrets in plaintext JSON; JSON-RPC input logged at TRACE |
| **HIGH** | 6 | No HTTP/TCP daemon auth; unofficial core crypto library; phone numbers logged in plaintext; temp files in world-readable `/tmp`; no encryption-at-rest |
| **MEDIUM** | 11 | Path traversal; D-Bus arbitrary file read; no request size limits; no CORS; incomplete scrubber; no dependency verification; Gradle wrapper missing SHA-256; libsignal override property; CI write permissions |
| **LOW** | 12 | Fat JAR strips signatures; GH Actions pinned to tags; native access flag; informational items, minor TODOs |
| **CLEAN** | 4 areas | No obfuscated secrets; no hidden backdoors; no covert data channels; repository matches upstream |

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

## Category 8: Deep Dive — Obfuscation, Supply Chain, and Covert Channels

*Second-pass analysis specifically hunting for obfuscated secrets, hidden backdoors, and subtle data exfiltration.*

### Obfuscated Secrets: CLEAN

| Technique | Result |
|-----------|--------|
| **All Base64 literals decoded** | Every Base64 string in `LiveConfig.java` and `StagingConfig.java` decodes to binary cryptographic material (33-byte EC public keys, zkgroup params, backup server params). None decode to ASCII text, URLs, credentials, or instructions. |
| **Hex strings decoded** | Only MRENCLAVE values (SGX enclave measurements): `0f6fd79c...` (CDSI), `29cd63c8...` (SVR2 live), `a75542d8...` (SVR2 staging). Public Intel SGX measurements, not secrets. |
| **Char/byte array construction** | No `new char[]{}`, `new byte[]{}` with literal values, or `String.valueOf(new char[]{...})` patterns found anywhere. |
| **Piecewise string building** | All `StringBuilder`/`StringBuffer` usage is for log scrubbing, hex encoding, and error messages. No strings assembled to form secrets or URLs. |
| **XOR/bitwise on strings** | Only standard hex encoding bit shifts in `Hex.java:35`. No XOR decoding of hidden data. |
| **Resource file secrets** | `whisper.store` contains exactly 2 X.509 certificates (TextSecure CA + Signal Messenger CA). `META-INF/services/` contains only a Logback configurator class name. No embedded credentials. |
| **Unicode tricks** | No zero-width characters, homoglyphs, RTL overrides, or BOM characters in any source file. |
| **Custom annotations** | No custom annotations (`@interface`) defined anywhere in the codebase. |

### Hidden Backdoors: CLEAN

| Technique | Result |
|-----------|--------|
| **Date/time bombs** | No `LocalDate`, `Calendar`, year/month/day comparisons, or time-based conditional logic. |
| **Magic phone numbers/UUIDs** | No hardcoded phone numbers or UUIDs in conditional logic. |
| **Hidden env vars** | Only 4 env vars read: `SIGNAL_CLI_USER_AGENT`, `XDG_DATA_HOME`, `XDG_RUNTIME_DIR`, `GRAALVM_HOME` (build-time). None enable hidden functionality. |
| **Reflection** | Zero instances of `Class.forName()`, `Method.invoke()`, `getDeclaredMethod()`, `newInstance()`, `Proxy.newProxyInstance()`. The only `getMethod()` hits are JSON-RPC method-name getters. |
| **ClassLoader manipulation** | No `URLClassLoader`, `defineClass`, `loadClass`, or custom ClassLoaders. |
| **Hidden threads** | All thread creation is for documented functionality: HTTP server, JSON-RPC, socket handler, WebSocket health monitor, job executor. No unexplained threads. |
| **Native code/JNI** | No `System.loadLibrary()` or `System.load()` in signal-cli's own source. `libsignal-client` JNI is a transitive dependency. |
| **Hidden network listeners** | All `ServerSocketChannel` instances are in `IOUtils.java:130-136` (user-requested via `--tcp`/`--socket`) and `DaemonCommand.java:157` (systemd socket activation). No hidden listeners. |
| **File watchers** | No `WatchService`, `FileObserver`, or `inotify` usage. |
| **Serialization gadgets** | No `readObject`, `readResolve`, `writeReplace`, `readExternal`, or `ObjectInputStream`. Jackson polymorphic typing (`enableDefaultTyping`, `JsonTypeInfo`) not used. |
| **Process execution** | The only `Runtime.getRuntime()` call is for a shutdown hook in `Shutdown.java:26`. Zero instances of `ProcessBuilder`. |

### Covert Data Channels: CLEAN

| Technique | Result |
|-----------|--------|
| **DNS exfiltration** | No dynamic hostname construction from data. DNS is default OkHttp (`Optional<Dns> dns = Optional.empty()`). |
| **HTTP header exfil** | Only custom header is `User-Agent`. No data from messages, keys, or phone numbers in any HTTP header. |
| **Steganography** | No `BufferedImage`, `ImageIO`, pixel manipulation, or data embedding in attachments. |
| **Timing side channels** | Two instances of `Arrays.equals()` on crypto material (`GroupV2Helper.java:423`, `IdentityHelper.java:34`), but both are local comparisons for data freshness — not authentication or MAC verification. Not exploitable as timing oracles. |
| **Error-based exfil** | No intentional exception throwing that encodes data. Standard error patterns only. |

### Supply Chain Risks

#### HIGH: Unofficial Signal Protocol Library

**File:** `gradle/libs.versions.toml:14`
```
signalservice = "com.github.turasa:signal-service-java:2.15.3_unofficial_137"
```

The **most security-critical dependency** (handles all encryption, key exchange, message sending/receiving) comes from `com.github.turasa` — a personal GitHub fork, not the official Signal organization (`org.signal`). The version string `2.15.3_unofficial_137` explicitly marks it as unofficial. Signal does not publish `signal-service-java` as a standalone Maven artifact, so this fork is necessary for signal-cli to exist, but it means the core cryptographic code cannot be verified against an official Signal release without manual diff.

#### MEDIUM: No Gradle Dependency Verification

No `gradle/verification-metadata.xml` exists. Downloaded dependency checksums and PGP signatures are not validated. Combined with `mavenLocal()` in the repository list (`settings.gradle.kts:4`), an attacker with write access to `~/.m2/repository/` could substitute any dependency.

#### MEDIUM: Gradle Wrapper Missing SHA-256 Checksum

**File:** `gradle/wrapper/gradle-wrapper.properties`

The `distributionSha256Sum` property is not set, meaning the Gradle distribution ZIP is downloaded without checksum verification. However, the wrapper JAR itself was verified: SHA-256 `b3a875ddc1f044746e1b1a55f645584505f4a10438c1afea9f15e92a7c42ec13` matches the official Gradle 9.3.0 release.

#### MEDIUM: libsignal-client Override Build Property

**File:** `lib/build.gradle.kts:17-27`

The `libsignal_client_path` Gradle property allows substituting the core crypto library with an arbitrary local JAR via `-Plibsignal_client_path=/path/to/jar`. Developer convenience feature that widens the attack surface on build systems.

#### MEDIUM: CI Workflow Has `contents: write` on All Branches

**File:** `.github/workflows/ci.yml:11`

The CI workflow grants write access to repository contents for all push/PR events, including pull requests from forks.

#### LOW: Fat JAR Strips Dependency Signatures

**File:** `build.gradle.kts:126-128`

The `fatJar` task removes `META-INF/*.SF`, `*.DSA`, `*.RSA` signature files from dependencies. Standard for uber JARs, but means individual dependency integrity cannot be verified after packaging.

#### LOW: GitHub Actions Pinned to Major Version Tags

**File:** `.github/workflows/ci.yml:23-29`

`actions/checkout@v4`, `actions/setup-java@v3`, etc. are pinned to major tags instead of commit SHAs. A compromised tag could be moved to point to malicious code.

#### LOW: `--enable-native-access=ALL-UNNAMED` JVM Flag

**File:** `build.gradle.kts:27`

Grants unrestricted native memory access to all unnamed modules. Required by `libsignal-client`'s JNI, but widens the attack surface if any dependency is compromised.

### Repository Integrity: VERIFIED

This repository is an **unmodified fork of upstream AsamK/signal-cli** (version 0.13.24 / 0.14.0-SNAPSHOT). The only non-upstream addition is this `SECURITY_AUDIT.md` file. All 46 upstream commits are from `AsamK <asamk@gmx.de>` (the official maintainer) plus standard community contributions. No source code, build files, or configuration has been modified from upstream.

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
11. **Add Gradle dependency verification** (`verification-metadata.xml`) and remove `mavenLocal()` from production builds.
12. **Add `distributionSha256Sum`** to `gradle-wrapper.properties`.
13. **Pin GitHub Actions to commit SHAs** instead of mutable version tags.
