# Windows process identity for the gate

```
Document:  docs/IDENTITY-WINDOWS.md, version 1.0 (ships with 0.7.0.0)
Status:    research and position. **No launcher code ships for Windows.**
Source:    docs/GATE-RESEARCH.md section 1, read from vendor and primary
           sources on 2026-08-08; epistemic labels retained
```

macOS ships a signed launcher with a stable cdhash; Linux uses a named
systemd unit plus an ELF SHA-256. Windows was researched before anything was
written, and the research changed what may be claimed. That is why this
document exists and a `build_identity_windows.py` does not.

## What the platform offers

- **Authenticode** signs a PE with a certificate from a CA the OS trusts,
  optionally countersigned by a timestamping service so verification survives
  certificate expiry or revocation. [measured]
- **`WinVerifyTrust`** is the user-mode API through which signed-code trust is
  validated; the same validation underpins AppLocker and Device Guard and
  feeds AV and EDR classification. [measured]
- **Sysmon Event ID 1** carries what an allowlist would key on: `Image`,
  `CommandLine`, `Hashes` (MD5/SHA-256/IMPHASH), `ParentImage`,
  `ParentCommandLine`, `ProcessGuid`, `ParentProcessGuid`, `User`, `LogonId`,
  and signature information. [measured]

## Three findings that shape the position

1. **The Authenticode hash is not the file hash.** It covers specific PE
   sections in a specific order and deliberately permits some regions to be
   modified and sections reordered; the `ExpectedHash` inside a signature
   does not equal SHA-256 over the file. An allowlist keyed on "the hash" is
   therefore ambiguous on Windows, and an operator who pastes one value into
   a control expecting the other has a control that does not fire. [measured]
2. **`ProcessGuid`, not the PID, is the correlation key.** PIDs are reused,
   which is precisely why Sysmon mints a GUID. A PID in an audit record is a
   value that will name a different process within the retention window.
   [measured]
3. **Parent-process attribution is not a control.** Parent-PID spoofing is an
   established technique and detection content in the wild must handle
   process-create records whose parent executable is simply absent. Below the
   API, the trust architecture itself is subvertible: tampering with SIP
   components and trust providers misleads `WinVerifyTrust` and, with it, the
   products that depend on it. [measured]

Finding 3 is the one that matters. The macOS design said "signed parent,
stable cdhash, allowlist by bundle-id/cdhash". On Windows both halves of that
- the ancestry and the signature validation - have known subversion paths
that do not require kernel access.

## The position, at its real strength

> The launcher is Authenticode-signed and publishes **both** its Authenticode
> hash and a plain SHA-256 of the PE, each labelled. The gate records its own
> `ProcessGuid` and image path in the ledger at startup. Allowlisting is
> recommended on image path **plus** file hash **plus** signer. Process
> ancestry is **evidence, not a control**: an adversary who spoofs a parent
> PID or tampers with a trust provider defeats ancestry-based attribution,
> and neither is exotic.

This is threat-model row **PT19**, accepted with a named trigger: the moment
the gate runs on a host the approver does not control, the row needs
attestation this launcher cannot provide.

## What was not found

No source establishing a Windows equivalent of macOS's *stable cdhash across
interpreter updates* - the property the macOS artefact already qualifies.
Absent evidence, the Windows artefact must not claim it. This is a measured
absence, not proof of absence. [measured absence]

## What ships, and when

Nothing executable, in this version. The launcher is owned by the first
version that runs the gate on Windows, and it ships with the wording above or
it does not ship. Writing the code first and discovering finding 3 afterwards
would have produced an artefact whose README claimed a strength the platform
does not grant.
