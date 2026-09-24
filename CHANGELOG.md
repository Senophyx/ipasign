# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0] - 2026-09-25

First public release. `ipasign` is a pure-Python iOS code signing library that re-signs
`.ipa` archives, `.app` bundles, frameworks, dylibs and bare Mach-O executables using a
`.p12` identity and a `.mobileprovision` profile. Signatures are accepted by iOS and Apple's
`codesign`.

### Added

- **Signing API.** A single entry point, `Key(pkey, prov, password).sign(input, output)`,
  that dispatches on input type: an `.ipa` archive, an `.app` bundle folder, or a bare Mach-O
  file. Returns a result object with `output_path`, `bundle_id`, `signed_count`, `app_name`
  and `app_version`.
- **Mach-O support.** Full parsing and rewriting of thin and fat containers, including
  `LC_CODE_SIGNATURE` insertion and `__LINKEDIT` resizing when the existing signature region
  is too small. Fat slices are re-laid at 16384-byte alignment.
- **Code signature construction.** CodeDirectory, Requirements, XML and DER entitlements, and
  SuperBlob assembly, byte-compatible with Apple's own output.
- **CMS signatures.** Detached PKCS#7 `SignedData` with SHA-256 and RSA PKCS#1 v1.5, carrying
  Apple's signed attributes and the certificate chain.
- **Identity loading.** `.p12` key and certificate loading, provisioning profile parsing, and
  automatic Apple WWDR intermediate resolution from the leaf's issuer.
- **Bundle signing.** Deepest-first traversal, per-bundle `Info.plist` sealing,
  `CodeResources` generation, and embedded provisioning profile placement before sealing.
- **Archive handling.** `.ipa` unpack and repack with a scratch directory that is removed
  automatically, or kept on request.
- **Ad-hoc signing.** Credential-less signing via `Key(adhoc=True)` for development builds.
- **Typed errors.** A dedicated exception hierarchy rooted at `IpasignError`, so no raw
  `struct.error`, `KeyError` or `ValueError` escapes the public API.

### Fixed

- Ad-hoc signatures now omit the CMS slot entirely instead of writing an empty wrapper, which
  the previous shape produced.
- Bare Mach-O files signed outside a bundle now fall back to the full file name, extension
  included, matching Apple's behaviour.
- Malformed or truncated Mach-O input is reported as a typed `MachOError` rather than leaking
  a low-level unpacking error.

### Security

- Archive extraction refuses absolute paths, drive letters and parent-directory traversal, so
  a crafted `.ipa` cannot write outside the scratch directory.
