# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0] - 2026-10-30

### Breaking changes

- **Signing moved from `Key` to `App`.** `Key.sign()` is gone. `Key` is now only a credential
  holder: it loads the `.p12`, the profile and the entitlements, and exposes them through
  `signer()`. Everything that touches the filesystem lives on `App`.

  ```python
  # before
  key = ipasign.Key("identity.p12", "profile.mobileprovision", "password")
  out = key.sign("input.ipa", "output.ipa")

  # after
  key = ipasign.Key("identity.p12", "profile.mobileprovision", "password")
  app = ipasign.App("input.ipa")
  out = app.sign(key, output="output.ipa")
  ```

  The signed bytes are unchanged: the same input produces a byte-identical archive through
  either path.

### Added

- **Bundle modification.** `App` records edits and applies them in one pass before the seal, so an
  edited file is always covered by the `CodeResources` that follows it. Each method returns the
  `App`, so they chain:

  ```python
  (ipasign.App("input.ipa")
      .set_bundle_id("com.example.prod")
      .set_name("ProdApp")
      .set_version("2.0")
      .set_icon("icon.png")
      .set_minimum_os("15.0")
      .enable_documents()
      .sign(key))
  ```

  `set_bundle_id()` rewrites `CFBundleIdentifier` in the root plist and string-replaces the old
  identifier in every nested `.app`/`.appex` (`CFBundleIdentifier`,
  `WKCompanionAppBundleIdentifier`, `NSExtension.NSExtensionAttributes.WKAppBundleIdentifier`).
  `set_name()` writes `CFBundleName`/`CFBundleDisplayName` and the `zh_CN`/`zh-Hans`
  `InfoPlist.strings` files when present. `set_version()` writes both version keys.
  `set_icon()` overwrites the bundle-root PNGs the declared icon names cover and drops
  `CFBundleIconName` so the `Assets.car` icon does not win on iOS 11+. `enable_documents()`,
  `set_minimum_os()`, `remove_supported_devices()`, `remove_extensions()`, `remove_watch_app()`
  and `remove_provision()` are independent toggles. Anything that needs a bundle raises on a bare
  Mach-O at call time, where `set_bundle_id()` sets the identifier sealed into the CodeDirectory
  instead.
- **`App.modify()`** applies the recorded edits without signing, so bundle modification works
  with no credential. An archive is rewritten in place unless `output` names a target; a bundle
  folder is edited where it is. `sign()` applies the same edits and then seals.
- **Input folder discovery.** A folder that is not itself a bundle is searched for the
  `.app`/`.appex` inside it, so a hand-unzipped archive can be handed over as it is, without
  knowing where the bundle landed. `App("unzipped")`, `App("unzipped/Payload")` and
  `App("unzipped/Payload/Runner.app")` all resolve to the same bundle, and `App.path` reports
  which one. Candidates are visited in sorted order, so the same tree always resolves the same
  way, `__MACOSX` is skipped, and a folder holding no bundle raises `InvalidInputError` at
  construction rather than failing later on a missing `Info.plist`. A folder that is already a
  bundle, either because its name ends in a bundle suffix or because it carries its own
  `Info.plist`, is used as it is, never scanned, so `App("Runner.app")`, `App("Inner.framework")`
  and a renamed `App("MyApp")` behave exactly as before.
- **`BundleEdits`** in `ipasign.edit` holds the recorded queue, and `ipasign.edit.apply_edits`
  runs the pass over a bundle root.
- **`App` facade.** `ipasign.App` accepts anything signable: an `.ipa` archive, an `.app`
  bundle folder, a framework, a dylib or a bare Mach-O executable, and dispatches on what it
  finds. `sign()` and `modify()` return a `SignResult`; `metadata()` and `check()` return their
  own result types.
- **Default output for an archive.** `App("test.ipa").sign(key)` writes `test-signed.ipa`
  beside the input. Pass `output` to name the target explicitly.
- **`Key.signer()`** exposes the credential-derived `Signer`, for callers working below the
  `App` level.
- **`ipasign.result.SignResult`** now lives in its own module, so `App` and `Key` can both
  refer to it without importing each other. It is still importable from `ipasign`.
- **Metadata extraction.** `App.metadata()` reads an app's name, version, bundle identifier,
  archive size, primary icon name and a timestamp, without signing and without a credential.
  Pass `save_to` to also write `metadata.json` and the app's primary icon into that directory.
  Works for an `.ipa`, an `.app` bundle folder and a bare Mach-O with an embedded
  `Info.plist`. `size` and `file_name` describe an archive, so both are empty for the two
  non-archive cases. `Metadata` is exported from `ipasign`.
- **CgBI icon decoding.** Icons crushed by `pngcrush -iphone` are converted back to a standard
  PNG (headerless inflate, row unfiltering, BGRA swap, alpha un-premultiplication) before they
  are written.
- **Certificate inspection.** `ipasign.check(path, password=None, *, ocsp=True, timeout=10.0)`
  reports the certificate a file carries or was signed with: subject name, derived type,
  organization, team, serial, validity window, days remaining, key algorithm and issuer. It
  accepts an `.ipa`, a Mach-O binary, a `.mobileprovision`, a `.p12`, a `.cer`/`.der` or a
  `.pem`; an archive is read straight out of the zip, without unpacking it. The result is a
  `CertCheckResult` whose `to_json()` (also `str(result)`) returns the report, and whose
  certificate fields are forwarded as properties such as `result.expires`. `App.check()`
  resolves a bundle folder to its `CFBundleExecutable` first, and `Key.check()` reports the
  already-loaded identity without touching the file again (an ad-hoc key reports
  `not_signed`).
- **OCSP revocation checking.** When the issuer is a known Apple intermediate, the certificate's
  Authority Information Access extension is used to query the responder, falling back to
  `ocsp.apple.com` otherwise. The outcome is one of `Valid`, `Revoked`, `Unknown`, `Error` or
  `Skipped` (non-WWDR issuer, or `ocsp=False`), alongside a numeric `code` (`0` valid,
  `1` revoked, `2` expired, `-2` not signed, `-1` error) and a stable `status` string.
  `CertCheckResult`, `CertificateInfo` and `OcspResult` are exported from `ipasign`.

### Changed

- An output path for a bundle folder is now always refused on `App.sign()`. Previously the
  folder's own path was accepted, since that is where the bundle is signed anyway, and a bare
  Mach-O already refused one.
- A `tmp_folder` passed to `App.sign()` or `App.modify()` must now be empty or missing. A
  folder that already holds files raises `ArchiveError` and is left untouched. Previously it
  was wiped before unpacking, which could delete the caller's own files.
- `bundle_id` on `App.sign()` is now refused for a bundle folder and an archive with
  `InvalidInputError`. It was silently ignored there; use `set_bundle_id()` instead.
- Signing a FairPlay-encrypted binary now raises `MachOError`. It used to sign cleanly and
  produce an app that cannot launch.
- `SignResult.signed_count` now counts files, as documented. A bundle executable is signed
  twice and a fat binary holds several slices, and both used to inflate the number.

### Removed

- `ProvisioningProfile.get_task_allow`. It was unused, and it read the entitlement more loosely
  than the signer does. The signer's own rule, true only for a boolean `true`, still applies.

### Fixed

- A `.DS_Store` file below the bundle root is now left out of `files2` in `CodeResources`, as
  the seal's own rules require. Sealing it made `codesign --verify` report a missing resource.
- Two runs on the same archive no longer share a scratch folder. Each unpack gets its own, so
  signing one `.ipa` in parallel, or reading its metadata while it is being signed, no longer
  fails with a raw `FileExistsError` or `FileNotFoundError`. A failed unpack also cleans up
  after itself.

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
