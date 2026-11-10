[![Views](https://api.visitorbadge.io/api/visitors?path=Senophyx%2Fipasign&label=Views&countColor=%23002fff)](https://github.com/Senophyx/ipasign)
[![PyPI](https://img.shields.io/pypi/v/ipasign?style=for-the-badge&logo=pypi&logoColor=FFD43B)](https://pypi.org/project/ipasign)

# ipasign

iOS code signing written in Python. Re-sign `.ipa` archives, `.app` bundles,
frameworks, dylibs and bare Mach-O executables with a `.p12` identity and a
`.mobileprovision` profile, producing a signature that iOS and Apple's
`codesign` accept.

## Install

Via PyPI:

```bash
pip install ipasign
```

With uv:

```bash
uv add ipasign
```

Requires Python 3.10 or later. The only dependencies are `cryptography` and
`asn1crypto`, both installed automatically.

## Migrating from 1.0

`Key.sign()` is gone in 2.0. `Key` is now only a credential holder, and
`App` owns everything that touches the filesystem:

```python
# 1.0
key = ipasign.Key("identity.p12", "profile.mobileprovision", "password")
out = key.sign("input.ipa", "output.ipa")

# 2.0
key = ipasign.Key("identity.p12", "profile.mobileprovision", "password")
out = ipasign.App("input.ipa").sign(key, output="output.ipa")
```

`output_path` is now `output`. The other keyword arguments carry over to
`App.sign()`, with a few behaviour changes:

- `output` for a bundle folder is always refused, because a folder is signed in
  place.
- `tmp_folder` must be empty or missing. A folder that already holds files raises
  `ArchiveError` instead of being wiped.
- `bundle_id` only applies to a bare Mach-O. For an archive or a bundle folder it
  raises `InvalidInputError` instead of being ignored; use `set_bundle_id()`.
- `signed_count` counts Mach-O files, so it can be lower than 1.0 reported.
- An encrypted (FairPlay) binary raises `MachOError` instead of being signed.

Signatures are otherwise produced the same way. See the
[changelog](https://github.com/Senophyx/ipasign/blob/main/CHANGELOG.md) for the
full list, including the fixes.

## Quick Example

```python
import ipasign

key = ipasign.Key("identity.p12", "profile.mobileprovision", "password")

app = ipasign.App("input.ipa")
out = app.sign(key)

print(f"Successfully signed: {out.output_path}")
print(f"{out.app_name} {out.app_version} ({out.bundle_id})")
```

`App` accepts anything signable. An `.ipa` archive gets a default output named
after the input, so `input.ipa` becomes `input-signed.ipa`. Pass `output` to
name the target yourself:

```python
out = ipasign.App("input.ipa").sign(key, output="build/signed.ipa")
```

A bundle folder, a framework, a dylib and a bare Mach-O executable are signed
where they are, so `output` is refused for them:

```python
ipasign.App("Payload/MyApp.app").sign(key)   # signed in place
ipasign.App("libX.dylib").sign(key)          # signed in place
```

A folder that is not itself a bundle is searched for the `.app`/`.appex`
inside it, so an unzip output can be handed over as it is:

```python
app = ipasign.App("unzipped")
print(app.path)   # unzipped/Payload/MyApp.app
app.sign(key)
```

`sign()` returns a result object, not a boolean:

| Attribute | Meaning |
|-----------|---------|
| `output_path` | Where the signed artifact actually landed |
| `bundle_id` | The identifier sealed into the CodeDirectory |
| `signed_count` | How many Mach-O files were signed |
| `app_name` | The app's display name, read from `Info.plist` |
| `app_version` | The release version, read from `Info.plist` |

Failures raise. Every exception derives from `ipasign.IpasignError`.

## Bundle modification

Edits are recorded on `App` and applied in one pass before the seal, so an
edited file is always covered by the `CodeResources` that follows it. Every
method returns the `App`, so they chain:

```python
(
    ipasign.App("input.ipa")
        .set_bundle_id("com.example.prod")
        .set_name("ProdApp")
        .set_version("2.0")
        .set_icon("icon.png")
        .set_minimum_os("15.0")
        .enable_documents()
        .sign(key)
)
```

| Method | Effect |
|--------|--------|
| `set_bundle_id()` | `CFBundleIdentifier`, and the same id inside every nested `.app`/`.appex` |
| `set_name()` | `CFBundleName` and `CFBundleDisplayName`, plus the `zh_CN`/`zh-Hans` `InfoPlist.strings` files when present |
| `set_version()` | `CFBundleVersion` and `CFBundleShortVersionString` |
| `set_icon()` | The bundle-root PNGs the declared icon names cover |
| `enable_documents()` | `UISupportsDocumentBrowser` and `UIFileSharingEnabled` |
| `set_minimum_os()` | `MinimumOSVersion` |
| `remove_supported_devices()` | Drops the `UISupportedDevices` array |
| `remove_extensions()` | Deletes `PlugIns/` and `Extensions/` |
| `remove_watch_app()` | Deletes `Watch/`, `WatchKit/` and `com.apple.WatchPlaceholder/` |
| `remove_provision()` | Leaves `embedded.mobileprovision` out of the output |

`sign()` applies the recorded edits and then signs. To edit without signing, use
`modify()`, which needs no credential:

```python
ipasign.App("input.ipa").set_name("ProdApp").modify()
```

With no `output`, `modify()` writes back over the input. Pass `output` to keep
the original:

```python
ipasign.App("input.ipa").set_name("ProdApp").modify(output="edited.ipa")
```

Editing changes `Info.plist` and possibly `CodeResources`, so an existing
signature goes stale. `modify()` does not repair it; sign the result again.

## Certificate check

`check()` reports the certificate a file carries or was signed with, without
signing anything:

```python
report = ipasign.App("signed.ipa").check()

print(report.name)            # Apple Distribution: Test Corp (TEAM123456)
print(report.team)            # TEAM123456
print(report.expires)         # 2027-01-15T08:30:00Z
print(report.days_remaining)  # 354
print(report.ocsp.status)     # Valid
```

It accepts an `.ipa`, a Mach-O binary, a `.mobileprovision`, a `.p12`, a
`.cer`/`.der` or a `.pem`. An archive is read straight out of the zip, without
unpacking it. `Key.check()` reports an identity that is already loaded.

Revocation is queried over OCSP when the issuer is a known Apple intermediate.
Pass `ocsp=False` to skip the network call:

```python
report = ipasign.App("signed.ipa").check(ocsp=False)
```

`str(report)` and `report.to_json()` return the whole report as JSON.

## Metadata

`metadata()` reads what an app says about itself, without signing and without a
credential:

```python
meta = ipasign.App("input.ipa").metadata()

print(meta.name, meta.version, meta.bundle_identifier)
print(meta.size, meta.file_name, meta.timestamp)
```

Pass `save_to` to also write `metadata.json` and the primary icon into that
directory. Icons crushed by `pngcrush -iphone` are decoded back to a standard
PNG first.

## Ad-hoc signing

No credentials needed:

```python
ipasign.App("input.ipa").sign(ipasign.Key(adhoc=True))
```

## Changelog

Release notes are available in
[CHANGELOG.md](https://github.com/Senophyx/ipasign/blob/main/CHANGELOG.md).

## License
```
This Project under MIT License
Copyright (c) 2026 Senophyx
```
