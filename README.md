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

## Quick Example

```python
import ipasign

key = ipasign.Key("identity.p12", "profile.mobileprovision", "password")
out = key.sign("input.ipa", "output.ipa")

print(f"Successfully signed: {out.output_path}")
print(f"{out.app_name} {out.app_version} ({out.bundle_id})")
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

### Ad-hoc signing

No credentials needed:

```python
ipasign.Key(adhoc=True).sign("input.ipa", "output.ipa")
```

## License
```
This Project under MIT License
Copyright (c) 2026 Senophyx
```
