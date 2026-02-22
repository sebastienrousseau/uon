# uon

<!-- markdownlint-disable MD033 MD041 -->
<center>
<!-- markdownlint-enable MD033 MD041 -->

[![Made With Python][made-with-python]][08] [![PyPI Version][pypi-badge]][03] [![Release][release-badge]][01] [![Docs][docs-badge]][04] [![Codecov][codecov-badge]][06] [![Build Status][build-badge]][07] [![GitHub][github-badge]][09]

• [Website][00] • [Documentation][04] • [Report Bug][02] • [Request Feature][02]

<!-- markdownlint-disable MD033 MD041 -->
</center>
<!-- markdownlint-enable MD033 MD041 -->

## Architectural Overview
Use `uon` to enforce FIDO2-signed Remote Terminal Execution. Secure your infrastructure with zero-trust execution bounds instead of relying on compromised static SSH private keys.

Follow this critical path:

1. Register a physical passkey in the `TargetStore`.
2. Connect to the target node, triggering a physical touch prompt (Touch ID, Windows Hello, YubiKey).
3. The hardware signs a challenge, dispatching the Zero-Trust envelope across SSH for execution.

## Feature List
- **Hardware Bindings**: Native routing for Apple Secure Enclave, Windows Hello, and USB security keys (YubiKey/SoloKey).
- **Core Security**: No private key material touches the disk. All cryptographic signatures occur strictly within the hardware bounds.
- **Python-Rust FFI**: Memory-safe parsing of assertions via the monolithic `uon_core` Rust execution engine.
- **TUI Onboarding**: Beautiful, lazy-loaded `Textual` wizards designed for frictionless credential enrollment.
- **QR Fallback**: Support for out-of-band signing via mobile devices if the primary controller lacks biometrics.
- **Continuous Access Evaluation Profile (CAEP)**: Experimental kernel policing via the `uon_ebpf` Linux module to terminate anomalous remote processes.

## Platform Support Matrix
`uon` is evaluated structurally across macOS and Linux, guaranteeing absolute cryptography conformance.

| Platform | Status | Notes |
|---|---|---|
| macOS | Supported | Primary development workflow. Native Touch ID bindings validated. |
| Linux | Supported | Production execution target. Requires `fido2` libraries for verification. |
| Windows | Supported | Validated against Windows Hello. |
| WSL (Windows Subsystem for Linux) | Supported | USB token pass-through requires `usbipd-win`. |

## Installation
Add this to your environment utilizing `uv` or `pip`:

```bash
uv pip install uon==0.0.3
```

## Quick Start
Initialize the onboarding wizard and register your first trusted FIDO2 credential.

```bash
# Launch the Onboarding Wizard
uon init

# Execute a Zero-Trust command
uon prod "uptime"
```

## Documentation
- The Python CLI documentation is natively served via the generated Sphinx build: `docs/_build/html/index.html`
- Explore the monolithic engine architecture: [`src/uon_core/README.md`](src/uon_core/README.md)
- Unpack the eBPF CAEP structures: [`src/uon_ebpf/README.md`](src/uon_ebpf/README.md)

## License
This project is licensed under the [GNU Affero General Public License v3.0][10].

[00]: https://sebastienrousseau.github.io/uon/
[01]: https://github.com/sebastienrousseau/uon/releases
[02]: https://github.com/sebastienrousseau/uon/issues
[03]: https://pypi.org/project/uon/
[04]: https://sebastienrousseau.github.io/uon/
[06]: https://codecov.io/gh/sebastienrousseau/uon
[07]: https://github.com/sebastienrousseau/uon/actions
[08]: https://www.python.org/
[09]: https://github.com/sebastienrousseau/uon
[10]: https://www.gnu.org/licenses/agpl-3.0.html
[build-badge]: https://img.shields.io/github/actions/workflow/status/sebastienrousseau/uon/ci.yml?branch=main&style=for-the-badge&logo=github
[codecov-badge]: https://img.shields.io/badge/codecov-100%25-brightgreen.svg?style=for-the-badge&logo=codecov
[pypi-badge]: https://img.shields.io/pypi/v/uon?style=for-the-badge&logo=pypi&logoColor=white&color=blue
[docs-badge]: https://img.shields.io/badge/docs-latest-blue.svg?style=for-the-badge&logo=read-the-docs&logoColor=white
[github-badge]: https://img.shields.io/badge/github-sebastienrousseau/uon-8da0cb?style=for-the-badge&labelColor=555555&logo=github
[release-badge]: https://img.shields.io/badge/release-v0.0.3-orange.svg?style=for-the-badge
[made-with-python]: https://img.shields.io/badge/Made%20with-Python-1f425f.svg?style=for-the-badge&logo=python&logoColor=white
