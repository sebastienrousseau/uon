# uon.ux

## Overview
The `uon.ux` package houses all strictly visual and interactive Terminal User Interface (TUI) components built upon the `Textual` Python library. It enables beautiful, responsive, and cross-platform native experiences for first-time registration and CAEP intervention blocking.

## Key Components

- **`wizard.py`**: The `OnboardingWizard` application. Triggers on `uon init` to capture initial `TargetStore` telemetry and run the user through a guided FIDO2 passkey hardware tap workflow.
- **`intervention.py`**: The CAEP Anomaly detector overlay. Sliding native dialogs directly over active SSH pipes to enforce step-up authentication.
- **`telemetry.py`**: Headless tracing utilities rendering localized dashboard states mapping execution logs.

## Performance Note
Because Textual is a robust framework, modules within `uon.ux` must **always** be imported *lazily* from within the `uon.cli` execution scopes. Do not place root-level `import uon.ux` macros within the `cli.py` or `.auth/` packages, to strictly protect the 5ms cold-start latency budget on non-interactive SSH events.
