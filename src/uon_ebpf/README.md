# uon_ebpf

Welcome to `uon_ebpf`. This module drives your CAEP (Continuous Access Evaluation Profile).

Inject these highly restricted `C` programs directly into the Linux Kernel. Use them to police active SSH execution environments dynamically in real-time.

## Mission Critical Boundaries

Your eBPF code must adhere to strict operational logic to satisfy the kernel verifier:

- **No loops:** Ensure all execution paths terminate deterministically.
- **Zero dynamic memory:** Map your state strictly to pre-allocated BPF Maps.
- **Intervention Protocol:** Intercept anomalous commands (like `su`) or restricted filesystem breaches instantly. The eBPF hook aggressively freezes the PID. It then signals your local Python UI (`uon.ux.intervention`) to demand a physical Step-Up FIDO2 authentication.
