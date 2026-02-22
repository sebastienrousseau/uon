import os
import re
import json

files = ['src/uon_site/index.html', 'src/uon_site/articles.html', 'src/uon_site/faq.html', 'src/uon_site/download.html']

nav_links = """
        <a href="articles.html" class="nav-link">Articles</a>
        <a href="faq.html" class="nav-link">FAQ</a>
        <a href="download.html" class="nav-link">Download</a>"""

footer_html = """  <footer>
    <div class="container flex items-center justify-between" style="flex-wrap: wrap;">
      <p>&copy; <script>document.write(new Date().getFullYear())</script> Sebastien Rousseau.</p>
      <div class="flex gap-4">
        <a href="articles.html" class="nav-link">Articles</a>
        <a href="faq.html" class="nav-link">FAQ</a>
        <a href="download.html" class="nav-link">Download</a>
      </div>
    </div>
  </footer>"""

faqs = {
  'Technical Architecture': [
    ['Is uon open-source?', 'Yes, governed under the GNU AGPLv3 license to ensure total downstream transparency.'],
    ['What language is uon built in?', 'Memory-safe Rust with strict Python PyO3 bindings for the core execution orchestration.'],
    ['Does uon use TCP for IPC?', 'No, it exclusively binds session exchanges via aggressive AF_VSOCK native streams to eliminate sniffable ports.'],
    ['Where is the state stored?', 'Zero state. It executes purely ephemerally in RAM and immediately wipes on teardown.'],
    ['How big is the binary?', 'We ship a highly optimized, zero-dependency environment guaranteeing static payloads.'],
    ['Can I use it offline?', 'Yes, for local endpoints, as long as the hardware enclave and CTAP2 hardware remain accessible.'],
    ['Does it require an agent?', 'Yes, a lightweight Rust verifier daemon is required on the remote execution endpoint.'],
    ['Is there a GUI interface?', 'Currently CLI and WebAssembly TUI. Web-based fleet management is planned for Phase 40.'],
    ['Can I self-host the infrastructure?', 'Yes, entirely self-hosted. There are zero external dependencies or telemetry callbacks.'],
    ['What defines the trust boundary?', 'Cryptographically enforced eBPF tracepoints and EndpointSecurity frameworks within the kernel natively.']
  ],
  'FIDO2 & Authentication': [
    ['What authentication is supported?', 'Only WebAuthn via FIDO2 hardware keys or Secure Enclaves.'],
    ['Are legacy passwords supported?', 'No. Passwords and legacy SSH `id_ed25519` keys are totally deprecated and blocked.'],
    ['Can I use a Yubikey?', 'Yes, any strict CTAP2 compliant authenticator is fully supported out-of-the-box.'],
    ['Does it allow synced passkeys?', 'No, we parse `backup_eligible == False` to enforce hardware-attested, non-extractable keys.'],
    ['What if I lose my token?', 'You must rotate hardware via secure enterprise recovery CI/CD workflows.'],
    ['Does it integrate with TouchID?', 'Yes, Apple Secure Enclave is natively integrated via roaming authenticators.'],
    ['Are biometrics stored remotely?', 'No, FIDO2 strictly keeps biometrics cryptographically isolated inside the hardware boundary.'],
    ['How fast is the login flow?', 'Virtually instantaneous upon biometric physical presence evaluation.'],
    ['Can attackers scrape my private key?', 'Mathematically impossible. The private signing key never physically leaves the hardware boundary under any condition.'],
    ['Is SMS 2FA allowed as fallback?', 'Absolutely not. Only unphishable cryptography is permitted within the execution paths.']
  ],
  'Post-Quantum Cryptography': [
    ['What is PQC?', 'Algorithms specifically designed to resist decryption attempts by Shor-capable quantum computers.'],
    ['Which PQC algorithms does uon use?', 'ML-KEM (Kyber) and ML-DSA (Dilithium) tracking the latest NIST standards.'],
    ['Why is RSA no longer sufficient?', 'Nation-state adversaries are currently executing "harvest now, decrypt later" campaigns at scale.'],
    ['What is SNTRUP?', 'A highly verified lattice-based encryption algorithm used natively for secondary fallback security.'],
    ['Does PQC add execution latency?', 'uon leverages memory-safe Rust FFI to execute PQC validations in under 5 milliseconds.'],
    ['Are these NIST approved?', 'Yes, aggressively tracking and implementing the finalized FIPS 203/204 standard definitions.'],
    ['Do I need special cryptographic hardware?', 'No, the lattice math executes entirely against standard CPU logic.'],
    ['How does it verify session signatures?', 'Via purely asymmetric ML-DSA signatures embedded directly within the handshake payload.'],
    ['Can I downgrade the tunnel to RSA?', 'No, uon rigidly and natively enforces post-quantum tunnels under all conditions.'],
    ['Is this a hybrid crypto implementation?', 'Yes, safely merging PQC structures with classical constraints to ensure total backward compliance without risk.']
  ],
  'Zero Standing Privilege (ZSP)': [
    ['What is ZSP?', 'The strict architectural paradigm of granting just-in-time (JIT) access only when actively required.'],
    ['Does uon allow 24/7 admin rights?', 'No. Privileges are strictly ephemeral and dynamically granted upon verified enclave execution.'],
    ['How is the localized access approved?', 'Via strict FIDO2 attestation signatures evaluated natively against your authorized OpenID profile.'],
    ['What happens after I log out?', 'The dynamically provisioned `uon-exec` Linux context pivot is deterministically destroyed.'],
    ['Can local malware pivot across endpoints?', 'No, lateral movement is neutralized since standing credentials do not exist to be stolen or abused.'],
    ['How is execution scope restricted?', 'Through native continuous evaluation inside our Custom Access Evaluation Profiles (CAEP).'],
    ['Does it use sudo locally?', 'We enforce strict JIT sudo policies scoped exactly to the parsed task environment alone.'],
    ['What triggers an immediate revocation?', 'Session timeouts, manual exists, kernel violations, or generic threat intelligence signals.'],
    ['Is the ephemeral escalation auditable?', 'Yes, every JIT privilege escalation natively executes deep non-repudiable kernel logging.'],
    ['Who provisions the JIT environment?', 'The local `uon-verifier` daemon operating deeply natively on the target execution host.']
  ],
  'Execution & Supported Systems': [
    ['Does the endpoint run on macOS?', 'Yes, native deployment support with deep XNU hooks into Apple EndpointSecurity frameworks.'],
    ['Does the endpoint run on Linux?', 'Yes, deeply integrated with strict eBPF kernel enforcement structures.'],
    ['Is Windows architectures supported?', 'Yes, but rigidly utilizing Windows Subsystem for Linux (WSL) environments natively.'],
    ['What hardware architectures compile?', '`x86_64` and `aarch64` native rust toolchains.'],
    ['Is Docker or Podman supported?', 'Yes, ephemeral containers natively can operate as hardened execution endpoints.'],
    ['Does uon require customized kernels?', 'Standard modern Linux kernels (eBPF-ready) are sufficient out-of-the-box.'],
    ['Can I run the daemon as a root process?', 'It natively drops root privileges instantly after successfully binding the AF_VSOCK streams.'],
    ['What is the execution memory limit?', 'It requires strictly less than 40MB of RAM under maximum concurrent execution load limits.'],
    ['Are mobile verification nodes supported?', 'Native iOS and Android verifiers are actively tracked on the long-term roadmap.'],
    ['How do I install the binaries?', 'Through tightly bound Cargo crates, Homebrew taps, or our official zero-dependency release objects.']
  ]
}

def generate_faq_html():
    html = '<h2 class="section-title text-center">Frequently Asked Questions</h2>\\n'
    for category in faqs:
        html += f'      <div class="faq-category">\\n        <h3>{category}</h3>\\n        <div class="faq-grid">\\n'
        for q, a in faqs[category]:
            html += f'          <details class="faq-item">\\n            <summary>{q}</summary>\\n            <div class="faq-content"><p>{a}</p></div>\\n          </details>\\n'
        html += '        </div>\\n      </div>\\n'
    return html

for filepath in files:
    with open(filepath, 'r') as f:
        content = f.read()

    # Inject Top Nav if missing
    if 'href="articles.html"' not in content.split('<nav')[1].split('</nav>')[0]:
        content = content.replace(
            '<div class="flex items-center gap-4">',
            f'<div class="flex items-center gap-4">{nav_links}'
        )

    # Inject Footer
    content = re.sub(r'<footer>.*?</footer>', footer_html, content, flags=re.DOTALL)
    
    # Check if FAQ file to inject questions
    if 'faq.html' in filepath:
        # replace inside section id="faq"
        content = re.sub(r'<section id="faq" .*?>.*?</section>', f'<section id="faq" class="container faq-section" aria-label="Frequently Asked Questions">\\n{generate_faq_html()}    </section>', content, flags=re.DOTALL)

    with open(filepath, 'w') as f:
        f.write(content)

print("✅ Navigation Links injected and 50-Item FAQ built.")
