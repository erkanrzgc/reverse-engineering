# Security

Treat every analyzed file as hostile input. The parser, disassembler, and report
writers process attacker-controlled bytes and strings; they must not execute the
input binary. Run analyses in a least-privilege, isolated process when inputs are
untrusted, and treat generated C and reports as untrusted text.

The engine enforces input-byte and extracted-string limits. Operators should also
apply OS/container CPU, memory, wall-clock, file-descriptor, and output-directory
quotas. Do not open reports in privileged tooling or compile generated C without
review and sandboxing.

To report a suspected vulnerability, privately contact the repository maintainers
through the security contact configured on the hosting service. Include a minimal
reproducer, affected version/commit, platform, and impact; avoid public disclosure
until a fix is available. Never include secrets or personal data in issues, fixtures,
logs, or pull requests.
