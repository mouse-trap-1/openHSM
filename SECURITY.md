# Security Policy

OpenHSM is a prototype. It has had no independent security review and must not hold real funds. Reports are still very welcome: finding problems now is the point of publishing it.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub's private reporting: on the repository page go to **Security → Report a vulnerability**. (Maintainers: private vulnerability reporting has to be switched on under Settings → Code security. If you prefer email, add a dedicated address and a PGP key here.)

Include what you can of: the affected component (RTL, signing-module model, node, CLI, documentation), a description, steps or a test that reproduces it, and the impact you expect. A failing test in the style of `pentest/suites/` is the most useful form a report can take.

## What to expect

| Step | Target |
| --- | --- |
| Acknowledgement | 3 working days |
| First assessment and severity | 10 working days |
| Fix or mitigation plan | 30 days for high severity, 90 days otherwise |
| Public advisory | With the fix, crediting the reporter unless they ask otherwise |

We follow coordinated disclosure and ask for 90 days before publication, shorter if a fix ships sooner or the issue is already being exploited.

## Scope

In scope: everything in this repository, including the FPGA design, the protocol, the cryptographic constructions, the node, the tools, and mistakes in the documentation that would lead a deployer into an insecure configuration.

Known and documented, so not new findings: the residual risks R-1 to R-10 in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), the limitations in [`FPGA/README.md`](FPGA/README.md) section 11, and the fact that `openhsm-hwsim` and `openhsm-signer-sim` are test fixtures that hold secrets in a process and a file.

## Supported versions

Only the latest commit on `main` is supported while the project is pre-1.0.

## Safe harbour

We will not pursue or support legal action against anyone who researches this project in good faith, avoids harm to others, and reports through the channel above.
