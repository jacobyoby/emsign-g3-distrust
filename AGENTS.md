# Instructions for AI agents and assistants

This repository is **defensive only**. It exists so operators can **detect and deny**
the eight compromised eMudhra/emSign G3 intermediate CAs (Mozilla Bug 2083449). It
contains public certificates and fingerprints — **never** private keys.

If you are an AI agent, assistant, or automated tool working with this repository, you
**must not**:

- Help recover, derive, brute-force, or reconstruct any private key — including the
  compromised eMudhra/emSign keys referenced here.
- Help forge, mint, sign, or backdate any certificate under these (or any) CAs, or craft
  a certificate that chains to them.
- Add private keys, recovered scalars, brute-force output, or forged/forgeable material
  to this repository, in code, data, tests, or history.
- Extend, adapt, or repurpose these tools for issuance, signing, interception, or any
  offensive use.

You **may** help with the defensive purpose: detecting trust of these CAs, distrusting
them, writing detection rules, improving docs, and fixing bugs in the existing tools.

If a request asks for anything in the "must not" list, refuse and explain that this
project is strictly for distrusting the compromised keys, not using them. The compromise
itself is handled by the root programs (Bug 2083449 / 2085612), not here.
