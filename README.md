🔐 Shamir Seed Lab

Offline terminal tool for generating BIP-39 seed phrases and backing them up with Shamir Secret Sharing (SLIP-39).

Works fully offline. No network access. No files written.UI available in English and Русский.
⚠️ Disclaimer

This tool deals with keys that can control real money. You are solely responsible for anything you do with it.

    Use an offline (air-gapped) computer for generating or entering real seed phrases.
    Always verify the tool first with the built-in self-test and with a small amount of test funds before trusting it with real funds.
    This software is provided "as is", without warranty of any kind (see LICENSE).

📋 What it does
#	Mode	Description
1	New backup	Generate a fresh 24-word BIP-39 phrase and split it into a T-of-N Shamir backup
2	Split existing	Take your existing BIP-39 phrase (12–24 words) and split it
3	Recovery	Combine T shares back into the seed phrase
4	Self-test	Run a 7-test suite on a random disposable secret
5	Environment check	Audit swap, core dumps, network, redirections

Example: a 3-of-5 backup means any 3 of the 5 shares recover the seed. Lose up to 2 shares — your funds are still safe. An attacker needs 3.
⚙️ How it works

    BIP-39: 256 bits of entropy are converted into a 24-word seed phrase (with a checksum).
    SLIP-39 (the Trezor standard for Shamir Secret Sharing): the raw entropy is encrypted with a key derived from your passphrase (optional), then split into N shares over GF(256). Each share is a 33-word phrase.
    Fingerprint: the first 8 hex characters of SHA-256(entropy) are shown and written on every share sheet. It is not a secret — it lets you detect a wrong passphrase or foreign shares during recovery.

🛡️ Security design

    One secret per screen — screen and scrollback buffer are wiped after each secret (\033[3J).
    Hidden input (getpass) for seed phrases and passphrases, entered twice for confirmation.
    Optional passphrase as a second factor (SLIP-39 PBKDF2 with iteration_exponent=2 → 40 000 iterations).
    Automatic verification — right after splitting, the tool restores the secret from the shares and compares it, so you never write down a broken backup.
    Fingerprint verification on recovery — a wrong passphrase can, with probability ~2⁻¹⁶, produce a checksum-valid but wrong seed phrase. The fingerprint check catches this.
    Memory hygiene — entropy is kept in bytearray and zeroed in place; Python's garbage collector is forced after each operation.
    Environment checks — active swap, enabled core dumps, live network interfaces and redirected stdout are detected and reported.
    No dangerous calls — no os.system, no subprocess, no eval, no network, no files, no shell.

📦 Installation

Requires Python 3.8+.

pip install -r requirements.txtpython3 shamir_seed_lab.py

Tails / air-gapped machines

The tool needs the two libraries only at runtime. On Tails you can install them in a session (non-persistent):

python3 -m pip install --user mnemonic shamir-mnemonicpython3 shamir_seed_lab.py

For persistence, keep the project in the Persistent Storage and install the libraries into a virtual environment there.
🖥️ Usage

 $ python3 shamir_seed_lab.py  Language / Язык  1. English  2. Русский  ╔════════════════════════════════════════════════════════╗  ║                 Shamir Seed Lab  v3.3                  ║  ╚════════════════════════════════════════════════════════╝  ──────────────────────────────────────────   1. Create a new seed phrase and backup   2. Split an existing seed phrase   3. Recover a seed from shares   4. Run the automatic test   5. Check environment   6. Exit  ──────────────────────────────────────────

Recommended first step: run option 4 (self-test) after installation and option 5 (environment check) before working with real secrets.
Recovery workflow

    Choose option 3 and enter your shares one at a time (each is a 33-word phrase).
    The tool tries to combine them after every share; when enough shares are present, the secret is recovered.
    Enter the fingerprint from your share sheets — a mismatch means a wrong passphrase or wrong shares, and the (bogus) result is not displayed.

💻 Recommended environment

    Air-gapped or offline machine (Tails works well)
    Swap disabled: sudo swapoff -a
    Terminal not logged or recorded
    Write secrets on paper only; close the terminal window when finished

🔗 Dependencies & trust

Both dependencies are the reference implementations by SatoshiLabs (the Trezor team) and are used in production hardware wallets:
Package	Role
mnemonic	BIP-39 reference implementation
shamir-mnemonic	SLIP-39 reference implementation

Both are pure Python with no transitive dependencies; entropy comes from os.urandom (the OS CSPRNG). Versions are pinned in requirements.txt. Consider verifying package hashes on PyPI before installing on a trusted machine.
⚠️ Limitations & residual risks

    Python memory model: immutable str secrets cannot be zeroed deterministically. The tool minimizes their lifetime and zeroes all bytearray buffers, but a fully hardened implementation would require a compiled language.
    Visible share input: shares are typed with echo so you can check for typos (~33 words). The privacy warning covers this trade-off.
    Fingerprint oracle: the fingerprint allows offline testing of a passphrase guess against stolen shares. This is a deliberate trade-off: it also protects you from silently restoring a wrong seed.
