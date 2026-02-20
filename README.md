# Features

- Tests 70+ DNS servers across IPv4 and IPv6 (Google, Cloudflare, Quad9, Mullvad, AdGuard, and more).
- Eliminates statistical noise from individual measurements before computing averages.
- flags servers with statistically unusual behaviour across the full result set (threshold: 2.5σ).
- Easures response consistency, not just speed.
- Combines success rate and speed into a single 0–100 score.
- Weighted composite score (DNS × 70% + Ping × 30%) for holistic server ranking.
- Separates Standard / Privacy / Family / Ad-Blocking / Security / Regional servers.


![frontende01](https://github.com/user-attachments/assets/b6675c23-1fd5-47e1-adf8-5a91324847df)
![frontende02](https://github.com/user-attachments/assets/27cade76-72a4-4cd7-92b1-11c3d7545b74)


# Installation

- Clone or download dnscout.py:
  
        pip install -r requirements.txt

- Or install dependencies directly:

        pip install dnspython rich

# Usage

          python dnscout.py

- DNScout runs interactively, it will ask whether to include IPv6 servers and whether to run the DNS-Ping correlation phase.

# Security

- IP addresses are validated via Python's ipaddress module before any network call
- Domains are validated against a strict regex (RFC-compliant)
- Subprocess ping uses list arguments (never shell=True) to prevent command injection
- No credentials, tokens, or sensitive data are stored or logged
- User-facing inputs are escaped before display
