# GALileo

Enumerate every domain user from on-prem Exchange using one valid mailbox
credential - no Domain Controller access required.

## Why

On internal engagements the Domain Controllers are increasingly locked down:
identity-protection EDR/ITDR, authentication policies, Protected Users, or logon
restrictions — so the usual LDAP/SAMR user enumeration against a DC gets blocked.
Exchange, however, is a member server: it validates your credential and will hand
back the Global Address List on your behalf, so a standard mailbox account can pull
the entire directory without ever authenticating to a DC.

GALileo automates that pivot: point it at a host or a subnet, give it a credential,
and it returns a clean username/email list ready for password spraying or phishing
simulation.

## Features

- **Subnet discovery** - sweep a CIDR and fingerprint hosts exposing EWS.
- **GAL dump** - complete enumeration via EWS `FindPeople` with paging, automatic
  fallback to `ResolveNames`.
- **NTLM or Basic** auth, auto-detected.
- **Version detection** - reads the Exchange build from the SOAP `ServerVersionInfo`.
- **Proxy-safe** - ignores `http(s)_proxy` env so internal targets aren't tunnelled
  out; skips TLS verification for self-signed Exchange certs.
- Threaded; outputs deduped `emails.txt` and `users.txt` (local-parts ≈ sAMAccountName).

## Install

```bash
pip install requests requests_ntlm
```

(`requests_ntlm` is optional — without it the tool falls back to Basic auth.)

## Usage

```bash
# discover EWS servers across a subnet (no creds)
galileo.py 10.0.0.0/24 --discover-only

# dump the GAL from one server
galileo.py mail.example.com -d example.com -u j.doe -p 'Passw0rd!'

# sweep a subnet and dump every Exchange server found
galileo.py 10.0.0.0/24 -d example.com -u j.doe -p 'Passw0rd!' -o loot -t 32
```

Target accepts a host, an IP, a CIDR, or `@hosts.txt`.

## Output

- `<prefix>_emails.txt` - unique primary SMTP addresses
- `<prefix>_users.txt`  - local-parts, typically the `sAMAccountName`

## Notes

- Works against on-prem Exchange.
- The account needs a mailbox; discovery works without credentials.

## Legal

For authorized security testing only. You are responsible for ensuring you have
explicit permission to test any system you point this at.
