# Practice: Kerberoasting -> detection (SOCF-033)

Personal CTF-to-detection practice exercise, not a real Investigation. The
telemetry here is hand-crafted synthetic data, not evidence from a real host.

## Technique

Kerberoasting from a recent CTF: from an already-compromised low-privileged
domain account, sweep the domain's SPN (service principal name) accounts and
request a Kerberos TGS (service) ticket for each one, downgrading to
RC4-HMAC encryption so the ticket can be cracked offline (the tool wasn't
specifically recalled, but the behavior - requesting tickets for most/all
discoverable SPN accounts in one pass - matches the common
`Impacket GetUserSPNs.py -request` / `Rubeus kerberoast` pattern).
ATT&CK: [T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/).

## Expected telemetry

Each TGS request appears as **Windows Security Event ID 4769** ("A Kerberos
service ticket was requested") on the domain controller, with:

- `TargetUserName` = the requesting account (the compromised principal)
- `ServiceName` = the SPN account being ticketed
- `TicketEncryptionType` = `0x17` for RC4-HMAC (the downgrade signature -
  modern AES-ticketed accounts show `0x12`/`0x11` instead)
- Many distinct `ServiceName` values from the same requesting account in a
  short window is what separates a sweep from ordinary, incidental
  RC4 usage by one legacy service account.

See `kerberoasting_events.jsonl` for the modeled event stream: account
`jdoe` requests RC4 tickets for four distinct SPNs (`svc-sql`, `svc-web`,
`svc-backup`, `svc-exchange`) within ~6 seconds, followed by one unrelated,
benign AES-ticketed request from a machine account, included as a control.

## Coverage check

Before this exercise, `soc_forge/rules/` had no rule matching event ID 4769
- Kerberoasting was a confirmed coverage gap, not just an assumption.

## New rule

`soc_forge/rules/SOCF-033.yml` - flags an account that requests RC4-HMAC TGS
tickets for 3+ distinct SPN accounts within a 2-minute window. The
3-distinct/2-minute threshold is deliberately conservative (real sweeps
request far more); it trades missing a very slow, low-and-slow roast for
not flagging one-off legacy RC4 usage by a single service account.

## Result

Running the modeled telemetry through the real pipeline:

```bash
soc-forge --input samples/kerberoasting_practice/kerberoasting_events.jsonl --rules-only
```

`SOCF-033` fires on the sweep and does not fire on the trailing benign AES
event - see `demo_output.txt` for the captured run. A throwaway run with
only 2 of the 4 sweep events (below the distinct-SPN threshold) confirmed
the rule correctly stays silent below threshold.
