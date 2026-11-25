# ARP Defense Suite

A host-based tool that **detects and remediates ARP-poisoning / MITM attacks** on a
local network, written in Python with Scapy.

> For authorized lab testing only. Run the attacker only on networks you own or have explicit permission to test.

- **`defender/defender.py`** — an interactive terminal tool that scans the network,
  monitors ARP traffic live, and can pin the gateway to neutralise an attack.
  **This is the project.**
- **`attacker/mitm_spoofer.py`** — a separate ARP-spoofer, included only as a test
  harness to trigger the defender during a demo. It runs on its own.

## Folder layout

```
ARP-Defense-Suite/
├── defender/
│   └── defender.py     # the whole defender - one interactive terminal file
└── attacker/
    └── mitm_spoofer.py  # test harness (run separately, ideally on another machine)
```

## Setup (Windows)

1. Install **Npcap** (https://npcap.com) in *WinPcap API-compatible mode* — Scapy needs
   it to capture packets.
2. Create a virtual environment (Python 3.10 recommended) and install Scapy:
   ```
   py -3.10 -m venv defender\venv
   defender\venv\Scripts\pip install scapy
   ```

## Running it

Open an **Administrator** terminal (without admin the sniffer captures nothing):

```
defender\venv\Scripts\python defender\defender.py
```

The defender auto-detects your gateway and interface, lets you confirm or change them
(press Enter to accept a detected value), then shows a menu:

```
[1] Scan network (list devices + set baseline)
[2] Monitor for ARP spoofing (live)
[3] Protect gateway (pin static ARP entry)
[4] Exit
```

All activity is also written to `arp_defender.log`.

## Detection rules

| Rule | Fires when |
|---|---|
| `GATEWAY_MAC_CHANGED` | something claims the gateway IP with a MAC that isn't the real one |
| `MAC_CHANGED_FOR_IP`  | a known IP suddenly answers from a different MAC |
| `ONE_MAC_MANY_IPS`    | one MAC claims more IPs than allowed (classic poisoner) |
| `ARP_FLOOD`           | a burst of unsolicited ARP replies (secondary signal) |

## Remediation

**Protect gateway** writes the real gateway MAC as a *permanent* ARP entry. A permanent
entry is immune to the attacker's spoofed replies — the OS simply ignores the flood —
so this is the real ARP-layer fix on the host.

## Demo

1. Start the defender and choose **[2] Monitor**.
2. From a separate (Linux) machine, run `attacker/mitm_spoofer.py` against this host.
3. Watch `GATEWAY_MAC_CHANGED` fire live, then use **[3] Protect gateway** to neutralise it.

## How it works

The defender passively sniffs ARP with Scapy and keeps a baseline of which MAC owns
which IP. The gateway's real MAC is the *trust anchor*: any packet claiming the gateway
IP from a different MAC is the attack. Because standard ARP has no authentication, a
host can't prevent spoofed replies outright — so the tool detects them and pins the
gateway, which stops the poisoning from affecting this host.
