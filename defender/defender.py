"""
ARP Defender - an interactive terminal tool that detects ARP spoofing / MITM
attacks on the local network.

It auto-detects your gateway and interface, lets you confirm or change them,
then gives you a simple menu:

    1. Scan network        - list the live hosts and record a baseline
    2. Monitor for attacks - watch ARP traffic live and alert on poisoning
    3. Protect gateway     - pin the real gateway MAC as a permanent ARP entry
    4. Exit

No config file - everything is asked for in the terminal.
NOTE: run as Administrator, or the sniffer / scan will see nothing.
"""

from scapy.all import ARP, Ether, sniff, srp, conf, getmacbyip
from collections import defaultdict, deque
import ctypes
import logging
import subprocess
import time


# --- detection settings ---
FLOOD_THRESHOLD = 20     # ARP replies per second from one MAC that counts as a flood
MAX_IPS_PER_MAC = 1      # how many IPs one MAC may claim before it looks like a poisoner
ALERT_COOLDOWN = 10      # seconds to wait before repeating the same alert

# --- live state (built up as we see traffic) ---
ip_to_mac = {}                      # learned baseline: IP -> MAC
mac_to_ips = defaultdict(set)       # MAC -> set of IPs it has claimed
reply_times = defaultdict(deque)    # MAC -> timestamps of its recent ARP replies
recent_alerts = {}                  # (rule, MAC) -> last time we showed that alert


# ---------------------------------------------------------------------------
# Setup / info gathering
# ---------------------------------------------------------------------------

def is_admin() -> bool:
    """Return True if we're running with Administrator rights (Windows)."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except Exception:
        return False


def ask(prompt: str, default: str = None) -> str:
    """
    Ask the user for a value, offering a detected default they can accept.

    Args:
        prompt (str): The question to show.
        default (str): A detected value; pressing Enter accepts it.

    Returns:
        str: What the user typed, or the default if they pressed Enter.
    """
    if default:
        entered = input(f"{prompt} [{default}]: ").strip()
        return entered or default
    return input(f"{prompt}: ").strip()


def detect_network() -> tuple:
    """
    Best-effort auto-detection of the active interface and gateway.

    Returns:
        tuple: (interface, local_ip, gateway_ip, gateway_mac). Any item may be
        None if it couldn't be detected (the user types it in then).
    """
    interface = local_ip = gateway_ip = gateway_mac = None
    try:
        route_iface, local_ip, gateway_ip = conf.route.route("0.0.0.0")
        interface = getattr(route_iface, "name", route_iface)
    except Exception:
        pass

    if gateway_ip and gateway_ip != "0.0.0.0":
        try:
            gateway_mac = getmacbyip(gateway_ip)   # resolves via ARP (needs admin)
        except Exception:
            gateway_mac = None

    return interface, local_ip, gateway_ip, gateway_mac


def get_settings() -> tuple:
    """
    Auto-detect the network, then let the user confirm or correct each value.

    Returns:
        tuple: (gateway_ip, gateway_mac, interface).
    """
    print("[*] Detecting your network...\n")
    detected_iface, local_ip, detected_gateway_ip, detected_gateway_mac = detect_network()
    gateway_ip = ask("Gateway IP", detected_gateway_ip)
    gateway_mac = ask("Real gateway MAC", detected_gateway_mac).lower()
    interface = ask("Interface name", detected_iface)
    return gateway_ip, gateway_mac, interface


# ---------------------------------------------------------------------------
# Scanning (scan -> display -> remember, each on its own)
# ---------------------------------------------------------------------------

def scan_network(ip_range: str, interface: str) -> list:
    """
    Layer 2 ARP broadcast scan. Pure discovery - no printing, no state.
    Just returns the hosts that answer.

    Args:
        ip_range (str): Target network block in CIDR notation (e.g. 192.168.1.0/24).
        interface (str): Interface to send the scan on.

    Returns:
        list[dict[str, str]]: One {'ip', 'mac'} dict per answering host.
    """
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    answered, _ = srp(request, iface=interface or None, timeout=2, verbose=False)
    return [{"ip": received.psrc, "mac": received.hwsrc.lower()} for _, received in answered]


def print_devices(devices: list, gateway_ip: str) -> None:
    """Print the discovered hosts as a table, tagging the gateway."""
    print(f"\n[i] | {'IP Address':<16} | MAC Address")
    print("-" * 45)
    for device in devices:
        label = f'{device["ip"]} [*]' if device["ip"] == gateway_ip else device["ip"]
        print(f'    | {label:<16} | {device["mac"]}')
    print("-" * 45)
    print(f"[+] Found {len(devices)} hosts.\n")


def remember_devices(devices: list) -> None:
    """Record scan results as the detection baseline."""
    for device in devices:
        ip_to_mac[device["ip"]] = device["mac"]
        mac_to_ips[device["mac"]].add(device["ip"])


# ---------------------------------------------------------------------------
# Detection (logic -> cooldown -> output, each on its own)
# ---------------------------------------------------------------------------

def check_arp(op: int, src_ip: str, src_mac: str, gateway_ip: str, gateway_mac: str) -> list:
    """
    Run every detection rule against one ARP packet, and update the baseline.

    Args:
        op (int): ARP opcode (1 = request, 2 = reply).
        src_ip (str): Sender IP being claimed.
        src_mac (str): Sender MAC making the claim (lowercased).
        gateway_ip (str): The real gateway IP (trust anchor).
        gateway_mac (str): The real gateway MAC (trust anchor).

    Returns:
        list: Zero or more (severity, rule, message) tuples.
    """
    alerts = []

    # Rule 1: someone claims the gateway IP with the wrong MAC (the big one).
    if src_ip == gateway_ip and gateway_mac and src_mac != gateway_mac:
        alerts.append(("high", "GATEWAY_MAC_CHANGED",
                       f"{src_ip} is claimed by {src_mac}, real gateway is {gateway_mac}"))

    # Rule 2: a known IP suddenly answers from a new MAC.
    elif src_ip in ip_to_mac and ip_to_mac[src_ip] != src_mac:
        alerts.append(("medium", "MAC_CHANGED_FOR_IP",
                       f"{src_ip} moved from {ip_to_mac[src_ip]} to {src_mac}"))

    ip_to_mac[src_ip] = src_mac   # learn / update the baseline

    # Rule 3: one MAC claiming lots of IPs (classic poisoner).
    mac_to_ips[src_mac].add(src_ip)
    if len(mac_to_ips[src_mac]) > MAX_IPS_PER_MAC:
        alerts.append(("high", "ONE_MAC_MANY_IPS",
                       f"{src_mac} is claiming {len(mac_to_ips[src_mac])} different IPs"))

    # Rule 4: a flood of unsolicited replies (secondary signal).
    if op == 2:
        times = reply_times[src_mac]
        times.append(time.time())
        while times and time.time() - times[0] > 1.0:   # keep only the last second
            times.popleft()
        if len(times) > FLOOD_THRESHOLD:
            alerts.append(("medium", "ARP_FLOOD",
                           f"{src_mac} sent {len(times)} ARP replies in one second"))

    return alerts


def is_new_alert(rule: str, src_mac: str) -> bool:
    """Return True unless this (rule, MAC) alert was shown within the cooldown."""
    key = (rule, src_mac)
    if time.time() - recent_alerts.get(key, 0) < ALERT_COOLDOWN:
        return False
    recent_alerts[key] = time.time()
    return True


def report_alert(severity: str, rule: str, message: str) -> None:
    """Print and log one alert line."""
    prefix = {"high": "[!]", "medium": "[*]", "low": "[i]"}.get(severity, "[i]")
    line = f'{prefix} {time.strftime("%H:%M:%S")} {severity.upper()} {rule} - {message}'
    print(line)
    logging.info(line)


def handle_packet(packet, gateway_ip: str, gateway_mac: str) -> None:
    """
    Called by Scapy for each captured ARP packet. Extracts the fields, runs the
    rules, and reports any alert (skipping ones still in cooldown).

    Args:
        packet: The Scapy packet.
        gateway_ip (str): The real gateway IP.
        gateway_mac (str): The real gateway MAC.
    """
    if ARP not in packet:
        return
    arp = packet[ARP]
    src_ip = arp.psrc
    if src_ip == "0.0.0.0":          # ARP probe (e.g. during DHCP) - not an attack
        return

    op = int(arp.op)
    src_mac = arp.hwsrc.lower()

    for severity, rule, message in check_arp(op, src_ip, src_mac, gateway_ip, gateway_mac):
        if is_new_alert(rule, src_mac):
            report_alert(severity, rule, message)


def monitor(gateway_ip: str, gateway_mac: str, interface: str) -> None:
    """
    Watch ARP traffic live and report alerts until the user presses Ctrl+C.

    Args:
        gateway_ip (str): The real gateway IP.
        gateway_mac (str): The real gateway MAC.
        interface (str): Interface to sniff on.
    """
    print("\n[*] Monitoring for ARP spoofing... press Ctrl+C to stop.\n")
    try:
        sniff(filter="arp", iface=interface or None, store=False,
              prn=lambda pkt: handle_packet(pkt, gateway_ip, gateway_mac))
    except KeyboardInterrupt:
        print("\n[*] Stopped monitoring.\n")


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------

def windows_interface_name(iface: str) -> str:
    """
    Translate a Scapy interface (often a '\\Device\\NPF_{...}' capture name) into
    the Windows connection name that netsh expects, e.g. 'Ethernet'.

    Args:
        iface (str): The interface as Scapy knows it.

    Returns:
        str: The matching Windows connection name, or the input unchanged.
    """
    for dev in conf.ifaces.values():
        if iface in (getattr(dev, "name", None), getattr(dev, "network_name", None)):
            return dev.name
    return iface


def pin_gateway(gateway_ip: str, gateway_mac: str, interface: str) -> None:
    """
    Pin the real gateway MAC as a PERMANENT ARP entry. A permanent entry is not
    overwritten by spoofed replies, so the OS ignores the attacker's flood.

    Args:
        gateway_ip (str): The real gateway IP.
        gateway_mac (str): The real gateway MAC.
        interface (str): Interface the entry is added on (Scapy or Windows name).
    """
    if not gateway_mac:
        print("[-] No gateway MAC set, can't pin.")
        return

    netsh_iface = windows_interface_name(interface)   # netsh needs the Windows name
    mac_dashed = gateway_mac.replace(":", "-")        # netsh wants aa-bb-cc form

    # Clear any existing entry first so pinning can be re-run safely.
    subprocess.run(["netsh", "interface", "ipv4", "delete", "neighbors",
                    netsh_iface, gateway_ip], capture_output=True, text=True)
    try:
        result = subprocess.run(
            ["netsh", "interface", "ipv4", "add", "neighbors",
             netsh_iface, gateway_ip, mac_dashed],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print(f"[+] Pinned {gateway_ip} -> {gateway_mac} (permanent) on {netsh_iface}.")
            logging.info(f"pinned gateway {gateway_ip} {gateway_mac} on {netsh_iface}")
        else:
            message = result.stderr.strip() or result.stdout.strip()
            print(f"[-] netsh failed: {message}")
    except Exception as error:
        print(f"[-] pin failed: {error}")


# ---------------------------------------------------------------------------
# CLI (banner + menu + the loop)
# ---------------------------------------------------------------------------

def print_banner() -> None:
    """Print the program title."""
    print("=" * 40)
    print("            ARP DEFENDER")
    print("=" * 40)


def print_menu() -> None:
    """Print the main menu options."""
    print("\n" + "-" * 40)
    print("[1] Scan network (list devices + set baseline)")
    print("[2] Monitor for ARP spoofing (live)")
    print("[3] Protect gateway (pin static ARP entry)")
    print("[4] Exit")


def startup() -> None:
    """Print the banner, warn if not elevated, and start the log file."""
    print_banner()
    if not is_admin():
        print("[-] WARNING: not running as Administrator - scanning and "
              "monitoring will see nothing. Re-run this elevated.\n")
    logging.basicConfig(filename="arp_defender.log", level=logging.INFO,
                        format="%(asctime)s %(message)s")


def do_scan(gateway_ip: str, interface: str) -> None:
    """Scan the local subnet, print the hosts, and save them as the baseline."""
    subnet = gateway_ip.rsplit(".", 1)[0] + ".0/24"
    devices = scan_network(subnet, interface)
    print_devices(devices, gateway_ip)
    remember_devices(devices)


def run_menu(gateway_ip: str, gateway_mac: str, interface: str) -> None:
    """Show the menu and route the user's choice until they exit."""
    while True:
        print_menu()
        choice = input("> ").strip()

        if choice == "1":
            do_scan(gateway_ip, interface)
        elif choice == "2":
            monitor(gateway_ip, gateway_mac, interface)
        elif choice == "3":
            pin_gateway(gateway_ip, gateway_mac, interface)
        elif choice == "4":
            print("[*] Bye.")
            break
        else:
            print("[-] Please choose 1-4.")


if __name__ == "__main__":
    try:
        startup()
        gateway_ip, gateway_mac, interface = get_settings()
        run_menu(gateway_ip, gateway_mac, interface)
    except KeyboardInterrupt:
        print('\n[*] Stopping ARP defender safely...')
