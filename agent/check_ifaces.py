import time
from scapy.all import conf, get_working_ifaces, AsyncSniffer

def test_interfaces():
    print("=== NetInsight-X Scapy Interface Diagnostic ===")
    print(f"Default Scapy Interface (conf.iface): {conf.iface}")

    try:
        route_iface = conf.route.route("8.8.8.8")[0]
        print(f"Default Route Interface (8.8.8.8): {route_iface}")
    except Exception as e:
        print(f"Error checking default route: {e}")

    print("\n--- Available Working Interfaces ---")
    ifaces = get_working_ifaces()
    for idx, iface in enumerate(ifaces):
        print(f"[{idx}] Name: {iface.name} | Description: {iface.description} | IP: {iface.ip}")

    print("\nTesting 3-second packet capture on default route interface...")
    pkt_count = [0]

    def cb(pkt):
        pkt_count[0] += 1

    try:
        target_iface = conf.route.route("8.8.8.8")[0]
        sniffer = AsyncSniffer(iface=target_iface, prn=cb, store=0)
        sniffer.start()
        time.sleep(3)
        sniffer.stop()
        print(f"Captured {pkt_count[0]} packets in 3 seconds on {target_iface}")
    except Exception as ex:
        print(f"Error during packet capture test: {ex}")

if __name__ == "__main__":
    test_interfaces()
