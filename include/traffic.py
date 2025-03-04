import csv
import asyncio
import pyshark
import logging
import subprocess

from include.utils import write_packets_to_csv

include_logger = logging.getLogger('include')

def run_executable(executable_path):
    """
    Run an executable file.

    Args:
        executable_path (str): The full path to the executable file.
    """
    try:
        include_logger.debug(f"Running executable: {executable_path}")
        subprocess.run(executable_path, check=True)
        return True
    except Exception as e:
        include_logger.error(f"Error running {executable_path}", exc_info=False)
        return False

def capture_traffic(interface, output_file, stop_event, timeout=10):
    """
    Capture network traffic on a specified interface and save it to a file.

    Args:
        interface (str): The network interface to capture traffic on (e.g., 'Ethernet').
        output_file (str): The file path to save the captured traffic (e.g., 'capture.pcap').
        stop_event (threading.Event): An event to signal when the capture should stop.
        timeout (itn): Amount of time that the executable will be running for
    """
    def _capture():
        include_logger.debug(f"Starting network capture on interface {interface}...")
        capture = pyshark.LiveCapture(interface=interface, output_file=output_file)
        capture.sniff(timeout)
        include_logger.debug(f"Stopped capture on interface {interface}")
        stop_event.set()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(_capture())
    loop.close()

def analyze_traffic(pcap_file, executable_name):
    """
    Analyze captured network traffic, extract DNS, HTTP, and SSL/TLS packets, and write them to a CSV file.

    Args:
        pcap_file (str): The file path to the captured traffic (e.g., 'capture.pcap').
        executable_name (str): The name of the executable file that generated the traffic.
    """
    include_logger.debug(f"Analyzing traffic from {pcap_file}...")
    capture = pyshark.FileCapture(pcap_file)

    dns_packets = []
    http_packets = []
    ssl_packets = []

    for packet in capture:
        if 'DNS' in packet:
            include_logger.debug(f"DNS packet found in packet {pcap_file}")
            dns_packets.append(packet)
        if 'HTTP' in packet:
            include_logger.debug(f"HTTP packet found in packet {pcap_file}")
            http_packets.append(packet)
        if 'SSL' in packet or 'TLS' in packet:
            include_logger.debug(f"SSL packet found in packet {pcap_file}")
            ssl_packets.append(packet)

    include_logger.info(f"DNS packets: {len(dns_packets)}")
    include_logger.info(f"HTTP packets: {len(http_packets)}")
    include_logger.info(f"SSL/TLS packets: {len(ssl_packets)}")

    with open('traffic_report.csv', 'a', newline='') as csvfile:
        include_logger.debug("Writing report into a CSV")
        csv_writer = csv.writer(csvfile)

        # If the file is empty
        if csvfile.tell() == 0:
            csv_writer.writerow(['Filename', 'Protocol', 'Source IP', 'Destination IP', 'Details'])

        write_packets_to_csv(executable_name, dns_packets, 'DNS', csv_writer)
        write_packets_to_csv(executable_name, http_packets, 'HTTP', csv_writer)
        write_packets_to_csv(executable_name, ssl_packets, 'SSL/TLS', csv_writer)

