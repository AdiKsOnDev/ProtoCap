import os
import csv
import time
import logging
import pyshark
import subprocess
from scapy.all import AsyncSniffer, wrpcap

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
        process = subprocess.Popen(executable_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return process
    except Exception as e:
        include_logger.error(f"{e} while running {executable_path}", exc_info=False)
        return None


def capture_traffic(executable_path, output_dir="./data/", timeout=10):
    """
    Capture network traffic save it to a file in a specified directory.

    Args:
        executable_path (str): Path to the executable that has to be ran
        output_dir (str): The directory path to save the captured traffic
        timeout (itn): Amount of time that the executable will be running for

    Return:
        (str): Path to the pcap file in case of success, None otherwise
    """
    sniffer = AsyncSniffer()
    sniffer.start()
    start_time = time.time()
    logging.debug(f"Started sniffing at {int(start_time)}")

    process = run_executable(executable_path)

    if process == None:
        return None

    try:
        process.wait(timeout)
    except subprocess.TimeoutExpired:
        process.kill()

    packets = sniffer.stop()
    runtime = time.time() - start_time
    logging.debug(f"Finished sniffing. Runtime is {int(runtime)}")

    exe_name = os.path.basename(executable_path)
    logging.debug(f"Output Directory is {output_dir}, file name is {exe_name}_{int(start_time)}.pcap")

    pcap_path = os.path.join(output_dir, f"{exe_name}_{int(start_time)}.pcap")
    wrpcap(pcap_path, packets)

    include_logger.info(f"Captured {len(packets)} packets for {exe_name} in {runtime:.2f} seconds. Saved to {pcap_path}")
    return pcap_path

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

    with open('DNS_report.csv', 'a', newline='') as csvfile:
        include_logger.debug("Writing report into a CSV")
        csv_writer = csv.writer(csvfile)

        # If the file is empty
        if csvfile.tell() == 0:
            csv_writer.writerow(['Filename', 'Protocol', 'Source IP', 'Destination IP', 'Query Name', 'Response Flags', 'Time-to-Live'])

        write_packets_to_csv(executable_name, dns_packets, 'DNS', csv_writer)

    with open('HTTP_report.csv', 'a', newline='') as csvfile:
        include_logger.debug("Writing report into a CSV")
        csv_writer = csv.writer(csvfile)

        # If the file is empty
        if csvfile.tell() == 0:
            csv_writer.writerow(['Filename', 'Protocol', 'Source IP', 'Destination IP', 'Hostname', 'Referrer', 'Cookie', 'User Agent', 'Content Type'])

        write_packets_to_csv(executable_name, http_packets, 'HTTP', csv_writer)

    with open('SSL/TLS_report.csv', 'a', newline='') as csvfile:
        include_logger.debug("Writing report into a CSV")
        csv_writer = csv.writer(csvfile)

        # If the file is empty
        if csvfile.tell() == 0:
            csv_writer.writerow(['Filename', 'Protocol', 'Source IP', 'Destination IP', 'Server Name', 'SSL Version', 'Certificate Expiry'])

        write_packets_to_csv(executable_name, ssl_packets, 'SSL/TLS', csv_writer)
