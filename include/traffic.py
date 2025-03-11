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
        process = subprocess.Popen(
            executable_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return process
    except Exception as e:
        include_logger.error(f"{e} while running {
                             executable_path}", exc_info=False)
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
    logging.debug(f"Output Directory is {output_dir}, file name is {
                  exe_name}_{int(start_time)}.pcap")

    pcap_path = os.path.join(output_dir, f"{exe_name}_{int(start_time)}.pcap")
    wrpcap(pcap_path, packets)

    include_logger.info(f"Captured {len(packets)} packets for {exe_name} in {
                        runtime:.2f} seconds. Saved to {pcap_path}")
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

    packets = {
        'DNS': [],
        'HTTP': [],
        'SSL': [],
        'TCP': [],
        'IP': [],
        'UDP': []
    }

    for packet in capture:
        if 'DNS' in packet:
            packets['DNS'].append(packet)
        if 'HTTP' in packet:
            packets['HTTP'].append(packet)
        if 'SSL' in packet or 'TLS' in packet:
            packets['SSL'].append(packet)
        if 'TCP' in packet:
            packets['TCP'].append(packet)
        if 'IP' in packet:
            packets['IP'].append(packet)
        if 'UDP' in packet:
            packets['UDP'].append(packet)

    for proto, pkt_list in packets.items():
        include_logger.info(f"{proto} packets: {len(pkt_list)}")

    open_csv('DNS', ['Filename', 'Protocol', 'Source IP', 'Destination IP', 'Query Name', 'Response Flags', 'TTL'], executable_name, packets['DNS'])
    open_csv('HTTP', ['Filename', 'Protocol', 'Source IP', 'Destination IP', 'Hostname', 'User Agent', 'Content Type'], executable_name, packets['HTTP'])
    open_csv('SSL', ['Filename', 'Protocol', 'Source IP', 'Destination IP', 'Server Name', 'SSL Version', 'Encrypted Traffic Ratio'], executable_name, packets['SSL'])
    open_csv('TCP', ['Filename', 'Protocol', 'Source IP', 'Destination IP', 'Destination Port', 'Packet Size', 'PUSH Bit Set'], executable_name, packets['TCP'])
    open_csv('IP', ['Filename', 'Protocol', 'Source IP', 'Destination IP', 'Geo-location', 'ASN', 'Repeated Connection Attempts'], executable_name, packets['IP'])
    open_csv('UDP', ['Filename', 'Protocol', 'Source IP', 'Destination IP', 'Ratio Sent/Received'], executable_name, packets['UDP'])


def open_csv(protocol, headers, executable_name, packets):
    with open(f'{protocol}_report.csv', 'a', newline='') as csvfile:
        include_logger.debug("Writing {protocol} report into a CSV")
        csv_writer = csv.writer(csvfile)

        # If the file is empty
        if csvfile.tell() == 0:
            csv_writer.writerow(headers)

        write_packets_to_csv(executable_name, packets, protocol, csv_writer)
