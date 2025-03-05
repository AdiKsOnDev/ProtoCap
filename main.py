import os
import time
import logging
import argparse
import threading

from include.traffic import run_executable, capture_traffic, analyze_traffic
from include.utils import write_packets_to_csv

main_logger = logging.getLogger('main')
include_logger = logging.getLogger('include')
LOG_LEVEL = logging.DEBUG

logging.basicConfig(
    level=logging.DEBUG,
    format='%(name)s - %(levelname)s - %(filename)s - %(funcName)s - %(message)s'
)
main_logger.setLevel(
    LOG_LEVEL
)
include_logger.setLevel(
    LOG_LEVEL
)

def main():
    """
    Main function to run executables, capture network traffic, and analyze protocols.
    """
    parser = argparse.ArgumentParser(description="Network Traffic Collector for Executables")
    parser.add_argument("target_dir", help="Directory containing executables")
    parser.add_argument("-o", "--output", default="pcaps", help="PCAP output directory")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Execution timeout (seconds)")
    args = parser.parse_args()

    # Create output directory if it doesn't exist
    os.makedirs(args.output, exist_ok=True)

    # Iterate through executables in the target directory
    for exe in os.listdir(args.target_dir):
        exe_path = os.path.join(args.target_dir, exe)
        print(f"Analyzing {exe}...")
        pcap_path = capture_traffic(exe_path, args.output, args.timeout)

        if pcap_path is not None:
            analyze_traffic(pcap_path, os.path.basename(exe))


if __name__ == "__main__":
    main()
