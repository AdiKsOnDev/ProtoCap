import os
import time
import logging
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
    directory = input("Enter the directory containing executable files: ")
    if not os.path.isdir(directory):
        print("Invalid directory.")
        return

    interface = input("Enter the network interface to capture traffic (e.g., 'Ethernet' or 'Wi-Fi'): ")

    stop_event = threading.Event()

    pcap_file = "capture.pcap"
    capture_thread = threading.Thread(target=capture_traffic, args=(interface, pcap_file, stop_event, 10))
    capture_thread.start()

    for executable in executables:
        run_executable(executable)

    stop_event.wait()
    capture_thread.join()

    analyze_traffic(pcap_file)

if __name__ == "__main__":
    main()
