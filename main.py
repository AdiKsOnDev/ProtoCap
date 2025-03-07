import os
import logging
import argparse
from tqdm import tqdm

from include.traffic import capture_traffic, analyze_traffic

main_logger = logging.getLogger('main')
include_logger = logging.getLogger('include')
LOG_LEVEL = logging.INFO

logging.basicConfig(
    level=logging.DEBUG,
    format="%(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
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
    parser.add_argument("--skip-capture", action="store_true", help="Skip network capture and analyze existing PCAP files")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    if args.skip_capture:
        print(f"Skipping capture. Analyzing existing PCAP files in {args.output}...")
        for pcap_file in tqdm(os.listdir(args.output)):
            if pcap_file.endswith(".pcap"):
                pcap_path = os.path.join(args.output, pcap_file)
                executable_name = os.path.splitext(pcap_file)[0].rsplit("_", 1)[0]
                print(f"Analyzing {pcap_file}...")
                analyze_traffic(pcap_path, executable_name)
    else:
        for exe in tqdm(os.listdir(args.target_dir)):
            exe_path = os.path.join(args.target_dir, exe)
            print(f"Analyzing {exe}...")
            pcap_path = capture_traffic(exe_path, args.output, args.timeout)

            if pcap_path is not None:
                analyze_traffic(pcap_path, os.path.basename(exe))


if __name__ == "__main__":
    main()
