import logging

include_logger = logging.getLogger('include')

def write_packets_to_csv(filename, packets, protocol, csv_writer):
    """
    Write packet details to a CSV file.

    Args:
        filename (str): The name of the executable file that generated the traffic.
        packets (list): A list of packets (e.g., DNS, HTTP, or SSL/TLS packets).
        protocol (str): The protocol type (e.g., 'DNS', 'HTTP', 'SSL/TLS').
        csv_writer (csv.writer): A CSV writer object to write the data to the file.
    """
    for packet in packets:
        source_ip = packet.ip.src if 'IP' in packet else 'N/A'
        destination_ip = packet.ip.dst if 'IP' in packet else 'N/A'
        details = ''

        if protocol == 'DNS':
            details = packet.dns.qry_name if 'DNS' in packet and hasattr(packet.dns, 'qry_name') else 'N/A'
        elif protocol == 'HTTP':
            details = packet.http.request_uri if 'HTTP' in packet and hasattr(packet.http, 'request_uri') else 'N/A'
        elif protocol == 'SSL/TLS':
            details = packet.ssl.handshake_type if 'SSL' in packet and hasattr(packet.ssl, 'handshake_type') else 'N/A'

        csv_writer.writerow([filename, protocol, source_ip, destination_ip, details])
