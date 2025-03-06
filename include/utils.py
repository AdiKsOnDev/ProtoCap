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
        if protocol == 'DNS':
            details = {
                'Query Name': packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else 'N/A',
                'Response Flags': packet.dns.flags if hasattr(packet.dns, 'flags') else 'N/A',
                'Time-to-Live': packet.dns.time_to_live if hasattr(packet.dns, 'time_to_live') else 'N/A'
            }
        elif protocol == 'HTTP':
            details = {
                'Hostname': packet.http.host if hasattr(packet.http, 'host') else 'N/A',
                'Referrer': packet.http.referer if hasattr(packet.http, 'referer') else 'N/A',
                'Cookie': packet.http.cookie if hasattr(packet.http, 'cookie') else 'N/A',
                'User Agent': packet.http.user_agent if hasattr(packet.http, 'user_agent') else 'N/A',
                'Content Type': packet.http.content_type if hasattr(packet.http, 'content_type') else 'N/A'
            }
        elif protocol == 'SSL/TLS':
            ssl_layer = getattr(packet, 'tls', getattr(packet, 'ssl', None))

            if ssl_layer:
                details = {
                    'Server Name': ssl_layer.get_field_value('server_name') if hasattr(ssl_layer, 'server_name') else 'N/A',
                    'SSL Version': ssl_layer.get_field_value('version') if hasattr(ssl_layer, 'version') else 'N/A',
                    'Certificate Expiry': ssl_layer.get_field_value('handshake_certificate_expiration') if hasattr(ssl_layer, 'handshake_certificate_expiration') else 'N/A'
                }
        else:
            return

        csv_writer.writerow([
            filename,
            protocol,
            packet.ip.src if hasattr(packet, 'ip') else 'N/A',
            packet.ip.dst if hasattr(packet, 'ip') else 'N/A',
            details
        ])
