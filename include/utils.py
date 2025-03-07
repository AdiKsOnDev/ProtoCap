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
            details = extract_dns_features(packet)
        elif protocol == 'HTTP':
            details = extract_http_features(packet)
        elif protocol == 'SSL':
            details = extract_ssl_features(packet)
        elif protocol == 'TCP':
            details = extract_tcp_features(packet)
        elif protocol == 'IP':
            details = extract_ip_features(packet)
        elif protocol == 'UDP':
            details = extract_udp_features(packet)
        else:
            return

        row = [filename, protocol]
        row.append(packet.ip.src if hasattr(packet, 'ip') else 'N/A')
        row.append(packet.ip.dst if hasattr(packet, 'ip') else 'N/A')

        for _, value in details.items():
            row.append(value)

        csv_writer.writerow(row)


def extract_http_features(packet):
    """
    Extract HTTP features from a packet.

    Args:
        packet (pyshark.packet.Packet): A network packet containing HTTP layer data.

    Returns:
        dict: A dictionary containing HTTP features such as Hostname, Referrer, Cookie, User Agent, and Content Type.
              If a feature is not available, it defaults to 'N/A'.
    """
    http_layer = packet.http
    return {
        'Hostname': http_layer.host if hasattr(http_layer, 'host') else 'N/A',
        'Referrer': http_layer.referer if hasattr(http_layer, 'referer') else 'N/A',
        'Cookie': http_layer.cookie if hasattr(http_layer, 'cookie') else 'N/A',
        'User Agent': http_layer.user_agent if hasattr(http_layer, 'user_agent') else 'N/A',
        'Content Type': http_layer.content_type if hasattr(http_layer, 'content_type') else 'N/A'
    }

def extract_ssl_features(packet):
    """
    Extract SSL/TLS features from a packet.

    Args:
        packet (pyshark.packet.Packet): A network packet containing SSL/TLS layer data.

    Returns:
        dict: A dictionary containing SSL/TLS features such as Server Name, SSL Version, and Certificate Expiry.
              If a feature is not available, it defaults to 'N/A'.
    """
    ssl_layer = getattr(packet, 'tls', getattr(packet, 'ssl', None))
    if ssl_layer:
        return {
            'Server Name': ssl_layer.get_field_value('server_name') if hasattr(ssl_layer, 'server_name') else 'N/A',
            'SSL Version': ssl_layer.get_field_value('version') if hasattr(ssl_layer, 'version') else 'N/A',
            'Certificate Expiry': ssl_layer.get_field_value('handshake_certificate_expiration') if hasattr(ssl_layer, 'handshake_certificate_expiration') else 'N/A'
        }
    return {
        'Server Name': 'N/A',
        'SSL Version': 'N/A',
        'Certificate Expiry': 'N/A'
    }

def extract_dns_features(packet):
    """
    Extract DNS features from a packet.

    Args:
        packet (pyshark.packet.Packet): A network packet containing DNS layer data.

    Returns:
        dict: A dictionary containing DNS features such as Query Name, Response Flags, and Time-to-Live.
              If a feature is not available, it defaults to 'N/A'.
    """
    dns_layer = packet.dns
    return {
        'Query Name': dns_layer.qry_name if hasattr(dns_layer, 'qry_name') else 'N/A',
        'Response Flags': dns_layer.flags if hasattr(dns_layer, 'flags') else 'N/A',
        'Time-to-Live': dns_layer.time_to_live if hasattr(dns_layer, 'time_to_live') else 'N/A'
    }

def extract_tcp_features(packet):
    """
    Extract TCP features from a packet.

    Args:
        packet (pyshark.packet.Packet): A network packet containing TCP layer data.

    Returns:
        dict: A dictionary containing TCP features such as Destination Port, Packet Size, PUSH Bit Set, and Out-of-Order Packets.
              If a feature is not available, it defaults to 'N/A'.
    """
    tcp_layer = packet.tcp
    return {
        'Destination Port': tcp_layer.dstport if hasattr(tcp_layer, 'dstport') else 'N/A',
        'Packet Size': packet.length,
        'PUSH Bit Set': tcp_layer.flags_push if hasattr(tcp_layer, 'flags_push') else 'N/A',
        'Out-of-Order Packets': 'N/A'  # TODO: Requires tracking sequence numbers
    }

def extract_ip_features(packet):
    """
    Extract IP features from a packet.

    Args:
        packet (pyshark.packet.Packet): A network packet containing IP layer data.

    Returns:
        dict: A dictionary containing IP features such as Destination IP, IP Geo-location, and IP Autonomous System Number.
              If a feature is not available, it defaults to 'N/A'.
    """
    ip_layer = packet.ip
    return {
        'Destination IP': ip_layer.dst if hasattr(ip_layer, 'dst') else 'N/A',
        'IP Geo-location': 'N/A',  # TODO: Requires external API or database
        'IP Autonomous System Number': 'N/A'  # TODO: Requires external API or database
    }

def extract_udp_features(packet):
    """
    Extract UDP features from a packet.

    Args:
        packet (pyshark.packet.Packet): A network packet containing UDP layer data.

    Returns:
        dict: A dictionary containing UDP features such as Ratio Sent/Received and Non-Existent Domain Responses.
              If a feature is not available, it defaults to 'N/A'.
    """
    udp_layer = packet.udp
    return {
        'Ratio Sent/Received': 'N/A',  # TODO: Requires tracking sent/received packets
        'Non-Existent Domain Responses': 'N/A'  # TODO: Requires DNS response analysis
    }
