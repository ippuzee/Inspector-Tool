import socket
import struct
import random

# Server configuration
servers = {
    "www.hackers.com": ["192.0.2.1", "10.0.1.1", "172.16.0.1"],
}

# DNS server function
def handle_query(data):
    # Parse query
    (query_id, flags, qdcount, ancount, nscount, arcount) = struct.unpack("!6H", data[:12])
    query_name = ""
    i = 12
    while data[i] != 0:
        length = data[i]
        query_name += data[i+1:i+length+1].decode() + "."
        i += length + 1
    qtype, qclass = struct.unpack("!2H", data[i+1:i+5])

    # Check if requested record exists
    if query_name in servers:
        # Select a random server from the list
        server_ip = random.choice(servers[query_name])

        # Construct response
        response = struct.pack("!6H", query_id, flags | 0x8000, qdcount, ancount, nscount, arcount)
        response += query_name.encode() + b"\x00"
        response += struct.pack("!2H4H", qtype, qclass, 0, 0, 0, 3600)
        response += struct.pack("!4s", socket.inet_aton(server_ip))
        return response
    else:
        # Handle non-existent records
        return None

# Main function
def main():
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 10053))

    print("CDN DNS server started on port 10053")

    while True:
        data, addr = sock.recvfrom(1024)
        response = handle_query(data)
        if response:
            sock.sendto(response, addr)

if __name__ == "__main__":
    main()
