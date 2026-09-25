import socket
import struct
import random

DNS_PORT = 53
TIMEOUT = 5

def encode_domain_name(domain):
    """Convert a domain name into DNS label format."""

    domain = domain.strip().rstrip(".")

    if not domain:
        raise ValueError("Domain name cannot be empty.")

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Invalid domain name.")

    labels = domain.split(".")
    encoded = b""

    for label in labels:
        label_bytes = label.encode("ascii")

        if len(label_bytes) > 63:
            raise ValueError("A domain label cannot exceed 63 characters.")

        encoded += struct.pack("!B", len(label_bytes))
        encoded += label_bytes

    encoded += b"\x00"

    if len(encoded) > 255:
        raise ValueError("Domain name is too long.")

    return encoded


def read_domain_name(data, offset):
    """
    Read a DNS domain name.
    Handles normal labels and RFC 1035 compression pointers.
    """

    labels = []
    original_offset = offset
    jumped = False
    visited = set()

    while True:
        if offset >= len(data):
            raise ValueError("Malformed DNS response: domain name exceeds message.")

        length = data[offset]

        if (length & 0xC0) == 0xC0:

            if offset + 1 >= len(data):
                raise ValueError("Malformed DNS response: incomplete compression pointer.")

            pointer = ((length & 0x3F) << 8) | data[offset + 1]

            if pointer >= len(data):
                raise ValueError("Malformed DNS response: invalid compression pointer.")

            if pointer in visited:
                raise ValueError("Malformed DNS response: compression loop.")

            visited.add(pointer)

            if not jumped:
                original_offset = offset + 2

            offset = pointer
            jumped = True
            continue

        #reserved label format
        if (length & 0xC0) != 0:
            raise ValueError("Malformed DNS response: invalid label.")

        
        if length == 0:
            if not jumped:
                original_offset = offset + 1
            break

        offset += 1

        if offset + length > len(data):
            raise ValueError("Malformed DNS response: label exceeds message.")

        label = data[offset:offset + length].decode("ascii", errors="replace")
        labels.append(label)

        offset += length

    return ".".join(labels), original_offset


def get_rcode_message(rcode):
    messages = {
        0: "No error",
        1: "Format error",
        2: "Server failure",
        3: "NXDOMAIN - Domain does not exist",
        4: "Not implemented",
        5: "Query refused"
    }

    return messages.get(rcode, "Unknown response code")


def get_record_type(record_type):
    types = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        15: "MX",
        16: "TXT",
        28: "AAAA"
    }

    return types.get(record_type, str(record_type))


def parse_dns_response(data, transaction_id, domain):
    """Parse the DNS response and display required information."""

    if len(data) < 12:
        raise ValueError("Malformed DNS response: header is incomplete.")

    (
        response_id,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount
    ) = struct.unpack("!HHHHHH", data[:12])

    print("Transaction ID :", hex(response_id))

    #Verification
    if response_id != transaction_id:
        raise ValueError("Transaction ID mismatch.")

    #extract DNS flags
    qr = (flags >> 15) & 1
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    rcode = flags & 0x0F

    print("Response :", "Response" if qr else "Query")
    print("Authoritative  :", "Yes" if aa else "No")
    print("Truncated :", "Yes" if tc else "No")
    print("Recursion :", "Available" if ra else "Not available")
    print("Response Status:", get_rcode_message(rcode))

    print("\nQDCOUNT:", qdcount)
    print("ANCOUNT:", ancount)
    print("NSCOUNT:", nscount)
    print("ARCOUNT:", arcount)

    if rcode != 0:
        print("\nQuery was not successful.")
        return

    if tc:
        print("\nWarning: DNS response is truncated.")

    offset = 12

    if qdcount == 0:
        raise ValueError("Malformed response: no question section.")

    for i in range(qdcount):

        question_name, offset = read_domain_name(data, offset)

        if offset + 4 > len(data):
            raise ValueError("Malformed response: incomplete question section.")

        qtype, qclass = struct.unpack(
            "!HH",
            data[offset:offset + 4]
        )

        offset += 4

        print("Query Name:", question_name)
        print("Query Type:", get_record_type(qtype))
        print("Query Class :", "IN" if qclass == 1 else str(qclass))

    if ancount == 0:
        print("No answer records found.")
        return

    found_a_record = False

    for i in range(ancount):

        record_name, offset = read_domain_name(data, offset)

        if offset + 10 > len(data):
            raise ValueError("Malformed response: incomplete resource record.")

        record_type, record_class, ttl, rdlength = struct.unpack(
            "!HHIH",
            data[offset:offset + 10]
        )

        offset += 10

        if offset + rdlength > len(data):
            raise ValueError("Malformed response: RDATA exceeds message.")

        rdata = data[offset:offset + rdlength]

        offset += rdlength

        type_name = get_record_type(record_type)
        class_name = "IN" if record_class == 1 else str(record_class)

        print("\nRecord", i + 1)
        print("Name :", record_name)
        print("Type :", type_name)
        print("Class :", class_name)
        print("TTL :", ttl, "seconds")

        # A record contains a 4-byte IPv4 address.
        if record_type == 1:

            if rdlength != 4:
                raise ValueError("Malformed A record: RDATA must be 4 bytes.")

            ip_address = socket.inet_ntoa(rdata)

            print("IPv4 Address  :", ip_address)
            found_a_record = True

        elif record_type == 5:

            cname, unused = read_domain_name(data, offset - rdlength)

            print("CNAME:", cname)

        elif record_type == 2:

            ns_name, unused = read_domain_name(data, offset - rdlength)

            print("Name Server:", ns_name)

        else:
            print("RDATA:", rdata.hex())

    if not found_a_record:
        print("\nNo IPv4 A record was found.")

def perform_dns_lookup(domain, dns_server):
    """Create, send and receive one DNS query."""

    transaction_id = random.randint(0, 65535)
    flags = 0x0100

    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack(
        "!HHHHHH",
        transaction_id,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount
    )


    qname = encode_domain_name(domain)
    question = qname + struct.pack("!HH", 1, 1)

    dns_query = header + question


    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    try:
        print("Dns lookup:")
        print("Domain:", domain)
        print("DNS Server:", dns_server)
        print("DNS Port:", DNS_PORT)
        print("Query Type: A")
        print("Query Class: IN")
        print("Transaction ID :", hex(transaction_id))

        # Send query to DNS server on UDP port 53.
        sock.sendto(dns_query, (dns_server, DNS_PORT))

        print("\nSending DNS query")

        # Receive raw DNS response.
        response, server_address = sock.recvfrom(4096)

        print("Response received from:", server_address[0])
        print("Response size:", len(response), "bytes")

        parse_dns_response(
            response,
            transaction_id,
            domain
        )

    except socket.timeout:
        print("\nerror : request timed out.")
        print("The DNS server did not respond within", TIMEOUT, "seconds.")

    except socket.gaierror:
        print("\nerror: Invalid DNS server IP address.")

    except ValueError as error:
        print("\nerror!", error)

    except OSError as error:
        print("\nerror: Socket operation failed.")
        print(error)

    finally:
        sock.close()


def main():

    dns_server = input("\nEnter DNS server IP: ").strip()

    if not dns_server:
        print("error:DNS server cannot be empty.")
        return

    while True:

        domain = input(
            "\nEnter domain name or type 'exit' to quit: "
        ).strip()

        if domain.lower() == "exit":
            break

        if not domain:
            print("ERROR: Domain name cannot be empty.")
            continue

        perform_dns_lookup(domain, dns_server)


if __name__ == "__main__":
    main()