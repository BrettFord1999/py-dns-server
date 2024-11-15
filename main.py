import socket
# dig @127.0.0.1 -p 2053 +noedns codecrafters.io

class dns_header:
    def __init__(self, id, qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, rcode=0, qdcount=1, ancount=0, nscount=0, arcount=0):
        self.id = id
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        self.z = z
        self.rcode = rcode
        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount

    def to_bytes(self):
        # Construct the flags
        flags = (self.qr << 15) | (self.opcode << 11) | (self.aa << 10) | (self.tc << 9) | (self.rd << 8) | (self.ra << 7) | (self.z << 4) | self.rcode
        
        # Create the byte representation of the header
        header_bytes = (
            self.id.to_bytes(2, byteorder='big') +
            flags.to_bytes(2, byteorder='big') +
            self.qdcount.to_bytes(2, byteorder='big') +  
            self.ancount.to_bytes(2, byteorder='big') +  
            self.nscount.to_bytes(2, byteorder='big') +  
            self.arcount.to_bytes(2, byteorder='big')    
        )
        return header_bytes
        
test_header = dns_header(
    id=1234,
    qr=1,
    opcode=0,
    aa=0,
    tc=0,
    rd=0,
    ra=0,
    z=0,
    rcode=0,
    qdcount=1,
    ancount=0,
    nscount=0,
    arcount=0
)


class Question:
    def __init__(self, domain, record_type=1, dns_class=1):
        self.domain = domain
        self.record_type = record_type
        self.dns_class = dns_class
    
    def to_bytes(self):
        domain_split = self.domain.split(".") 
        domain_question_name = bytearray()  
        
    
        for label in domain_split:
            domain_question_name.append(len(label))
            domain_question_name.extend(label.encode('utf-8'))
        
        domain_question_name.append(0)
        
    
        question_packet = (
            domain_question_name +
            self.record_type.to_bytes(2, byteorder='big')+
            self.dns_class.to_bytes(2, byteorder='big')
        )
        
        return question_packet


test_question = Question(domain="codecrafters.io", record_type=1, dns_class=1)


#create our socket object, loop to await incoming packets with a max size of 512 bytes
def main():

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
    
            response = test_header.to_bytes() + test_question.to_bytes()
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()