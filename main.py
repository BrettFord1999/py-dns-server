import socket
# dig @127.0.0.1 -p 2053 +noedns codecrafters.io

class dns_header:
    def __init__(self, id, qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, rcode=0, qdcount=1, ancount=0, nscount=0, arcount=0):
        self.id      = id
        self.qr      = qr
        self.opcode  = opcode
        self.aa      = aa
        self.tc      = tc
        self.rd      = rd
        self.ra      = ra
        self.z       = z
        self.rcode   = rcode
        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount

    def to_packet(self):
        # Construct the flags
        flags = (self.qr << 15) | (self.opcode << 11) | (self.aa << 10) | (self.tc << 9) | \
            (self.rd << 8) | (self.ra << 7) | (self.z << 4) | self.rcode
        
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

class question:
    def __init__(self, domain, record_type=1, dns_class=1):
        self.domain      = domain
        self.record_type = record_type
        self.dns_class   = dns_class
    
    def to_packet(self):
        domain_split = self.domain.split(".") 
        domain_question_name = bytearray()  
        
        for label in domain_split:
            domain_question_name.append(len(label))
            domain_question_name.extend(label.encode('utf-8'))
        
        domain_question_name.append(0)
        print(f"this is domain_question_name BEFORE being added to question_packet: {domain_question_name}")    
        print(f"SELF RECORD TYPE BEFORE ADD {self.record_type}")
        print(f"SELF DNS CLASS BEFORE ADD {self.dns_class}") 

        question_packet = (
            domain_question_name +
            self.record_type.to_bytes(2, byteorder='big')+
            self.dns_class.to_bytes(2, byteorder='big')
        )
        
        return question_packet , domain_question_name

class answer(question): 
    def __init__(self, domain, record_type, dns_class, ttl, rdlength, data):
        self.domain = domain
        self.record_type = record_type
        self.dns_class = dns_class
        self.ttl = ttl
        self.rdlength = rdlength
        self.data = data
    
    def to_packet(self):
        
        answer_packet = (
        self.domain + 
        self.record_type.to_bytes(2, byteorder='big') +
        self.dns_class.to_bytes(2, byteorder='big') +
        self.ttl.to_bytes(4, byteorder='big') +
        self.rdlength.to_bytes(2, byteorder='big') +
        socket.inet_aton(self.data)
        )
        return answer_packet

def header_parser(recvd_bytes):
    print(f"full request = {recvd_bytes}")
    # Parse the Transaction ID (first 2 bytes)
    id = int.from_bytes(recvd_bytes[:2], "big")

    # Parse the Flags (next 2 bytes)
    flags = int.from_bytes(recvd_bytes[2:4], "big")
    
    # Extract individual flags
    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 0x1
    tc = (flags >> 9) & 0x1
    rd = (flags >> 8) & 0x1
    ra = (flags >> 7) & 0x1
    z = (flags >> 4) & 0x7
    rcode = flags & 0xF

    # Parse the counts (each 2 bytes)
    qdcount = int.from_bytes(recvd_bytes[4:6], "big")
    ancount = int.from_bytes(recvd_bytes[6:8], "big")
    nscount = int.from_bytes(recvd_bytes[8:10], "big")
    arcount = int.from_bytes(recvd_bytes[10:12], "big")

    return id , qr , opcode , aa , tc , rd , ra , z , rcode , qdcount , ancount , nscount , arcount

# Examples:
# Header: (12 bytes)
# AA AA 01 00 00 02 00 00 00 00 00 00

# First Question:
# 07 65 78 61 6D 70 6C 65 03 63 6F 6D 00 00 01 00 01

# Second Question:
# 0C 63 6F 64 65 63 72 61 66 74 65 72 73 02 69 6F 00 00 01 00 01

#Full
# AA AA 01 00 00 02 00 00 00 00 00 00 | 07 65 78 61 6D 70 6C 65 03 63 6F 6D 00 00 01 00 01 | 0C 63 6F 64 65 63 72 61 66 74 65 72 73 02 69 6F 00 00 01 00 01

def question_parser(recvd_bytes, qdcount):
    question_bytes = recvd_bytes[12:]
    print(f"Question bytes: {question_bytes}")
    question_values = []


    for q in range(qdcount):
        
        termination_index = question_bytes.index(0x00)

        question = question_bytes[:termination_index]

        domain_name_length = question[0]
        
        domain_name = question[1:1+domain_name_length].decode('utf-8')
        
        top_domain_length = question[1+domain_name_length] 
        
        top_domain = question[2+domain_name_length:2+domain_name_length+top_domain_length].decode('utf-8')

        record_type = int.from_bytes(question_bytes[termination_index+1:termination_index+3], "big")
        dns_class   = int.from_bytes(question_bytes[termination_index+3:termination_index+5], "big")
        full_domain = domain_name + "." + top_domain

        #logging/debugging prints
        #print(type(domain_name), type(top_domain))
        #print(f"domain: {domain_name} (Length: {domain_name_length})")
        #print(f"top domain: {top_domain} (Length: {top_domain_length})")
        #print(f"{recvd_bytes[12:].decode('utf-8')}")
        print("++++++++ QUESTION PARSER FUNCTION +++++++++")
        print(f"question: {question}")
        print(f"domain length = {domain_name_length}")
        print(f"full domain: {full_domain}, record_type = {record_type}, dns_class = {dns_class}")
        print(f"termination index: {termination_index}")

        

        question_values.append({
            'domain'     : domain_name,
            'top_domain' : top_domain,
            'full_domain': full_domain,
            'record_type': record_type,
            'dns_class'  : dns_class
        })

    return question_values



# test_header = dns_header(
#     id=1234,
#     qr=1,
#     opcode=0,
#     aa=0,
#     tc=0,
#     rd=0,
#     ra=0,
#     z=0,
#     rcode=0,
#     qdcount=1,
#     ancount=1,
#     nscount=0,
#     arcount=0
# )

#test_question = question(domain="codecrafters.io", record_type=1, dns_class=1)
#test_answer   = answer(domain=test_question.to_packet()[1], record_type=1, dns_class=1, ttl=60, rdlength=4, data='8.8.8.8')



#create our socket object, loop to await incoming packets with a max size of 512 bytes
def main():

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            #print(source)

            #header creation
            id, qr, opcode, aa, tc, rd, ra, z, rcode, qdcount, ancount, nscount, arcount = header_parser(buf)
            header_response = dns_header(
                id=id,
                qr=1,
                opcode=opcode,
                aa=aa,
                tc=tc,
                rd=rd,
                ra=ra,
                z=z,
                rcode=4,
                qdcount=qdcount,
                ancount=qdcount,
                nscount=nscount,
                arcount=arcount
            )
            #question parsing then pass into our question header initializer
            question_values = question_parser(buf, qdcount)
            question_objects_array = []

            for q in range(qdcount):
                question_objects_array.append(question(domain=question_values[q]['full_domain'], \
                                                       record_type=question_values[q]['record_type'], \
                                                       dns_class=question_values[q]['dns_class']))
            print("+++++++++ Creating question headers +++++++++++ \
                  Question Values being passed into question class within loop to create question object arrays")
            print(question_values[0]['full_domain'])
            print(question_values[0]['record_type'])
            print(question_values[0]['dns_class'])


            question_response = b''
            for q in question_objects_array:
                packet_output = q.to_packet()[0]
                question_response += packet_output
            print(f"question packet built {question_response}")

            #answer creation with object initialization
            answer_objects_array = []
            for q in range(qdcount):
                answer_objects_array.append(answer( domain      =question_objects_array[q].to_packet()[1], \
                                                    record_type =question_values[q]['record_type'], \
                                                    dns_class   =question_values[q]['dns_class']  , \
                                                    ttl=60, \
                                                    rdlength=4, \
                                                    data='8.8.8.8'))

            #answer_response = b''.join([a.to_packet() for a in answer_objects_array])

            print(type(answer_objects_array[0].to_packet()))
            answer_response = b''
            for a in answer_objects_array:
                packet_output = a.to_packet()
                answer_response += packet_output
            print(f"answer packet built {answer_response}")
            
            #answer_response = answer(domain= question_response, record_type=record_type, dns_class=dns_class, ttl=60, rdlength=4, data='8.8.8.8')


            response = header_response.to_packet() + question_response + answer_response
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()