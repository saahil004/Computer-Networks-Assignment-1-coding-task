import struct
import socket
import random

class Answer: # just for my own ease to parse answers
    def __init__(self, NAME, TYPE, CLASS, TTL, RDLENGTH, ip1, ip2, ip3, ip4):
        self.__NAME = NAME
        self.__TYPE = TYPE
        self.__CLASS = CLASS
        self.__TTL = TTL
        self.__RDLENGTH = RDLENGTH
        self.__IP = f"{ip1}.{ip2}.{ip3}.{ip4}" # fstring ip
    
    def display(self): # to print answers easily
        print("NAME: ", self.__NAME)    
        print("TYPE: ", self.__TYPE)    
        print("CLASS: ", self.__CLASS)    
        print("TTL: ", self.__TTL)    
        print("RDLENGTH: ", self.__RDLENGTH)  
        print("IP Address: ", self.__IP)  


def buildHeader(id, qd=1, an=0, ns=0, ar=0):
    flags = 0x0100 # recursion desired by default
    data = struct.pack("!HHHHHH", id, flags, qd, an, ns, ar) # byte stream for header
    return data

def parseHeader(data):
    id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12]) # unpacking stuff from header
    return id, flags, qd, an, ns, ar

def QNAME(domain): # logic for finding qname
    arr = domain.split('.') 
    qname = b""
    for x in arr:
        qname += struct.pack("!B", len(x)) + x.encode()
    qname += struct.pack("!B", 0)
    return qname # final byte string

def QTYPE(IPv4=True):
    return struct.pack("!H", 1) if IPv4 == True else struct.pack("!H", 0) # by default ipv4

def QCLASS(IN=True):
    return struct.pack("!H", 1) if IN == True else struct.pack("!H", 0) # by default internet

def buildQuery(id, domain):
    header = buildHeader(id)
    questionBody = QNAME(domain) + QTYPE() + QCLASS()
    
    return header + questionBody # making header + body for query


def handleQuery(req, dns, port):
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # this is udp socket
    s.settimeout(5) # 5 seconds timeout
    s.sendto(req, (dns, port))
    res, addr = s.recvfrom(512) # response bytes and address 
    return (res, addr)
  except socket.timeout as e:
      print(str(e))
      return (None, None)  
  finally:
      s.close()

def sliceAnswer(res, domain):
    header = res[:12]
    ansstart = 16 + len(QNAME(domain)) # answer starts after header (12 bytes) + body in bytes + 4 (2 for QTYPE and QCLASS)
    ques = res[12 : ansstart]
    ans = res[ansstart:]
    return header, ques, ans # separated header, questions, answers

def parseAnswers(ans):
    answers = []
    st, end = 0, 16 # each answer is 16 bytes
    while end <= len(ans):
        NAME, TYPE, CLASS, TTL, RDLENGTH, ip1, ip2, ip3, ip4 = struct.unpack("!HHHIHBBBB", ans[st:end]) # (NAME=H, TYPE=H, CLASS=H, TTL=I, RDLENGTH=H, and the four B's are the IP octets)
        answers.append(Answer(NAME, TYPE, CLASS, TTL, RDLENGTH, ip1, ip2, ip3, ip4))
        st += 16
        end += 16
    return answers  # all answers as Answer objects 

def getID(header):
    id, flags, qd, an, ns, ar = parseHeader(header)
    return id # just to show id of the query

def getRCODE(header):
    id, flags, qd, an, ns, ar = parseHeader(header)
    rcode = flags & 0x000F # getting only the rcode part (last 4 bits of the flag)
    return rcode # to find out if query was successful

def typeRCODE(rcode):
    if rcode == 0:
        return "NOERROR" # success
    if rcode == 1:
        return "FORMERR" # format error
    if rcode == 2:
        return "SERVFAIL" # server error
    if rcode == 3:
        return "NXDOMAIN" # domain does not exist
    if rcode == 4:
        return "NOTIMP" # not implemented
    if rcode == 5:
        return "REFUSED" # server refused to answer
    
    return "Not applicable for basic A records"

while True:
    print("Enter nothing to end.")
    domain = input("Enter domain to be looked up: ")
    dns = input("Enter DNS IP: ")
    
    if domain == "" or dns == "":
        break
    req = buildQuery(random.randint(0, 65535), domain)
    res, addr = handleQuery(req, dns, 53)
    if res and addr:
        header, question, answer = sliceAnswer(res, domain)
        id = getID(header)
        rcodeType = typeRCODE(getRCODE(header))
        print("Transaction ID: ", id)
        print("Record Type: A")
        print("RCODE Name: ", rcodeType)
        print("Domain: ", domain)
        if rcodeType == "NOERROR":
            answers = parseAnswers(answer)
            for record in answers:
                record.display()
    else:
        print("DNS Query failed.")