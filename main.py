import json
import socket, glob


##Used rfc1035.txt to create this
##please refer to RFC1035 if any question appears
##-----------------------------incomplete----------------------------------##


ip = "127.0.0.1" #my computer's IP
port = 53 #port
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #socket object
sock.bind((ip,port)) #binging socket



##function that loads all the zone when the DNS server starts, so it will load it in the memeory
##uses glob

def load_zones():

    zonefiles = glob.glob('zones/*.zone')
    for zone in zonefiles:
        with open(zone) as zonedata:
            data = json.load(zonedata)
            zonename = data["$origin"]
            jsonzone[zonename] = data

    return jsonzone ##there are some errors here, need to fix 

zonedata = load_zones()

##-----------------------------END----------------------------------------##
##function for getting flags

def getflags(flags):

    byte1 = bytes(flags[:1]) #Getting 1st byte
    byte2 = bytes(flags[1:2]) #Getting byte 2nd

    rflags = ''

    QR = '1'

    OPCODE = '' #this is an empty string, op code is 4 bits long
    for bit in range(1,5):
        OPCODE += str(ord(byte1)&(1<<bit))  #bit shift operation, str for converting to string
    AA = '1' #authorative ans is 1 always

    TC = '0'

    RD = '0' # no recursion

    RA = '0' #same

    Z = '000' #reserved for future use

    RCODE = '0000' #no response code it's 4 bits

    return int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder = 'big')+int(RA+Z+RCODE, 2).to_bytes(1, byteorder = 'big')


##-----------------------------END----------------------------------------##
##function that gets question domain
##needs more work here, it has poor formatting at the moment

def getquestiondomain(data):
    state = 0
    expenctedLength = 0
    domainstring = ''
    domainparts = []
    x = 0
    y = 0 #increment y by 1

    for byte in data:
        if state == 1:
            domainstring += chr(byte)
            x += 1
            if x == expenctedLength:
                domainparts.append(domainstring)
                domainstring = ''
                state = 0
                x = 0
            if byte == 0:
                domainparts.append(domainstring)
                break

        else:
            state = 1
            expenctedLength = byte

        y += 1

    questiontype = data[y:y+2]

    print(questiontype)

    return (domainparts, questiontype)

##-----------------------------END----------------------------------------##
##function getzone takes domain

def getzone(domain):
    global zonedata

    zone_name = '.'.join(domain) + "."
    return zonedata[zone_name]



##-----------------------------END----------------------------------------##

def getrecs(data):
    domain, questiontype = getquestiondomain(data)
    qt = ''

    if questiontype == b'\x00\x01':
        qt ='a'

    zone = getzone(domain)

    return (zone[qt], qt, domainname)

##-----------------------------END----------------------------------------##
##function build response

def buildresponse(data):
    TransactionID = data[0:2] #will get the first 2 bytes from trasnsaction ID
    print(TransactionID)
    #getting flags

    Flags = getflags(data[2:4]) #getting 2nd and 4th byte

    #Question count that is 2bytes

    QDCOUNT = b'\x00\x01' #second byte is 0 always

    getrecs(data)

while True:
    message, client_addr = sock.recvfrom(512)
    print("data")
    r = buildresponse()
    sock.sendto(r, addr)
