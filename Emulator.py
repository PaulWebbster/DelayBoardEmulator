__author__ = 'paweber'

from Crc import CRCCCITT
from serial import Serial

# Board connection
board = Serial("COM11")
board.baudrate = 115200

#crc calculator
crcCalculator = CRCCCITT()

# Header
preamble = 0x55
version = 0x01

# Modes
mode = {}
mode['read'] = 0x00
mode['write'] = 0x01
mode['conn check'] = 0x02
mode['ack'] = 0x03

# Channels
channel = {}
channel['none'] = 0x00
channel['one'] = 0x01
channel['two'] = 0x02
channel['three'] = 0x03
channel['four'] = 0x04
channel['five'] = 0x05
channel['six'] = 0x06

# commands
action = {}
action['tone'] = 0x01
action['delay'] = 0x02
action['timeout'] = 0x03
action['volume in'] = 0x04
action['mute'] = 0x05
action['map'] = 0x06
action['volume out'] = 0x07
action['mag threshold'] = 0x08
action['write settings'] = 0x09
action['read mag'] = 0x0A

conCheck = [preamble, version, mode['conn check'], channel['none'], 0x00, 0x00, 0x00]
conCheckAnsw = [preamble, version, mode['ack'], channel['none'], 0x00, 0x00, 0x00]
ack = [preamble, version, mode['ack'], channel['none'], 0x00, 0x00, 0x00]

# LINE 1
lines = {}
lines[1] = {}
lines[1]['delay'] = [preamble, version, mode['read'], action['delay'], channel['one'], 0x00, 0x0c]
lines[1]['tone'] = [preamble, version, mode['read'], action['tone'], channel['one'], 0x00, 0x01]
lines[1]['timeout'] = [preamble, version, mode['read'], action['timeout'], channel['one'], 0x00, 0x21]
lines[1]['volume in'] = [preamble, version, mode['read'], action['volume in'], channel['one'], 0x00, 0x40]
lines[1]['mute'] = [preamble, version, mode['read'], action['mute'], channel['one'], 0x00, 0x01]
lines[1]['map'] = [preamble, version, mode['read'], action['map'], channel['one'], 0x00, 0x01]
lines[1]['volume out'] = [preamble, version, mode['read'], action['volume out'], channel['one'], 0x00, 0x02]
lines[1]['mag threshold'] = [preamble, version, mode['read'], action['mag threshold'], channel['one'], 0x00, 0x02]
lines[1]['read mag'] = [preamble, version, mode['read'], action['read mag'], channel['one'], 0x00, 0x02]

def compare_packets(first, second):
    return all(map(lambda v: v in map(ord, first), second))

def packet_print(packet, prefix="", suffix=""):
    print prefix + '-'.join('%2x' % ord(c) for c in packet) + suffix

def read_packet_handler(packet):
    line = lines[int(packet[4].encode('hex'), 16)]

    if ord(packet[3]) == action['tone']:
        response = line['tone'][:]
    elif ord(packet[3]) == action['delay']:
        response = line['delay'][:]
    elif ord(packet[3]) == action['timeout']:
        response = line['timeout'][:]
    elif ord(packet[3]) == action['volume in']:
        response = line['volume in'][:]
    elif ord(packet[3]) == action['mute']:
        response = line['mute'][:]
    elif ord(packet[3]) == action['map']:
        response = line['map'][:]
    elif ord(packet[3]) == action['volume out']:
        response = line['volume out'][:]
    elif ord(packet[3]) == action['mag threshold']:
        response = line['mag threshold'][:]
    elif ord(packet[3]) == action['read mag']:
        response = line['read mag'][:]
    else:
        print "ERROR: Read packet not recognized."
        return

    crcCalculator.calculate(response)
    board.write(response)
    print "Packet send: " + '-'.join('%2x' % c for c in response)

def write_packet_handler(packet):
    ack_response = ack[:]
    crcCalculator.calculate(ack_response)

    if ord(packet[3]) == action['tone']:
        print "Write Tone Detection packet come..."
        slot = lines[ord(packet[4])]['tone']
    elif ord(packet[3]) == action['delay']:
        print "Write Delay packet come..."
        slot = lines[ord(packet[4])]['delay']
    elif ord(packet[3]) == action['timeout']:
        print "Write Timeout packet come..."
        slot = lines[ord(packet[4])]['timeout']
    elif ord(packet[3]) == action['volume in']:
        print "Write Volume In packet come..."
        slot = lines[ord(packet[4])]['volume in']
    elif ord(packet[3]) == action['mute']:
        print "Write Mute packet come..."
        slot = lines[ord(packet[4])]['mute']
    elif ord(packet[3]) == action['map']:
        print "Write Map packet come..."
        slot = lines[ord(packet[4])]['map']
    elif ord(packet[3]) == action['volume out']:
        print "Write Volume Out packet come..."
        slot = lines[ord(packet[4])]['volume out']
    elif ord(packet[3]) == action['mag threshold']:
        print "Write Mag Threshold packet come..."
        slot = lines[ord(packet[4])]['mag threshold']
    elif ord(packet[3]) == action['read mag']:
        print "Write Magnitude level packet come..."
        slot = lines[ord(packet[4])]['read mag']
    else:
        print "ERROR: Write packet not recognized packet."
        return

    slot[5] = int(packet[5].encode('hex'), 16)
    slot[6] = int(packet[6].encode('hex'), 16)
    board.write(ack_response)
    return

def connectivity__packet_handler(packet):

    if compare_packets(packet, conCheck):
        print "Connectivity Check packet come..."
        response = conCheckAnsw[:]
        crcCalculator.calculate(response)
        print "Send packet: " + '-'.join('%2x' % c for c in response)
        board.write(response)

if __name__ == "__main__":

    if board.isOpen():
        board.close()

    board.open()

    print "Connection established on port: %s" % board.port

    while True:
        print "Waiting for packet..."
        data = board.read(9)

        print "Packet come: " + '-'.join('%2x' % ord(c) for c in data)

        if 0 == ord(data[2]):
            print "Packet is read packet."
            read_packet_handler(data)

        if 1 == ord(data[2]):
            print "Packet is write packet."
            write_packet_handler(data)

        if 2 == ord(data[2]):
            print "Packet is connectivity check packet."
            connectivity__packet_handler(data)

        print
