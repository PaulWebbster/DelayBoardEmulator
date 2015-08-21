__author__ = 'paweber'

from Crc import CRCCCITT
from serial import Serial

# Board connection
board = Serial("COM11")
board.baudrate = 115200

#crc calculator
crcCalculator = CRCCCITT()

packetLength = 13;

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
action['none'] = 0x00
action['tone'] = 0x01
action['delay'] = 0x02
action['timeout'] = 0x03
action['volume in'] = 0x04
action['mute'] = 0x05
action['map'] = 0x06
action['volume out'] = 0x07
action['mag threshold'] = 0x08
action['write settings'] = 0x09
action['read settings'] = 0x0A
action['read mag'] = 0x0B
action['reset board'] = 0x0C
action['restore factory'] = 0x0D

conCheck = [preamble, version, mode['conn check'], action['none'], channel['none'], 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
conCheckAnsw = [preamble, version, mode['ack'], action['none'], channel['none'], 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
conCheckAnswFlashNotUpdated = [preamble, version, mode['ack'], action['none'], channel['none'], 0x80, 0x10, 0x00, 0x00, 0x00, 0x00]
conCheckAnswFlashTime = [preamble, version, mode['ack'], action['none'], channel['none'], 0x80, 0x20, 0x55, 0xD4, 0x6A, 0x97]
conCheckAnswTimeoutError = [preamble, version, mode['ack'], action['none'], channel['one'], 0x80, 0x08, 0x00, 0x00, 0x00, 0x00]
conCheckAnswI2CError = [preamble, version, mode['ack'], action['none'], channel['none'], 0x80, 0x27, 0x55, 0xD4, 0x6A, 0x97]
conCheckAnswCommError = [preamble, version, mode['ack'], action['none'], channel['none'], 0x00, 0x01, 0x55, 0xD4, 0x6A, 0x97]
ack = [preamble, version, mode['ack'], channel['none'], 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

ack_read_settings = [preamble, version, mode['ack'], channel['none'], 0x00, 0x00, 0x00, 0x55, 0xBA, 0x1A, 0xBB]
ack_write_settings = [preamble, version, mode['ack'], channel['none'], 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

zeros = 0x00

# errors
errors = {}
errors['crc'] = [preamble, version, mode['ack'], zeros, zeros, zeros, 0x01]
errors['attribute'] = [preamble, version, mode['ack'], zeros, zeros, zeros, 0x02]
errors['setting'] = [preamble, version, mode['ack'], zeros, zeros, zeros, 0x03]
errors['channel'] = [preamble, version, mode['ack'], zeros, zeros, zeros, 0x04]
errors['operation'] = [preamble, version, mode['ack'], zeros, zeros, zeros, 0x05]
errors['protocol'] = [preamble, version, mode['ack'], zeros, zeros, zeros, 0x06]


# LINE 1
lines = {}
lines[1] = {}
lines[1]['delay'] = [preamble, version, mode['read'], action['delay'], channel['one'], 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00]
lines[1]['tone'] = [preamble, version, mode['read'], action['tone'], channel['one'], 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
lines[1]['timeout'] = [preamble, version, mode['read'], action['timeout'], channel['one'], 0x00, 0x21, 0x00, 0x00, 0x00, 0x00]
lines[1]['volume in'] = [preamble, version, mode['read'], action['volume in'], channel['one'], 0x00, 0x40, 0x00, 0x00, 0x00, 0x00]
lines[1]['mute'] = [preamble, version, mode['read'], action['mute'], channel['one'], 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
lines[1]['map'] = [preamble, version, mode['read'], action['map'], channel['one'], 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
lines[1]['volume out'] = [preamble, version, mode['read'], action['volume out'], channel['one'], 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00]
lines[1]['mag threshold'] = [preamble, version, mode['read'], action['mag threshold'], channel['one'], 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]
lines[1]['read mag'] = [preamble, version, mode['read'], action['read mag'], channel['one'], 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]

# LINE 2
lines[2] = {}
lines[2]['delay'] = [preamble, version, mode['read'], action['delay'], channel['two'], 0x00, 0xff, 0x00, 0x00, 0x00, 0x00]
lines[2]['tone'] = [preamble, version, mode['read'], action['tone'], channel['two'], 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
lines[2]['timeout'] = [preamble, version, mode['read'], action['timeout'], channel['two'], 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]
lines[2]['volume in'] = [preamble, version, mode['read'], action['volume in'], channel['two'], 0x00, 0x12, 0x00, 0x00, 0x00, 0x00]
lines[2]['mute'] = [preamble, version, mode['read'], action['mute'], channel['two'], 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
lines[2]['map'] = [preamble, version, mode['read'], action['map'], channel['two'], 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]
lines[2]['volume out'] = [preamble, version, mode['read'], action['volume out'], channel['two'], 0x00, 0x40, 0x00, 0x00, 0x00, 0x00]
lines[2]['mag threshold'] = [preamble, version, mode['read'], action['mag threshold'], channel['two'], 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
lines[2]['read mag'] = [preamble, version, mode['read'], action['read mag'], channel['two'], 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]

# LINE 3
lines[3] = {}
lines[3]['delay'] = [preamble, version, mode['read'], action['delay'], channel['three'], 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00]
lines[3]['tone'] = [preamble, version, mode['read'], action['tone'], channel['three'], 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
lines[3]['timeout'] = [preamble, version, mode['read'], action['timeout'], channel['three'], 0x00, 0x16, 0x00, 0x00, 0x00, 0x00]
lines[3]['volume in'] = [preamble, version, mode['read'], action['volume in'], channel['three'], 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]
lines[3]['mute'] = [preamble, version, mode['read'], action['mute'], channel['three'], 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
lines[3]['map'] = [preamble, version, mode['read'], action['map'], channel['three'], 0x00, 0x03, 0x00, 0x00, 0x00, 0x00]
lines[3]['volume out'] = [preamble, version, mode['read'], action['volume out'], channel['three'], 0x00, 0x40, 0x00, 0x00, 0x00, 0x00]
lines[3]['mag threshold'] = [preamble, version, mode['read'], action['mag threshold'], channel['three'], 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
lines[3]['read mag'] = [preamble, version, mode['read'], action['read mag'], channel['three'], 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]

# LINE 4
lines[4] = {}
lines[4]['delay'] = [preamble, version, mode['read'], action['delay'], channel['four'], 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00]
lines[4]['tone'] = [preamble, version, mode['read'], action['tone'], channel['four'], 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
lines[4]['timeout'] = [preamble, version, mode['read'], action['timeout'], channel['four'], 0x00, 0x15, 0x00, 0x00, 0x00, 0x00]
lines[4]['volume in'] = [preamble, version, mode['read'], action['volume in'], channel['four'], 0x00, 0x20, 0x00, 0x00, 0x00, 0x00]
lines[4]['mute'] = [preamble, version, mode['read'], action['mute'], channel['four'], 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
lines[4]['map'] = [preamble, version, mode['read'], action['map'], channel['four'], 0x00, 0x04, 0x00, 0x00, 0x00, 0x00]
lines[4]['volume out'] = [preamble, version, mode['read'], action['volume out'], channel['four'], 0x00, 0x40, 0x00, 0x00, 0x00, 0x00]
lines[4]['mag threshold'] = [preamble, version, mode['read'], action['mag threshold'], channel['four'], 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
lines[4]['read mag'] = [preamble, version, mode['read'], action['read mag'], channel['four'], 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]

# LINE 5
lines[5] = {}
lines[5]['delay'] = [preamble, version, mode['read'], action['delay'], channel['five'], 0x00, 0x08, 0x00, 0x00, 0x00, 0x00]
lines[5]['tone'] = [preamble, version, mode['read'], action['tone'], channel['five'], 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
lines[5]['timeout'] = [preamble, version, mode['read'], action['timeout'], channel['five'], 0x00, 0x13, 0x00, 0x00, 0x00, 0x00]
lines[5]['volume in'] = [preamble, version, mode['read'], action['volume in'], channel['five'], 0x00, 0x22, 0x00, 0x00, 0x00, 0x00]
lines[5]['mute'] = [preamble, version, mode['read'], action['mute'], channel['five'], 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
lines[5]['map'] = [preamble, version, mode['read'], action['map'], channel['five'], 0x00, 0x05, 0x00, 0x00, 0x00, 0x00]
lines[5]['volume out'] = [preamble, version, mode['read'], action['volume out'], channel['five'], 0x00, 0x40, 0x00, 0x00, 0x00, 0x00]
lines[5]['mag threshold'] = [preamble, version, mode['read'], action['mag threshold'], channel['five'], 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
lines[5]['read mag'] = [preamble, version, mode['read'], action['read mag'], channel['five'], 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]

# LINE 6
lines[6] = {}
lines[6]['delay'] = [preamble, version, mode['read'], action['delay'], channel['six'], 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]
#lines[6]['delay'] = errors['crc']
lines[6]['tone'] = [preamble, version, mode['read'], action['tone'], channel['six'], 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
lines[6]['timeout'] = [preamble, version, mode['read'], action['timeout'], channel['six'], 0x00, 0x11, 0x00, 0x00, 0x00, 0x00]
lines[6]['volume in'] = [preamble, version, mode['read'], action['volume in'], channel['six'], 0x00, 0x10, 0x00, 0x00, 0x00, 0x00]
lines[6]['mute'] = [preamble, version, mode['read'], action['mute'], channel['six'], 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
lines[6]['map'] = [preamble, version, mode['read'], action['map'], channel['six'], 0x00, 0x06, 0x00, 0x00, 0x00, 0x00]
lines[6]['volume out'] = [preamble, version, mode['read'], action['volume out'], channel['six'], 0x00, 0x40, 0x00, 0x00, 0x00, 0x00]
lines[6]['mag threshold'] = [preamble, version, mode['read'], action['mag threshold'], channel['six'], 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
lines[6]['read mag'] = [preamble, version, mode['read'], action['read mag'], channel['six'], 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]

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
    # generate crc error
    # response[6] = 0xff
    board.write(response)
    print "Packet send: " + '-'.join('%2x' % c for c in response)

def write_packet_handler(packet):
    ack_response = ack[:]
    crcCalculator.calculate(ack_response)

    if ord(packet[4]) != channel['none']:
        # Line settings
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

        response_packet = [preamble, version, ord(packet[2]), ord(packet[3]), ord(packet[4]), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        crcCalculator.calculate(response_packet)
        print "Packet send: " + '-'.join('%2x' % c for c in response_packet)

        # slot[5] = int(packet[5].encode('hex'), 16)
        # slot[6] = int(packet[6].encode('hex'), 16)

        board.write(response_packet)
    else:
        # other settings
        if ord(packet[3]) == action['read settings']:
            board.write(ack_response)
        if ord(packet[3]) == action['write settings']:
            board.write(ack_response)
        if ord(packet[3]) == action['restore factory']:
            board.write(ack_response)
        if ord(packet[3]) == action['reset board']:
            board.write(ack_response)
    return

def connectivity__packet_handler(packet):

    if compare_packets(packet, conCheck):
        print "Connectivity Check packet come..."
        #response = conCheckAnswI2CError[:]
        #response = conCheckAnswTimeoutError[:]
        #response = conCheckAnswCommError[:]
        #response = conCheckAnswFlashTime[:]
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
        data = board.read(packetLength)

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
