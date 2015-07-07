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
mode = dict
mode['read'] = 0x00
mode['write'] = 0x01
mode['conn check'] = 0x02
mode['ack'] = 0x03

# Channels
channel = dict
channel['none'] = 0x00
channel['one'] = 0x01
channel['two'] = 0x02
channel['three'] = 0x03
channel['four'] = 0x04
channel['five'] = 0x05
channel['six'] = 0x06

# commands
action = dict
action['tone'] = 0x00
action['delay'] = 0x01
action['timeout'] = 0x02
action['volume in'] = 0x03
action['mute'] = 0x04
action['map'] = 0x05
action['volume out'] = 0x06
action['mag threshold'] = 0x07
action['write settings'] = 0x08
action['read mag'] = 0x09

conCheck = [preamble, version, mode['conn check'], channel['none'], 0x00, 0x00, 0x00]
conCheckAnsw = [preamble, version, mode['ack'], channel['none'], 0x00, 0x00, 0x00]
ack = [preamble, version, mode['ack'], channel['none'], 0x00, 0x00, 0x00]

# LINE 1
lines = dict
lines[1] = dict
lines[1]['delay'] = [preamble, version, mode['read'], action['tone_detection'], channel['one'], 0x00, 0x0c]
lines[1]['tone'] = [preamble, version, mode['read'], action['delay'], channel['one'], 0x00, 0x00]
lines[1]['timeout'] = [preamble, version, mode['read'], action['timeout'], channel['one'], 0x00, 0x21]
lines[1]['volume in'] = [preamble, version, mode['read'], action['volume_in'], channel['one'], 0x00, 0x02]
lines[1]['mute'] = [preamble, version, mode['read'], action['mute'], channel['one'], 0x00, 0x01]
lines[1]['map'] = [preamble, version, mode['read'], action['map'], channel['one'], 0x00, 0x01]
lines[1]['volume out'] = [preamble, version, mode['read'], action['volume_out'], channel['one'], 0x00, 0x02]
lines[1]['mag threshold'] = [preamble, version, mode['read'], action['magnitude_threshold'], channel['one'], 0x00, 0x02]
lines[1]['read mag'] = [preamble, version, mode['read'], action['read_magnitude'], channel['one'], 0x00, 0x02]

def compare_packets(first, second):
    return all(map(lambda v: v in map(ord, first), second))

def packet_print(packet, prefix="", suffix=""):
    print prefix + '-'.join('%2x' % ord(c) for c in packet) + suffix

def read_packet_handler(packet):
    line = lines[int(packet[4])]

    if ord(packet[3]) == action['tone']:
        print "Read Tone Detection packet come..."
        print "Channel: {chann}, Attribute: {attr}".format(chann=hex(line), attr=int(packet[5]+packet[6]))
        board.write(line['tone'])

    if ord(packet[3]) == action['delay']:
        print "Read Delay packet come..."
        board.write(line['delay'])

    if ord(packet[3]) == action['timeout']:
        print "Read Timeout packet come..."
        board.write(line['timeout'])

    if ord(packet[3]) == action['volume in']:
        print "Read Volume In packet come..."
        board.write(line['volume in'])

    if ord(packet[3]) == action['mute']:
        print "Read Mute packet come..."
        board.write(line['mute'])

    if ord(packet[3]) == action['map']:
        print "Read Map packet come..."
        board.write(line['map'])

    if ord(packet[3]) == action['volume out']:
        print "Read Volume Out packet come..."
        board.write(line['volume out'])

    if ord(packet[3]) == action['maq threshold']:
        print "Read Mag Threshold packet come..."
        board.write(line['mag threshold'])

    if ord(packet[3]) == action['read mag']:
        print "Read Magnitude level packet come..."
        board.write(line['read mag'])

def write_packet_handler(packet):
    line = lines[int(packet[4])]

    if ord(packet[3]) == action['tone']:
        print "Write Tone Detection packet come..."
        board.write(ack)

    if ord(packet[3]) == action['delay']:
        print "Write Delay packet come..."
        board.write(ack)

    if ord(packet[3]) == action['timeout']:
        print "Write Timeout packet come..."
        board.write(ack)

    if ord(packet[3]) == action['volume in']:
        print "Write Volume In packet come..."
        board.write(ack)

    if ord(packet[3]) == action['mute']:
        print "Write Mute packet come..."
        board.write(ack)

    if ord(packet[3]) == action['map']:
        print "Write Map packet come..."
        board.write(ack)

    if ord(packet[3]) == action['volume out']:
        print "Write Volume Out packet come..."
        board.write(ack)

    if ord(packet[3]) == action['maq threshold']:
        print "Write Mag Threshold packet come..."
        board.write(ack)

    if ord(packet[3]) == action['read mag']:
        print "Write Magnitude level packet come..."
        board.write(ack)

def connectivity__packet_handler(packet):

    if compare_packets(packet, conCheck):
        print "Connectivity Check packet come"
        response = conCheckAnsw[:]
        crcCalculator.calculate(response)

        board.write(response)

if __name__ == "__main__":

    if board.isOpen():
        board.close()

    board.open()

    print "Connection established on port: %s" % board.port

    while True:
        print "Waiting for packet"
        data = board.read(9)

        print "Packet come: " + '-'.join('%2x' % ord(c) for c in data)
        print "\n"

        if 0 == ord(data[2]):
            print "Read packet come..."
            read_packet_handler(data)

        if 1 == ord(data[2]):
            print "Write packet come..."

        if 2 == ord(data[2]):
            print "Connectivity check packet come..."
