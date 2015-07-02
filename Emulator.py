__author__ = 'paweber'

from serial import Serial

             # pream  vers  mode  act   chan  attr0 attr1 crc1  crc2
conCheck =     [0x55, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x77, 0xCF]
conCheckAnsw = [0x55, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x18, 0x02]
ack          = [0x55, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x18, 0x02]

board = Serial("COM5")
board.baudrate = 115200

if board.isOpen():
    board.close()

board.open()

print "Connection established on port: %s" % board.port

while True:
    print "Waiting for packet"
    data = board.read(9)

    print "Packet come: " + '-'.join('%2x' % ord(c) for c in data)
    print "\n\n"

    if all(map(lambda v: v in map(ord, data), conCheck)):
        print "ConnectivityCheck packet come"
        board.write(conCheckAnsw)

    if 1 == ord(data[2]):
        print "Data write packet come"
        board.write(ack);
