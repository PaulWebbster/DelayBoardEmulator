#
# CRC CCITT
#
# comes in 3 flavors
# (XModem)  starting value: 0x0000
#           starting value: 0xffff
#           starting value: 0x1d0f
#


from ctypes import c_ushort


class CRCCCITT(object):
    crc_ccitt_tab = []

    # The CRC's are computed using polynomials.
    # Here is the most used coefficient for CRC CCITT
    crc_ccitt_constant = 0x1021

    def __init__(self, version='XModem'):
        try:
            dict_versions = {'XModem': 0x0000, 'FFFF': 0xffff, '1D0F': 0x1d0f, '1021': 0x1021}
            if version not in dict_versions.keys():
                raise Exception("Your version parameter should be one of \
                    the {} options".format("|".join(dict_versions.keys())))

            self.starting_value = dict_versions[version]

            # initialize the precalculated tables
            if not len(self.crc_ccitt_tab):
                self.init_crc_ccitt()
        except Exception as e:
            print("EXCEPTION(calculate): {}".format(e))

    def calculate(self, input_data=None):
        try:
            crcValue = self.starting_value

            for c in input_data:
                d = c
                tmp = (c_ushort(crcValue >> 8).value) ^ d
                crcValue = (c_ushort(crcValue << 8).value) ^ int(
                    self.crc_ccitt_tab[tmp], 0)

            crc = [int(crcValue >> i & 0xff) for i in (8, 0)]

            input_data.append(crc[0])
            input_data.append(crc[1])

            return
        except Exception as e:
            print("EXCEPTION(calculate): {}".format(e))

    def init_crc_ccitt(self):
        '''The algorithm uses tables with precalculated values'''
        for i in range(0, 256):
            crc = 0
            c = i << 8

            for j in range(0, 8):
                if ((crc ^ c) & 0x8000):
                    crc = c_ushort(crc << 1).value ^ self.crc_ccitt_constant
                else:
                    crc = c_ushort(crc << 1).value

                c = c_ushort(c << 1).value  # equivalent of c = c << 1
            self.crc_ccitt_tab.append(hex(crc))