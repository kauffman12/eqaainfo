# requires windows version of python
# use 'winpty' if running from gitbash

import msvcrt
from os import path
from scapy.all import *

def packet_callback(packet):
  if packet[UDP] and packet[UDP].payload:
    #print(packet.summary())
    writer.write(packet)

def main(args):
  if (len(args) < 2):
    print('Usage: ' + args[0] + ' <output filename>')
  else:
    if path.exists(args[1]):
      overwrite = False
      while not overwrite:
        print('%s already exists, Overwrite? (y/n) ' % args[1], end = '', flush = True)
        read = msvcrt.getch()
        if read == b'n':
          return
        elif read == b'y':
          overwrite = True

    print('Capturing to %s (Ctrl+C to Stop)' % args[1], flush = True)
    writer = PcapWriter(args[1], append=True, sync=False)
    sniff(filter="src net 69.174 or dst net 69.174", prn=packet_callback, store=0)

main(sys.argv)
