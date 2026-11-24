# requires windows version of python
# use 'winpty' if running from gitbash

import msvcrt
import sys
from os import path
from scapy.all import PcapWriter, UDP, conf, sniff


def main(args):
  if len(args) < 2:
    print('Usage: ' + args[0] + ' <output filename>')
    return

  filename = args[1]
  if path.exists(filename):
    while True:
      print('%s already exists, Overwrite? (y/n) ' % filename, end='', flush=True)
      answer = msvcrt.getch().lower()
      if answer == b'n':
        return
      if answer == b'y':
        break

  iface = conf.route.route('8.8.8.8')[0]
  print('Using default interface:', iface)

  with PcapWriter(filename, append=False, sync=True) as writer:
    def packet_callback(packet):
      if UDP in packet and packet[UDP].payload:
        writer.write(packet)

    def ready():
      print('Capturing to %s (Ctrl+C to Stop)' % filename, flush=True)

    # Keep one capture socket open; Scapy stops sniffing on Ctrl+C.
    sniff(iface=iface, filter='udp and (src net 69.174 or dst net 69.174)',
          prn=packet_callback, store=False, started_callback=ready)


if __name__ == '__main__':
  main(sys.argv)
