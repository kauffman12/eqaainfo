#
# EQ Packet handling based on EQExtractor created by EQEMu Development Team
# --> Copyright (C) 2001-2010 EQEMu Development Team (http://eqemulator.net). Distributed under GPL version 2.
#
import zlib
from scapy.all import *
from lib.util import *

ClientToServer = 0
ServerToClient = 1
UnknownDirection = 2
Fragments = []
FragmentSeq = -1
FragmentedPacketSize = 0
LastSeq = -1

def uncompress(bytes, isSubPacket, removeEnd):
  if (not isSubPacket and bytes[2] == 0x5a):
    uncompressed = zlib.decompress(bytes[3:])
  elif (not isSubPacket and bytes[2] == 0xa5):
    if (removeEnd):
      uncompressed = bytes[3:len(bytes)-2]
    else:
      uncompressed = bytes[3:]
  else:
    uncompressed = bytes[2:]
  return list(uncompressed)

def getDirection(srcIP, dstIP, srcPort, dstPort):
  direction = UnknownDirection
  if ('ServerIP' in globals() and 'ClientIP' in globals()):
    if (srcIP == ServerIP and srcPort == ServerPort and dstIP == ClientIP and dstPort == ClientPort):
      direction = ServerToClient
    elif (srcIP == ClientIP and srcPort == ClientPort and dstIP == ServerIP and dstPort == ServerPort):
      direction = ClientToServer
  return direction

def findAppPacket(callback, uncompressed):
  code = readUInt16(uncompressed)
  if (code == 0x1900):
    while (len(uncompressed) > 3):
      if (uncompressed[0] == 0xff):
        readBytes(uncompressed, 1)
        size = readBUInt16(uncompressed)
      else:
        size = readBytes(uncompressed, 1)[0]

      newPacket = readBytes(uncompressed, size)
      appOpcode = readUInt16(newPacket)
      callback(appOpcode, len(newPacket), newPacket, 0)    
  else:
    callback(code, len(uncompressed), uncompressed, 0)

def processPacket(callback, srcIP, dstIP, srcPort, dstPort, bytes, isSubPacket):
  global CryptoFlag, FragmentSeq, Fragments, FragmentedPacketSize, LastSeq
  opcode = int.from_bytes(bytes[0:2], 'big', signed=False)

  direction = getDirection(srcIP, dstIP, srcPort, dstPort)
  if ((direction == UnknownDirection and opcode != 0x01) or (direction == ClientToServer and opcode != 0x02)):
    return

  # Check if this is a UCS connection and if so, skip packets until we see another Session Request
  if (opcode != 0x01 and 'CryptoFlag' in globals() and (CryptoFlag & 4) > 0):
    return

  try:
    # Session Request
    if (opcode == 0x01):
      global ClientIP, ClientPort, ServerIP, ServerPort
      CryptoFlag = 0
      ClientIP = srcIP
      ClientPort = srcPort
      ServerIP = dstIP
      ServerPort = dstPort

    # Session Response
    elif (opcode == 0x02):
      CryptoFlag = int.from_bytes(bytes[11:13], 'little', signed=False)

    # Combined 
    elif (opcode == 0x03):
      uncompressed = uncompress(bytes, isSubPacket, False)

      pos = 0
      while (pos < len(uncompressed) - 2):
        size = uncompressed[pos]
        pos += 1
        newPacket = uncompressed[pos:size+pos]
        processPacket(callback, srcIP, dstIP, srcPort, dstPort, newPacket, True)
        pos += size

    # Packet
    elif (opcode == 0x09):
      uncompressed = uncompress(bytes, isSubPacket, True)
      findAppPacket(callback, uncompressed[2:]) 

    # Fragment
    elif (opcode == 0x0d):
      uncompressed = uncompress(bytes, isSubPacket, True)
      seq = readBUInt16(uncompressed)

      #print('SEQ: %d' % seq)
      if (FragmentSeq == -1):
        FragmentedPacketSize = readBUInt32(uncompressed)

        size = len(uncompressed)
        if (FragmentedPacketSize == 0 or FragmentedPacketSize > 1000000):
          raise StopIteration('Got a fragmented packet of size ' + str(FragmentedPacketSize) + ', discarding')
        else:
          if (size > FragmentedPacketSize):
            raise TypeError('Fragment: mangled fragment %d to %d' % (size, FragmentedPacketSize))

          FragmentSeq = seq
          Fragments += uncompressed
          # +4 to account for packet size read in current fragment
          # assuming a standrd length for fragments within a sequence
          LastSeq = int(FragmentedPacketSize / size + 4) + FragmentSeq
      else:
        if (seq <= LastSeq):
          Fragments += uncompressed
          FragmentSeq += 1

        # no issues
        if ((len(Fragments) == FragmentedPacketSize and FragmentSeq <= LastSeq)):
          findAppPacket(callback, Fragments)
          FragmentSeq = -1
          Fragments = []
        elif (seq > LastSeq): #skipped too far ahead
          FragmentSeq = -1
          Fragments = []
          print('Fragment: incomplete sequence, possible data loss')
          processPacket(callback, srcIP, dstIP, srcPort, dstPort, bytes, isSubPacket)      
  except TypeError as error:
    print(error)
  except StopIteration as stopInfo:
    pass #print(stopInfo)
  except Exception as other:  
    print(other) #traceback.print_exc()

def readPcap(callback, pcap):
  for packet in rdpcap(pcap):
    try:
      if (UDP in packet and Raw in packet and len(packet[UDP].payload) > 2):
        processPacket(callback, packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport, packet[UDP].payload.load, False)
    except Exception as error:
      print(error)