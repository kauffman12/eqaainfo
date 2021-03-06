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
  if (not isSubPacket and bytes[0] == 0x5a):
    uncompressed = bytearray(zlib.decompress(bytes[1:]))
  elif (not isSubPacket and bytes[0] == 0xa5):
    uncompressed = bytes[1:]
    if (removeEnd):
      uncompressed = uncompressed[:-2]
  else:
    uncompressed = bytes[0:]
  return uncompressed

def getDirection(srcIP, dstIP, srcPort, dstPort):
  direction = UnknownDirection
  if ('ServerIP' in globals() and 'ClientIP' in globals()):
    if (srcIP == ServerIP and srcPort == ServerPort and dstIP == ClientIP and dstPort == ClientPort):
      direction = ServerToClient
    elif (srcIP == ClientIP and srcPort == ClientPort and dstIP == ServerIP and dstPort == ServerPort):
      direction = ClientToServer
  return direction

def findAppPacket(callback, uncompressed, timeStamp):
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
      callback(appOpcode, newPacket, timeStamp)    
  else:
    callback(code, uncompressed, timeStamp)

def processPacket(callback, srcIP, dstIP, srcPort, dstPort, bytes, timeStamp, isSubPacket):
  global CryptoFlag, FragmentSeq, Fragments, FragmentedPacketSize, LastSeq
  opcode = readBUInt16(bytes)

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
      CryptoFlag = int.from_bytes(bytes[19:11], 'little', signed=False)

    # Combined 
    elif (opcode == 0x03):
      uncompressed = uncompress(bytes, isSubPacket, False)
      while (len(uncompressed) > 2):
        size = readBytes(uncompressed, 1)[0]
        newPacket = readBytes(uncompressed, size)
        processPacket(callback, srcIP, dstIP, srcPort, dstPort, newPacket, timeStamp, True)

    # Packet
    elif (opcode == 0x09):
      uncompressed = uncompress(bytes, isSubPacket, True)
      findAppPacket(callback, uncompressed[2:], timeStamp) 

    # Fragment
    elif (opcode == 0x0d):
      uncompressed = uncompress(bytes, isSubPacket, True)
      seq = readBUInt16(uncompressed)
      if (FragmentSeq == -1):
        FragmentedPacketSize = readBUInt32(uncompressed)
        size = len(uncompressed)
        if (FragmentedPacketSize == 0 or FragmentedPacketSize > 2000000):
          raise StopIteration('Debug: received fragmented of size %d, discarding' % FragmentedPacketSize)
        else:
          if (size > FragmentedPacketSize):
            raise TypeError('Error: mangled fragment %d to %d' % (size, FragmentedPacketSize))
          FragmentSeq = seq
          Fragments = uncompressed
          # +4 to account for packet size read in current fragment
          # assuming a standrd length for fragments within a sequence
          LastSeq = int(FragmentedPacketSize / (size + 4)) + FragmentSeq
      else:
        if (seq <= LastSeq):
          Fragments += uncompressed
          FragmentSeq += 1
        # no issues
        if ((len(Fragments) == FragmentedPacketSize and FragmentSeq <= LastSeq)):
          findAppPacket(callback, Fragments, timeStamp)
          FragmentSeq = -1
        elif (seq > LastSeq): # sequence skipped too far ahead
          #print('Warning: data missing from sequence ending %d' % LastSeq)
          FragmentSeq = -1
          replayPacket = bytearray(opcode.to_bytes(2, 'big')) + bytes
          processPacket(callback, srcIP, dstIP, srcPort, dstPort, replayPacket, timeStamp, isSubPacket)      
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
        processPacket(callback, packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport, bytearray(packet[UDP].payload.load), packet.time, False)
    except Exception as error:
      print(error)
