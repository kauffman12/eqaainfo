#
# EQ Packet handling based on EQExtractor created by EQEMu Development Team
# --> Copyright (C) 2001-2010 EQEMu Development Team (http://eqemulator.net). Distributed under GPL version 2.
#
import zlib
from scapy.all import *

Cache = dict()
ClientToServer = 0
ServerToClient = 1
UnknownDirection = 2
FragmentSeq = [-1, -1]
FragmentedPacketSize = [0, 0]
FragmentedBytesCollected = [0, 0]
Fragments = [[]] * 2

def getUInt16(buffer, offset):
  value = buffer[offset:offset+2]
  return int.from_bytes(value, 'little', signed=False)

def getBUInt16(buffer, offset):
  value = buffer[offset:offset+2]
  return int.from_bytes(value, 'big', signed=False)

def getBUInt32(buffer, offset):
  value = buffer[offset:offset+4]
  return int.from_bytes(value, 'big', signed=False)

def getDirection(srcIP, dstIP, srcPort, dstPort):
  direction = UnknownDirection
  if ('ServerIP' in globals() and 'ClientIP' in globals()):
    if (srcIP == ServerIP and srcPort == ServerPort and dstIP == ClientIP and dstPort == ClientPort):
      direction = ServerToClient
    elif (srcIP == ClientIP and srcPort == ClientPort and dstIP == ServerIP and dstPort == ServerPort):
      direction = ClientToServer
  return direction

def advanceSequence(direction):
  global ServerSEQ, ClientSEQ
  if (direction == ServerToClient):
    ServerSEQ += 1
  elif (direction == ClientToServer):
    ClientSEQ += 1

def getSequence(direction):
  seq = 0
  if (direction == ServerToClient and 'ServerSEQ' in globals()):
    seq = ServerSEQ
  elif (direction == ClientToServer and 'ClientSEQ' in globals()):
    seq = ClientSEQ
  return seq

def uncompress(bytes, isSubPacket):
  if (not isSubPacket and bytes[2] == 0x5a):
    uncompressed = zlib.decompress(bytes[3:])
  elif (not isSubPacket and bytes[2] == 0xa5):
    uncompressed = bytes[3:]
  else:
    uncompressed = bytes[2:]
  return uncompressed

def addToCache(seq, direction, bytes, isSubPacket):
  key = 'seq=%d&dir=%d' % (seq, direction)
  if (Cache.get(key) == None):
    Cache[key] = {
      'seq': seq,
      'direction': direction,
      'bytes': bytes,
      'isSubPacket': isSubPacket
    }

def processCache(callback, direction):
  seq = getSequence(direction)
  key = 'seq=%d&dir=%d' % (seq, direction)
  entry = Cache.get(key)

  while (entry != None):
    if (direction == ServerToClient):
      processPacket(callback, ServerIP, ClientIP, ServerPort, ClientPort, entry['bytes'], entry['isSubPacket'], True)
    elif (direction == ClientToServer):
      processPacket(callback, ClientIP, ServerIP, ClientPort, ServerPort, entry['bytes'], entry['isSubPacket'], True)
    del Cache[key]
    entry = Cache.get(key)

def findAppPacket(callback, uncompressed, direction):
  if (uncompressed[0] == 0x00 and uncompressed[1] == 0x19):
    pos = 2
    while (pos < len(uncompressed)):
      if (uncompressed[pos] == 0xff):
        size = getBUInt16(uncompressed, pos + 1) - 2
        pos += 3
      else:
        size = uncompressed[pos] - 2
        pos += 1

      appOpcode = getUInt16(uncompressed, pos)
      newPacket = uncompressed[pos+2:]
      callback(appOpcode, len(newPacket), newPacket, 0, ServerToClient == direction)    
      pos += size + 2 
  else:
    appOpcode = getUInt16(uncompressed, 0)
    newPacket = uncompressed[2:]
    callback(appOpcode, len(newPacket), newPacket, 0, ServerToClient == direction) 

def validateSequence(seq, direction, bytes, isSubPacket, resetToError):
  expected = getSequence(direction)
  if (seq != expected):
    if (seq > expected):
      if (seq - expected < 1000):
        addToCache(seq, direction, bytes, isSubPacket)
      else:
        FragmentSeq[direction] = -1
        advanceSequence(direction);
        raise TypeError('Fragment: Missing expected fragment')

    if (resetToError):
      FragmentSeq[direction] = -1
    raise StopIteration()
  else:
    advanceSequence(direction)

def processPacket(callback, srcIP, dstIP, srcPort, dstPort, bytes, isSubPacket, isCached):
  global CryptoFlag, FragmentSeq, Fragments, FragmentedPacketSize, FragmentedBytesCollected
  opcode = getBUInt16(bytes, 0)

  direction = getDirection(srcIP, dstIP, srcPort, dstPort)
  if (direction == UnknownDirection and opcode != 1):
    return

  # Check if this is a UCS connection and if so, skip packets until we see another Session Request
  if (opcode != 0x01 and 'CryptoFlag' in globals() and (CryptoFlag & 4) > 0):
    return

  try:
    # Session Request
    if (opcode == 0x01):
      global ClientIP, ClientPort, ServerIP, ServerPort, ClientSEQ, ServerSEQ
      CryptoFlag = ClientSEQ = ServerSEQ = 0
      ClientIP = srcIP
      ClientPort = srcPort
      ServerIP = dstIP
      ServerPort = dstPort

    # Session Response
    elif (opcode == 0x02):
      CryptoFlag = getUInt16(bytes, 11)

    # Combined 
    elif (opcode == 0x03):
      uncompressed = uncompress(bytes, isSubPacket)

      pos = 0
      while (pos < len(uncompressed) - 2):
        size = uncompressed[pos]
        pos += 1
        newPacket = uncompressed[pos:size + pos]
        processPacket(callback, srcIP, dstIP, srcPort, dstPort, newPacket, True, isCached)
        pos += size

    # Packet
    elif (opcode == 0x09):
      uncompressed = uncompress(bytes, isSubPacket)
      seq = getBUInt16(uncompressed, 0)
      validateSequence(seq, direction, bytes, isSubPacket, False)
      findAppPacket(callback, uncompressed[2:], direction) 

    # Fragment
    elif (opcode == 0x0d):
      uncompressed = uncompress(bytes, isSubPacket)

      if (FragmentSeq[direction] == -1):
        FragmentSeq[direction] = getBUInt16(uncompressed, 0)
        validateSequence(FragmentSeq[direction], direction, bytes, isSubPacket, True)
        FragmentedPacketSize[direction] = getBUInt32(uncompressed, 2)

        if (FragmentedPacketSize[direction] == 0 or FragmentedPacketSize[direction] > 1000000):
          FragmentSeq[direction] = -1
          raise TypeError('Got a fragmented packet of size ' + str(FragmentedPacketSize[direction]) + ' and discarding')
        else:
          FragmentedBytesCollected[direction] = len(uncompressed) - 6
          if (len(uncompressed) - 6 > FragmentedPacketSize[direction]):
            FragmentSeq[direction] = -1
            raise TypeError('Fragment: mangled fragment')

          Fragments[direction] = bytearray(FragmentedPacketSize[direction])
          temp = uncompressed[6:]
          Fragments[direction][0:len(temp)] = temp
      else:
        last = FragmentSeq[direction]
        FragmentSeq[direction] = getBUInt16(uncompressed, 0)
        validateSequence(FragmentSeq[direction], direction, bytes, isSubPacket, False)

        if (len(uncompressed) - 2 > len(Fragments[direction]) - FragmentedBytesCollected[direction]):
          FragmentSeq[direction] = -1
          raise TypeError('Fragment: mangled fragment')

        index = FragmentedBytesCollected[direction]
        lastIndex = index + len(uncompressed) - 2;   
        Fragments[direction][index:lastIndex] = uncompressed[2:]
        FragmentedBytesCollected[direction] += len(uncompressed) - 2

        if (FragmentedBytesCollected[direction] == FragmentedPacketSize[direction]):
          findAppPacket(callback, Fragments[direction], direction)
          FragmentSeq[direction] = -1
  except TypeError as error:
    pass #print(error)
  except StopIteration as stoppping:
    pass
  except Exception as other:
    #traceback.print_exc()
    print(other)

  if (not isCached and len(Cache) > 0):
    processCache(callback, ServerToClient)
    processCache(callback, ClientToServer)

def readPcap(callback, pcap):
  for packet in rdpcap(pcap):
    try:
      if (UDP in packet and Raw in packet and len(packet[UDP].payload) > 2):
        processPacket(callback, packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport, packet[UDP].payload.load, False, False)
    except Exception as error:
      #traceback.print_exc()
      print(error)