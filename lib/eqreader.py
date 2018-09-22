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

def getBUInt16(buffer, offset):
  value = buffer[offset:offset+2]
  return int.from_bytes(value, 'big', signed=False)

def getUInt16(buffer, offset):
  value = buffer[offset:offset+2]
  return int.from_bytes(value, 'little', signed=False)

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

def uncompress(bytes, opcode, isSubPacket, offset):
  lastIndex = len(bytes) - offset
  if (not isSubPacket and bytes[2] == 0x5a):
    uncompressed = zlib.decompress(bytes[3:lastIndex])
  elif (not isSubPacket and bytes[2] == 0xa5):
    uncompressed = bytes[3:lastIndex]
  else:
    # offset not used when subpacket
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

def processAppPacket(callback, srcIP, dstIP, srcPort, dstPort, opcode, size, bytes, pos, direction):
  if (ServerToClient == direction):
    callback(opcode, size, bytes, pos)

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
    if (opcode == 1):
      global ClientIP, ClientPort, ServerIP, ServerPort, ClientSEQ, ServerSEQ
      ClientIP = srcIP
      ClientPort = srcPort
      ServerIP = dstIP
      ServerPort = dstPort
      CryptoFlag = ClientSEQ = ServerSEQ = 0

    # Session Response
    elif (opcode == 0x02):
      CryptoFlag = getUInt16(bytes, 11)

    # Combined 
    elif (opcode == 0x03):
      pos = 0
      uncompressed = uncompress(bytes, opcode, isSubPacket, 0)

      while (pos < len(uncompressed) - 2):
        isSubPacketSize = uncompressed[pos]
        pos += 1
        newPacket = uncompressed[pos:isSubPacketSize + pos]
        pos += isSubPacketSize
        processPacket(callback, srcIP, dstIP, srcPort, dstPort, newPacket, True, isCached)

    # Packet
    elif (opcode == 0x09):
      uncompressed = uncompress(bytes, opcode, isSubPacket, 2)
      seq = getBUInt16(uncompressed, 0)
      validateSequence(seq, direction, bytes, isSubPacket, False)

      if (uncompressed[2] == 0x00 and uncompressed[3] == 0x19):
        pos = 4
        while (pos < len(uncompressed) - 2):
          if (uncompressed[pos] == 0xff):
            size = getBUInt16(uncompressed, pos + 1) - 2
            pos += 3
          else:
            size = uncompressed[pos] - 2
            pos += 1

          appOpcode = getUInt16(uncompressed, pos)
          pos += 2
          processAppPacket(callback, srcIP, dstIP, srcPort, dstPort, appOpcode, size, uncompressed, pos, direction)
          pos += size
      else:
        appOpcode = getUInt16(uncompressed, 2)
        processAppPacket(callback, srcIP, dstIP, srcPort, dstPort, appOpcode, len(uncompressed) - 4, uncompressed, 4, direction)       

    # Fragment
    elif (opcode == 0x0d):
      uncompressed = uncompress(bytes, opcode, isSubPacket, 2)

      if (FragmentSeq[direction] == -1):
        FragmentSeq[direction] = getBUInt16(uncompressed, 0)
        validateSequence(FragmentSeq[direction], direction, bytes, isSubPacket, True)
        FragmentedPacketSize[direction] = uncompressed[2] * 0x1000000 + uncompressed[3] * 0x10000 + uncompressed[4] * 0x100 + uncompressed[5]

        if (FragmentedPacketSize[direction] == 0 or FragmentedPacketSize[direction] > 1000000):
          FragmentSeq[direction] = -1
          raise TypeError('Got a fragmented packet of size ' + str(FragmentedPacketSize[direction]) + ' and discarding')
        else:
          FragmentedBytesCollected[direction] = len(uncompressed) - 6
          if (len(uncompressed) - 6 > FragmentedPacketSize[direction]):
            FragmentSeq[direction] = -1
            raise TypeError('Fragment: mangled fragment 1')

          Fragments[direction] = bytearray(FragmentedPacketSize[direction])
          temp = uncompressed[6:]
          Fragments[direction][0:len(temp)] = temp
      else:
        last = FragmentSeq[direction]
        FragmentSeq[direction] = getBUInt16(uncompressed, 0)
        validateSequence(FragmentSeq[direction], direction, bytes, isSubPacket, False)

        if (len(uncompressed) - 2 > len(Fragments[direction]) - FragmentedBytesCollected[direction]):
          FragmentSeq[direction] = -1
          raise TypeError('Fragment: Mangled fragment 2')

        index = FragmentedBytesCollected[direction]
        lastIndex = index + len(uncompressed) - 2;   
        Fragments[direction][index:lastIndex] = uncompressed[2:]
        FragmentedBytesCollected[direction] += len(uncompressed) - 2

        if (FragmentedBytesCollected[direction] == FragmentedPacketSize[direction]):
          if (Fragments[direction][0] == 0x00 and Fragments[1][direction] == 0x019):
            pos = 2
            while (pos < len(Fragments[direction])):
              if (Fragments[direction][pos] == 0xff):
                size = getBUInt16(Fragments[direction], pos + 1) - 2     
                pos += 3
              else:
                size = Fragments[direction][pos] - 2
                pos += 1

              appOpcode = getUInt16(Fragments[direction], pos)
              pos += 2
              processAppPacket(callback, srcIP, dstIP, srcPort, dstPort, appOpcode, size, Fragments[direction], pos, direction)
              pos += size
          else:
            appOpcode = getUInt16(Fragments[direction], 0)
            newPacket = Fragments[direction][2:len(Fragments[direction]) - 2]
            processAppPacket(callback, srcIP, dstIP, srcPort, dstPort, appOpcode, len(newPacket), newPacket, 0, direction)
          FragmentSeq[direction] = -1

    # Unencapsulated EQ Application Opcode
    elif (opcode > 0xff):
      if (isSubPacket):
        appOpcode = getBUInt16(bytes, 0)
        newPacket = bytes[2:]
      else:
        if (bytes[1] == 0x5a):
          uncompressed = zlib.decompress(bytes[2:])
          appOpcode = uncompressed[0] * 256 + bytes[0]
          newPacket = uncompressed[1:]
        else:
          appOpcode = bytes[2] * 256 + bytes[0] 
          newPacket = bytes[3:]
      processAppPacket(callback, srcIP, dstIP, srcPort, dstPort, appOpcode, len(newPacket), newPacket, 0, direction)
  except TypeError as error:
    pass #print(error)
  except StopIteration as stoppping:
    pass
  except Exception as other:
    #traceback.print_exc()
    print(error)

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