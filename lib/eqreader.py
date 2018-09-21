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

def uncompress(bytes, opcode, isSubPacket):
  if (not isSubPacket and bytes[2] == 0x5a):
    uncompressed = zlib.decompress(bytes[3:])
  elif (not isSubPacket and bytes[2] == 0xa5):
    lastIndex = len(bytes)
    # remove two bytes at the end for some reason
    if (opcode == 0x09 or opcode == 0x0d):
      lastIndex -= 2
    uncompressed = bytes[3:lastIndex]
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

def processAppPacket(callback, srcIP, dstIP, srcPort, dstPort, opcode, size, bytes, pos, direction):
  if (ServerToClient == direction):
    callback(opcode, size, bytes, pos)

def processPacket(callback, srcIP, dstIP, srcPort, dstPort, bytes, isSubPacket, isCached):
  global CryptoFlag, FragmentSeq, Fragments, FragmentedPacketSize, FragmentedBytesCollected
  opcode = bytes[0] * 256 + bytes[1]

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
      CryptoFlag = bytes[11] + bytes[12] * 256

    # Combined 
    elif (opcode == 0x03):
      pos = 0
      uncompressed = uncompress(bytes, opcode, isSubPacket)

      while (pos < len(uncompressed) - 2):
        isSubPacketSize = uncompressed[pos]
        pos += 1
        lastIndex = isSubPacketSize + pos
        newPacket = uncompressed[pos:lastIndex]
        pos += isSubPacketSize
        processPacket(callback, srcIP, dstIP, srcPort, dstPort, newPacket, True, isCached)

    # Packet
    elif (opcode == 0x09):
      uncompressed = uncompress(bytes, opcode, isSubPacket)
      seq = uncompressed[0] * 256 + uncompressed[1]
      expected = getSequence(direction)

      if (seq != expected):
        if (seq > expected):
          if (seq - expected < 1000):
            addToCache(seq, direction, bytes, isSubPacket)
          else:
            FragmentSeq[direction] = -1
            advanceSequence(direction)
            raise TypeError('Packet: Missing expected fragment')
        raise StopIteration()
      else:
        advanceSequence(direction)

      if (uncompressed[2] == 0x00 and uncompressed[3] == 0x19):
        pos = 4
        while (pos < len(uncompressed) - 3):
          size = 0
          opcodeBytes = 2

          if (uncompressed[pos] == 0xff):
            if (uncompressed[pos + 1] == 0x01):
              size = 256 + uncompressed[pos + 2]
            else:
              size = uncompressed[pos + 2]
            pos += 3
          else:
            size = uncompressed[pos]
            appOpcode = uncompressed[pos + 1]
            pos += 2

            if (appOpcode == 0):
              pos += 1
              opcodeBytes = 3

            appOpcode = appOpcode + uncompressed[pos] * 256
            pos += 1
            processAppPacket(callback, srcIP, dstIP, srcPort, dstPort, appOpcode, size - opcodeBytes, uncompressed, pos, direction)
            pos += size - opcodeBytes
      else:
        pos = opcodeBytes = 2
        appOpcode = uncompressed[pos]
        pos = pos + 1

        if (appOpcode == 0):
          pos += 1
          opcodeBytes = 3

        appOpcode = appOpcode + uncompressed[pos] * 256
        processAppPacket(callback, srcIP, dstIP, srcPort, dstPort, appOpcode, len(uncompressed) - 2 + opcodeBytes, uncompressed, pos + 1, direction)       

    # Fragment
    elif (opcode == 0x0d):
      uncompressed = uncompress(bytes, opcode, isSubPacket)

      if (FragmentSeq[direction] == -1):
        seq = getSequence(direction)
        FragmentSeq[direction] = uncompressed[0] * 256 + uncompressed[1]

        if (FragmentSeq[direction] != seq):
          if (FragmentSeq[direction] > seq):                
            if ((FragmentSeq[direction] - seq) < 1000):
              addToCache(FragmentSeq[direction], direction, bytes, isSubPacket);
            else:
              FragmentSeq[direction] = -1
              advanceSequence(direction)
              raise TypeError('Fragment: Missing expected fragment 1')
          FragmentSeq[direction] = -1
          raise StopIteration()
        else:
          advanceSequence(direction)

        FragmentedPacketSize[direction] = uncompressed[2] * 0x1000000 + uncompressed[3] * 0x10000 + uncompressed[4] * 0x100 + uncompressed[5]

        if (FragmentedPacketSize[direction] == 0 or FragmentedPacketSize[direction] > 1000000):
          FragmentSeq[direction] = -1
          raise TypeError('Got a fragmented packet of size ' + str(FragmentedPacketSize[direction]) + ' and discarding')
        else:
          FragmentedBytesCollected[direction] = len(uncompressed) - 6
          if (len(uncompressed) - 6 > FragmentedPacketSize[direction]):
            FragmentSeq[direction] = -1
            raise TypeError('Fragment: mangled fragment 1')
          else:
            Fragments[direction] = bytearray(FragmentedPacketSize[direction])
            temp = uncompressed[6:]
            Fragments[direction][0:len(temp)] = temp
      else:
        last = FragmentSeq[direction]
        FragmentSeq[direction] = uncompressed[0] * 256 + uncompressed[1]
        seq = getSequence(direction)

        if (FragmentSeq[direction] != seq):
          if (FragmentSeq[direction] > seq):
            if (FragmentSeq[direction] - seq < 1000):
              addToCache(FragmentSeq[direction], direction, bytes, isSubPacket)
            else:
              advanceSequence(direction);
              FragmentSeq[direction] = -1
              raise TypeError('Fragment: Missing expected fragment 2')
          raise StopIteration()
        else:
          advanceSequence(direction)

        if (len(uncompressed) - 2 > len(Fragments[direction]) - FragmentedBytesCollected[direction]):
          FragmentSeq[direction] = -1
          raise TypeError('Fragment: Mangled fragment 2')
        else:
          index = FragmentedBytesCollected[direction]
          lastIndex = FragmentedBytesCollected[direction] + len(uncompressed) - 2;
          Fragments[direction][index:lastIndex] = uncompressed[2:]
          FragmentedBytesCollected[direction] += len(uncompressed) - 2

          if (FragmentedBytesCollected[direction] == FragmentedPacketSize[direction]):
            if (Fragments[direction][0] == 0x00 and Fragments[1][direction] == 0x019):
              pos = 2
              while (pos < len(Fragments[direction])):
                size = 0
                if (Fragments[direction][pos] == 0xff):
                  if (Fragments[direction][pos + 1] == 0x01):
                    size = 256 + Fragments[direction][pos + 2]
                  else:
                    size = Fragments[direction][pos + 2]            
                  pos += 3
                else:
                  size = Fragments[direction][pos]
                  pos += 1

                opcodeBytes = 2
                appOpcode = Fragments[direction][pos]
                pos += 1

                if (appOpcode == 0):
                  pos += 1
                  opcodeBytes = 3

                appOpcode += Fragments[direction][pos] * 256
                pos += 1
                processAppPacket(callback, srcIP, dstIP, srcPort, dstPort, appOpcode, size - opcodeBytes, Fragments[direction], pos, direction)
                pos = pos + size - opcodeBytes
            else:
              pos = 0
              opcodeBytes = 2
              appOpcode = Fragments[direction][pos]
              pos += 1

              if (appOpcode == 0):
                pos += 1
                opcodeBytes = 3

              appOpcode += Fragments[direction][pos] * 256
              pos += 1
              lastIndex = len(Fragments[direction]) - opcodeBytes + pos
              newPacket = Fragments[direction][pos:lastIndex]
              processAppPacket(callback, srcIP, dstIP, srcPort, dstPort, appOpcode, len(newPacket), newPacket, 0, direction)
            FragmentSeq[direction] = -1

    # Unencapsulated EQ Application Opcode
    elif (opcode > 0xff):
      if (isSubPacket):
        appOpcode = bytes[1] * 256 + bytes[0]
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