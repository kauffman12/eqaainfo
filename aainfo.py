# Script for reading network stream from PCAP recording and attempting to parse Everquest AA data
# Currently working with Test Server version on 9/11/2018
#
# EQ Packet handling based on EQExtractor created by EQEMu Development Team
# --> Copyright (C) 2001-2010 EQEMu Development Team (http://eqemulator.net). Distributed under GPL version 2.
# 

import re
import zlib
from scapy.all import *

AATableOpcode = 0x41a4
OutputFile = 'aainfo.txt'
DBStringsFile = 'data/dbstr_us.txt'
Debug = False

Cache = dict()
DBStrings = dict()
ClientToServer = 0
ServerToClient = 1
UnknownDirection = 2
FragmentSeq = [-1, -1]
FragmentedPacketSize = [0, 0]
FragmentedBytesCollected = [0, 0]
Fragments = [[]] * 2

def readByte(buffer):
  value = buffer[0]
  del buffer[0]
  return value

def readBytes(buffer, count):
  value = buffer[0:count]
  del buffer[0:count]
  return value

def readInt32(buffer):
  value = buffer[0:4]
  del buffer[0:4]
  return int.from_bytes(value, 'little', signed=True)

def readUInt16(buffer):
  value = buffer[0:2]
  del buffer[0:2]
  return int.from_bytes(value, 'little', signed=False)

def readUInt32(buffer):
  value = buffer[0:4]
  del buffer[0:4]
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

# Pulls all Titles from EQ DB file. Example/Format: 16366^1^Sorcerer's Vengeance^0^
def loadDBStrings():
  db = open(DBStringsFile, 'r')
  for line in db:
    result = re.match(r'^(\d+)\^[1]\^([\w\s\'\-\(\)\:]+?)\^[0]\^$', line)
    if (result != None):
      DBStrings[int(result.group(1))] = result.group(2)

def addToCache(seq, direction, bytes, isSubPacket):
  key = 'seq=%d&dir=%d' % (seq, direction)
  if (Cache.get(key) == None):
    Cache[key] = {
      'seq': seq,
      'direction': direction,
      'bytes': bytes,
      'isSubPacket': isSubPacket
    }

def processCache(output, direction):
  seq = getSequence(direction)
  key = 'seq=%d&dir=%d' % (seq, direction)
  entry = Cache.get(key)

  if (entry != None):
    if (direction == ServerToClient):
      handlePacket(output, ServerIP, ClientIP, ServerPort, ClientPort, entry['bytes'], entry['isSubPacket'], True)
    elif (direction == ClientToServer):
      handlePacket(output, ClientIP, ServerIP, ClientPort, ServerPort, entry['bytes'], entry['isSubPacket'], True)
    del Cache[key]
    processCache(output, direction)

def handleAppPacket(output, srcIP, dstIP, srcPort, dstPort, opcode, size, bytes, pos, direction):
  result = False

  if (opcode == AATableOpcode and getDirection(srcIP, dstIP, srcPort, dstPort) == ServerToClient):
    buffer = list(bytes[pos:])
    descID = readInt32(buffer)
    readByte(buffer)
    hotKeySID = readInt32(buffer)
    hotKeySID2 = readInt32(buffer)
    titleSID = readUInt32(buffer)
    descSID2 = readInt32(buffer)
    reqLevel = readUInt32(buffer)
    cost = readUInt32(buffer)
    aaID = readUInt32(buffer)
    rank = readUInt32(buffer)

    reqSkills = readUInt32(buffer)
    for s in range(reqSkills):
      readUInt32(buffer)
    reqPts = readUInt32(buffer)
    for p in range(reqPts):
      readUInt32(buffer)

    type = readUInt32(buffer)
    spellID = readInt32(buffer)
    readUInt32(buffer) # unknown
    abilityTimer = readUInt32(buffer)
    refreshTime = readUInt32(buffer)
    classMask = readUInt16(buffer)
    berserkerMask = readUInt16(buffer)
    maxRank = readUInt32(buffer)
    prevDescSID = readInt32(buffer)
    nextDescSID = readInt32(buffer)
    totalCost = readUInt32(buffer)
    readBytes(buffer, 10) # unknown
    expansion = readUInt32(buffer)
    specialCat = readInt32(buffer)
    readBytes(buffer, 13) # unknown
    spaCount = readUInt32(buffer)

    # lookup Title from DB
    title = DBStrings.get(titleSID)
    if (title == None):
      title = titleSID

    output.write('Ability: \t%s\r\n' % title)
    output.write('Ability ID: \t%d\r\n' % aaID)
    output.write('Expansion: \t%d\r\n' % expansion)
    output.write('Level: \t\t%d\r\n' % reqLevel)
    output.write('Rank: \t\t%d / %d\r\n' % (rank, maxRank))
    output.write('Rank Cost: \t%d AAs\r\n' % cost)
    output.write('Reuse Time: \t%ds\r\n' % refreshTime)

    if (spellID > 0):
      output.write('Spell ID: \t%d\r\n' % spellID)
    output.write('Total Cost: \t%d AAs\r\n' % totalCost) 
    if (spaCount > 0):
      output.write('Found %d SPAs:\r\n' % spaCount)

    for t in range(spaCount):
      spa = readUInt32(buffer)
      base1 = readInt32(buffer)
      base2 = readInt32(buffer)
      slot = readUInt32(buffer)
      output.write('\t\tSlot:\t%d\tSPA:\t%d\tBase1:\t%d\tBase2:\t%d\r\n' % (slot, spa, base1, base2))

    output.write('\r\n')
    result = True
  return result

def handlePacket(output, srcIP, dstIP, srcPort, dstPort, bytes, isSubPacket, isCached):
  global CryptoFlag, FragmentSeq, Fragments, FragmentedPacketSize, FragmentedBytesCollected
  opcode = bytes[0] * 256 + bytes[1]
  result = False

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
        handlePacket(output, srcIP, dstIP, srcPort, dstPort, newPacket, True, isCached)

    # Packet
    elif (opcode == 0x09):
      uncompressed = uncompress(bytes, opcode, isSubPacket)
      seq = uncompressed[0] * 256 + uncompressed[1]
      expected = getSequence(direction)

      if (seq != expected and seq > expected):
        if (seq - expected < 1000):
          addToCache(seq, direction, bytes, isSubPacket)
        else:
          FragmentSeq[direction] = -1
          advanceSequence(direction)
        raise TypeError('Packet:\t\t missing expected fragment')
      else:
        advanceSequence(direction)

      if (uncompressed[2] == 0x00 and uncompressed[3] == 0x19):
        pos = 4
        while (pos < len(uncompressed) - 2):
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
            result = handleAppPacket(output, srcIP, dstIP, srcPort, dstPort, appOpcode, size - opcodeBytes, uncompressed, pos, direction)
            pos += size - opcodeBytes
      else:
        pos = opcodeBytes = 2
        appOpcode = uncompressed[pos]
        pos = pos + 1

        if (appOpcode == 0):
          pos += 1
          opcodeBytes = 3

        appOpcode = appOpcode + uncompressed[pos] * 256
        result = handleAppPacket(output, srcIP, dstIP, srcPort, dstPort, appOpcode, len(uncompressed) - 2 + opcodeBytes, uncompressed, pos + 1, direction)       

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
          FragmentSeq[direction] = -1
          raise TypeError('Fragment:\t missing expected fragment')
        else:
          advanceSequence(direction)

        FragmentedPacketSize[direction] = uncompressed[2] * 0x1000000 + uncompressed[3] * 0x10000 + uncompressed[4] * 0x100 + uncompressed[5]

        if (FragmentedPacketSize[direction] == 0 or FragmentedPacketSize[direction] > 1000000):
          FragmentSeq[direction] = -1
        else:
          FragmentedBytesCollected[direction] = len(uncompressed) - 6
          if (len(uncompressed) - 6 > FragmentedPacketSize[direction]):
            FragmentSeq[direction] = -1
            raise TypeError('Fragment:\t Mangled fragment 1')
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
          raise TypeError ('Fragment:\t missing expected fragment')
        else:
          advanceSequence(direction)

        if (len(uncompressed) - 2 > len(Fragments[direction]) - FragmentedBytesCollected[direction]):
          FragmentSeq[direction] = -1
          raise TypeError ('Fragment:\t Mangled fragment 2')
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
                result = handleAppPacket(output, srcIP, dstIP, srcPort, dstPort, appOpcode, size - opcodeBytes, Fragments[direction], pos, direction)
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
              result = handleAppPacket(output, srcIP, dstIP, srcPort, dstPort, appOpcode, len(newPacket), newPacket, 0, direction)
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
      result = handleAppPacket(output, srcIP, dstIP, srcPort, dstPort, appOpcode, len(newPacket), newPacket, 0, direction)
  except TypeError as error:
    if (Debug):
      print(error)

  if (not isCached and len(Cache) > 0):
    processCache(output, ServerToClient)
    processCache(output, ClientToServer)
  return result

def main(args):
  if (len(args) < 2):
    print ('Usage: ' + args[0] + ' <pcap file>')
  else:
    try:
      print('Loading Strings DB from %s' % DBStringsFile)
      loadDBStrings()

      size = len(DBStrings)
      if (size > 0):
        print('Found %d entries' % len(DBStrings))
      else:
        print('No data found, copy over latest from your EQ directory?')
    except Exception as error:
      print(error)

    output = open(OutputFile, 'w')
    print('Reading %s' % args[1])

    try:
      count = 0
      packets = rdpcap(args[1])
      for packet in packets:
        if (UDP in packet and len(packet[UDP].payload) > 2):
          result = handlePacket(output, packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport, packet[UDP].payload.load, False, False)
          if (result):
            count += 1

      print('Saved data for %d AAs to %s' % (count, OutputFile))
    except Exception as error:
      print(error)
    output.close()
main(sys.argv)