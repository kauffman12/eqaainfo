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

def resetFragment(frag):
  frag['data'] = dict()
  frag['last'] = -1
  frag['seq'] = -1
  frag['size'] = 0
  return frag

ServerFragmentData = resetFragment(dict())
ClientFragmentData = resetFragment(dict())

def getFragmentData(direction):
  global ServerFragmentData, ClientFragmentData
  if direction == ClientToServer:
    return ClientFragmentData
  return ServerFragmentData

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

def findAppPacket(callback, uncompressed, timeStamp, clientToServer):
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
      callback(appOpcode, newPacket, timeStamp, clientToServer)
  else:
    callback(code, uncompressed, timeStamp, clientToServer)

def processPacket(callback, srcIP, dstIP, srcPort, dstPort, bytes, timeStamp, isSubPacket):
  global CryptoFlag
  opcode = readBUInt16(bytes)

  direction = getDirection(srcIP, dstIP, srcPort, dstPort)
  #if ((direction == UnknownDirection and opcode != 0x01) or (direction == ClientToServer and opcode != 0x02)):
  if ((direction == UnknownDirection and opcode != 0x01)):
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
      findAppPacket(callback, uncompressed[2:], timeStamp, direction == ClientToServer) 

    # Fragment
    elif (opcode == 0x0d):
      uncompressed = uncompress(bytes, isSubPacket, True)
      seq = readBUInt16(uncompressed)
      frag = getFragmentData(direction)
      if (frag['seq'] == -1):
        frag['size'] = readBUInt32(uncompressed)
        size = len(uncompressed)
        frag['seq'] = seq
        frag['data'][seq] = uncompressed
        # +4 to account for packet size read in current fragment
        # assuming a standrd length for fragments within a sequence
        frag['last'] = int(frag['size'] / (size + 4)) + frag['seq']
        # if sequence of 1 just handle it
        if frag['last'] == seq:
          if len(uncompressed) > 0:
            findAppPacket(callback, uncompressed, timeStamp, direction == ClientToServer)
          resetFragment(frag)
      else:
        # keep saving fragments 
        frag['data'][seq] = uncompressed

        total = (frag['last'] - frag['seq']) + 1
        if len(frag['data']) == total:
          data = bytearray([])
          order = sorted(frag['data'].keys())
          current = order[0]
          error = False
          for key in order:
            if current != key:
              error = True
              break
            data += frag['data'][key]
            current += 1

          if not error:
            findAppPacket(callback, data, timeStamp, direction == ClientToServer)

          resetFragment(frag)
  except TypeError as error:
    pass
  except Exception as other:  
    print(other) #traceback.print_exc()

def readPcap(callback, pcap):
  for packet in rdpcap(pcap):
    try:
      if (UDP in packet and Raw in packet and len(packet[UDP].payload) > 2):
        processPacket(callback, packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport, bytearray(packet[UDP].payload.load), packet.time, False)
    except Exception as error:
      print(error)
