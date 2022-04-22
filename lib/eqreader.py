#
# EQ Packet handling based on EQExtractor created by EQEMu Development Team
# --> Copyright (C) 2001-2010 EQEMu Development Team (http://eqemulator.net). Distributed under GPL version 2.
#
import zlib
from scapy.all import *
from lib.util import *

ClientIP = 0
ClientPort = 0
ServerIP = 0
ServerPort = 0
ClientToServer = 0
ServerToClient = 1
UnknownDirection = 2
ServerFragmentData = dict()
ClientFragmentData = dict()
MaxLength = 512
SessionId = 0

def resetFragment(frag):
  frag['data'] = dict()
  frag['last'] = -1
  frag['seq'] = -1
  frag['size'] = 0
  return frag

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
  global ClientIP, ClientPort, ServerIP, ServerPort
  direction = UnknownDirection
  if srcIP != 0 and srcIP == ServerIP and srcPort == ServerPort and dstIP == ClientIP and dstPort == ClientPort:
    direction = ServerToClient
  elif srcIP != 0 and srcIP == ClientIP and srcPort == ClientPort and dstIP == ServerIP and dstPort == ServerPort:
    direction = ClientToServer
  return direction

def findAppPacket(callback, uncompressed, timeStamp, direction):
  global ClientToServer

  clientToServer = (direction == ClientToServer)
  if readUInt16(uncompressed) == 0x1900:
    while len(uncompressed) > 3:
      if uncompressed[0] == 0xff:
        readBytes(uncompressed, 1)
        size = readBUInt16(uncompressed)
      else:
        size = readBytes(uncompressed, 1)[0]
      newPacket = readBytes(uncompressed, size)
      appOpcode = readUInt16(newPacket)
      if len(newPacket) > 0:
        callback(appOpcode, newPacket, timeStamp, clientToServer)
  else:
    if len(uncompressed) > 0:
      callback(code, uncompressed, timeStamp, clientToServer)

def processPacket(callback, srcIP, dstIP, srcPort, dstPort, bytes, timeStamp, isSubPacket):
  global MaxLength, ClientIP, ClientPort, ServerIP, ServerPort, SessionId
  if len(bytes) > MaxLength:
    return

  opcode = readBUInt16(bytes)
  direction = getDirection(srcIP, dstIP, srcPort, dstPort)

  if direction == UnknownDirection and opcode not in [0x01, 0x02]:
    return

  try:
    # Session Request
    if opcode == 0x01:
      if len(bytes) == 22:
        readBytes(bytes, 4)
        SessionId = readBUInt32(bytes)

    # Session Response
    elif opcode == 0x02:
      if len(bytes) == 19:
        session = readBUInt32(bytes)
        readBytes(bytes, 7)
        maxLen = readBUInt32(bytes)
        # should always be 512 but they could raise it
        if session == SessionId and (maxLen >= 512 and maxLen <= 4096):
          MaxLength = maxLen
          ClientIP = dstIP
          ClientPort = dstPort
          ServerIP = srcIP
          ServerPort = srcPort
          resetFragment(ServerFragmentData)
          resetFragment(ClientFragmentData)

    # Disconnect
    elif opcode == 0x05:
      if len(bytes) == 9:
        SessionId = 0
        ClientIP = 0
        ClientPort = 0
        ServerIP = 0
        ServerPort = 0

    # Combined 
    elif opcode == 0x03:
      uncompressed = uncompress(bytes, isSubPacket, False)
      while (len(uncompressed) > 2):
        size = readUInt8(uncompressed)
        newPacket = readBytes(uncompressed, size)
        processPacket(callback, srcIP, dstIP, srcPort, dstPort, newPacket, timeStamp, True)

    # Packet
    elif opcode == 0x09:
      uncompressed = uncompress(bytes, isSubPacket, True)
      findAppPacket(callback, uncompressed[2:], timeStamp, direction) 

    # Fragment
    elif opcode == 0x0d:
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
            findAppPacket(callback, uncompressed, timeStamp, direction)
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
            findAppPacket(callback, data, timeStamp, direction)

          resetFragment(frag)
    else:
      if (opcode & 0xff00) != 0:
        pass # unhandled app opcodes

  except Exception as other:  
    print(other) #traceback.print_exc()

def readPcap(callback, pcap):
  for packet in rdpcap(pcap):
    try:
      if (UDP in packet and Raw in packet and len(packet[UDP].payload) > 2):
        processPacket(callback, packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport, bytearray(packet[UDP].payload.load), packet.time, False)
    except Exception as error:
      print(error)
