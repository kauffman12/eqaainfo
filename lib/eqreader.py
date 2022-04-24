#
# EQ Packet handling. EQExtractor created by EQEMu Development Team used
# as a reference but it's been completely reworked at this point.
#
import zlib
from scapy.all import *
from lib.util import *

Clients = dict()
ClientToServer = 0
ServerToClient = 1
UnknownDirection = 2
ServerIPList = []

def addClient(clientIP, clientPort, serverIP, serverPort, maxLength, session):
  global ServerIPList
  Clients[clientPort] = dict()
  Clients[clientPort]['clientIP'] = clientIP
  Clients[clientPort]['serverIP'] = serverIP
  Clients[clientPort]['serverPort'] = serverPort
  Clients[clientPort]['serverFrags'] = dict()
  Clients[clientPort]['clientFrags'] = dict()
  Clients[clientPort]['maxLength'] = maxLength
  Clients[clientPort]['session'] = session
  ServerIPList.append(serverIP)

def getFragmentData(client, direction):
  if direction == ClientToServer:
    return client['clientFrags']
  return client['serverFrags']

def uncompress(bytes, isSubPacket, isCombined):
  if (not isSubPacket and bytes[0] == 0x5a):
    uncompressed = bytearray(zlib.decompress(bytes[1:]))
  elif (not isSubPacket and bytes[0] == 0xa5):
    uncompressed = bytes[1:]
    if not isCombined:
      uncompressed = uncompressed[:-2]
  else:
    uncompressed = bytes
  return uncompressed

def findAppPacket(callback, bytes, timeStamp, direction, port):
  global ClientToServer
  appoc = readUInt16(bytes)
  clientToServer = (direction == ClientToServer)
  if appoc == 0x1900:
    while len(bytes) > 3:
      size = readUInt8(bytes)
      if size == 0xff:
        size = readBUInt16(bytes)
      newPacket = readBytes(bytes, size)
      appoc = readUInt16(newPacket)
      if appoc == 0:
        appoc = (readUInt8(newPacket) << 8)
      if len(newPacket) > 0:
        callback(appoc, newPacket, timeStamp, clientToServer, port)
  else:
    if len(bytes) > 0:
      callback(appoc, bytes, timeStamp, clientToServer, port)

def processPacket(callback, srcIP, dstIP, srcPort, dstPort, bytes, timeStamp, isSubPacket):
  global Clients, ServerIPList, UnknownDirection

  client = None
  clientPort = -1
  direction = UnknownDirection

  if srcIP in ServerIPList and dstPort in Clients:
    clientPort = dstPort
    client = Clients[clientPort]
    direction = ServerToClient
  elif dstIP in ServerIPList and srcPort in Clients:
    clientPort = srcPort
    client = Clients[clientPort]
    direction = ClientToServer

  if client and len(bytes) > client['maxLength']:
    return

  opcode = readBUInt16(bytes)
  if direction == UnknownDirection and opcode not in [0x01, 0x02]:
    return

  try:
    # Session Request
    if opcode == 0x01:
      if len(bytes) == 22:
        readBytes(bytes, 4)
        session = readBUInt32(bytes)
        addClient(srcIP, srcPort, dstIP, dstPort, 512, session)

    # Session Response
    elif opcode == 0x02:
      if len(bytes) == 19:
        session = readBUInt32(bytes)
        readBytes(bytes, 7)
        maxLen = readBUInt32(bytes)
        if dstPort in Clients and Clients[dstPort]['session'] == session:
          # max length should always be 512 but they could raise it
          addClient(dstIP, dstPort, srcIP, srcPort, maxLen, session)
          getFragmentData(Clients[dstPort], ClientToServer)['data'] = dict()
          getFragmentData(Clients[dstPort], ServerToClient)['data'] = dict()

    # Disconnect
    elif opcode == 0x05:
      if len(bytes) == 9:
        del Clients[clientPort]
        ServerIPList.remove(srcIP)

    # Combined 
    elif opcode == 0x03:
      uncompressed = uncompress(bytes, isSubPacket, True)
      while (len(uncompressed) > 2):
        size = readUInt8(uncompressed)
        newPacket = readBytes(uncompressed, size)
        processPacket(callback, srcIP, dstIP, srcPort, dstPort, newPacket, timeStamp, True)

    # Packet
    elif opcode == 0x09:
      if client:
        uncompressed = uncompress(bytes, isSubPacket, False)
        seq = readBUInt16(uncompressed)
        findAppPacket(callback, uncompressed, timeStamp, direction, clientPort) 

    # Fragment
    elif opcode == 0x0d:
      if client:
        frag = getFragmentData(client, direction)
        uncompressed = uncompress(bytes, isSubPacket, False)
        seq = readBUInt16(uncompressed)
        frag['data'][seq] = uncompressed
        found = False
        size = -1
        data = bytearray([])
        order = sorted(frag['data'].keys())
        current = order[0]
        start = order[0]

        for key in order:
          if current != key:
            break
          data += frag['data'][key]
          if size == -1:
            # temp read off size
            size = readBUInt32(data[0:4])

          if len(data) == (size + 4):
            # ok really remove the size
            readBUInt32(data)
            found = True
            # cleanup
            for i in range((current - start + 1)):
              del frag['data'][start + i]
            break
          current += 1

        if found:
          findAppPacket(callback, data, timeStamp, direction, clientPort)
          # there shouldn't be too many unhandled packets after
          # a group has successfully been found
          if len(frag['data']) > 5:
            remaining = bytearray([])
            for r in sorted(frag['data'].keys()):
              remaining += frag['data']
            findAppPacket(callback, remaining, timeStamp, direction, clientPort)
            frag['data'] = dict()

    else:
      if (opcode & 0xff00) != 0:
        findAppPacket(callback, bytes, timeStamp, direction, clientPort)
        pass # unhandled app opcodes

  except Exception as other:  
    print(other) # traceback.print_exc()

def readPcap(callback, pcap):
  for packet in rdpcap(pcap):
    try:
      if (UDP in packet and Raw in packet and len(packet[UDP].payload) > 2):
        processPacket(callback, packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport, bytearray(packet[UDP].payload.load), packet.time, False)
    except Exception as error:
      print(error)
