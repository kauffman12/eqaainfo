#
# EQ Packet handling.
#
import zlib
from scapy.all import *
from lib.util import *

Clients = dict()
ServerIPs = dict()

def addClient(clientIP, clientPort, serverIP, serverPort, maxLength, s, sKey):
  global ServerIPs
  Clients[clientPort] = dict()
  Clients[clientPort]['clientIP'] = clientIP
  Clients[clientPort]['serverIP'] = serverIP
  Clients[clientPort]['serverPort'] = serverPort
  Clients[clientPort]['serverFrags'] = dict()
  Clients[clientPort]['clientFrags'] = dict()
  Clients[clientPort]['maxLength'] = maxLength
  Clients[clientPort]['session'] = s
  Clients[clientPort]['sKey'] = sKey
  ServerIPs[serverIP] = True

def isValidCRC(client, opcode, bytes, isSubPacket):
  valid = True
  if not isSubPacket:
    # crc of session key and original packet minus received checksum
    packet = client['sKey'][:] + opcode.to_bytes(2, 'big') + bytes[0:-2]
    crc = (zlib.crc32(packet) & 0xffff)
    valid = (crc == readBUInt16(bytes[-2:]))
  return valid

def getFragmentData(client, direction):
  if direction == 'clientToServer': return client['clientFrags']
  return client['serverFrags']

def uncompress(opcode, bytes, isSubPacket):
  uncompressed = bytes
  if not isSubPacket and bytes[0] == 0x5a:
    uncompressed = bytearray(zlib.decompress(bytes[1:]))
  elif not isSubPacket and bytes[0] == 0xa5:
    uncompressed = bytes[1:]
    if opcode != 0x03: uncompressed = uncompressed[:-2]
  return uncompressed

def findAppPacket(callback, bytes, timeStamp, clientToServer, port):
  appoc = readUInt16(bytes)
  if appoc == 0x1900:
    while len(bytes) > 3:
      size = readUInt8(bytes)
      if size == 0xff: size = readBUInt16(bytes)
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
  global Clients, ServerIPs, UnknownDirection

  client = None
  clientPort = -1
  direction = 'unknown'
  if srcIP in ServerIPs and dstPort in Clients:
    clientPort = dstPort
    client = Clients[clientPort]
    direction = 'serverToClient'
  elif dstIP in ServerIPs and srcPort in Clients:
    clientPort = srcPort
    client = Clients[clientPort]
    direction = 'clientToServer'

  # packet exceeds max length
  if client and len(bytes) > client['maxLength']: return

  # do nothing until sessions request/response is seen
  opcode = readBUInt16(bytes)
  if direction == 'unknown' and opcode not in [0x01, 0x02]: return
  clientToServer = (direction == 'clientToServer')

  try:
    # Session Request
    if opcode == 0x01:
      if len(bytes) == 22:
        readBytes(bytes, 4)
        session = readBUInt32(bytes)
        # use this to setup the initial session
        addClient(srcIP, srcPort, dstIP, dstPort, 512, session, 0)

    # Session Response
    elif opcode == 0x02:
      if len(bytes) == 19:
        session = readBUInt32(bytes)
        sKey = readBytes(bytes, 4, 'big')
        readBytes(bytes, 3)
        maxLen = readBUInt32(bytes)
        if dstPort in Clients and Clients[dstPort]['session'] == session:
          # should just update the client added during the request
          addClient(dstIP, dstPort, srcIP, srcPort, maxLen, session, sKey)
          getFragmentData(Clients[dstPort], 'clientToServer')['data'] = dict()
          getFragmentData(Clients[dstPort], 'serverToClient')['data'] = dict()
          # using this as a reset message for any cached data
          callback(opcode, bytearray([]), timeStamp, False, port)

    # Disconnect
    elif opcode == 0x05:
      if len(bytes) == 9:
        del Clients[clientPort]
        del ServerIPs[srcIP]

    # Combined 
    elif opcode == 0x03:
      if client and isValidCRC(client, opcode, bytes, False):
        uncompressed = uncompress(opcode, bytes, False)
        while (len(uncompressed) > 6):
          size = readUInt8(uncompressed)
          subPacket = readBytes(uncompressed, size)
          processPacket(callback, srcIP, dstIP, srcPort, dstPort, subPacket, timeStamp, True)

    # Packet
    elif opcode == 0x09:
      if client and isValidCRC(client, opcode, bytes, isSubPacket):
        data = uncompress(opcode, bytes, isSubPacket)
        seq = readBUInt16(data)
        findAppPacket(callback, data, timeStamp, clientToServer, clientPort) 

    # Fragment
    elif opcode == 0x0d:
      if client and isValidCRC(client, opcode, bytes, isSubPacket):
        frag = getFragmentData(client, direction)
        uncompressed = uncompress(opcode, bytes, isSubPacket)
        seq = readBUInt16(uncompressed)
        frag['data'][seq] = {'part': uncompressed, 'time': timeStamp}

        # remove stale data and assume it's bad
        # sending things too out of time order will cause problems
        for key in sorted(frag['data'].keys()):
          if (timeStamp - frag['data'][key]['time']) > 60:
            del frag['data'][key]
          else:
            # seq sort should also be time sort
            break

        found = False
        size = -1
        data = bytearray([])
        order = sorted(frag['data'].keys())
        current = order[0]
        start = order[0]

        for key in order:
          if current != key:
            break
          data += frag['data'][key]['part']
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
          findAppPacket(callback, data, timeStamp, clientToServer, clientPort)
    else:
      pass
      # not sure these are useful for item or AA parsing
      #if (opcode & 0xff00) != 0: # other application level
      #  if client and isValidCRC(client, opcode, bytes, isSubPacket):
      #    findAppPacket(callback, bytes, timeStamp, clientToServer, clientPort)

  except Exception as other:  
    print(other) # traceback.print_exc()

def readPcap(callback, pcap):
  for packet in rdpcap(pcap):
    try:
      if (UDP in packet and Raw in packet and len(packet[UDP].payload) > 2):
        processPacket(callback, packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport, bytearray(packet[UDP].payload.load), packet.time, False)
    except Exception as error:
      print(error)
