import struct

# useful when searching for new fields or when existing ones have been moved
def findIndexOf(bytes, data, size=4):
  index = -1
  start = 0
  if isinstance(data, str):
    barr = bytearray(data.encode())
  elif isinstance(data, float):
    barr = bytearray(struct.pack('f', data))
  elif isinstance(data, int):
    barr = bytearray(data.to_bytes(size, byteorder='little'))
  else:
    barr = data
  end = len(barr)
  while len(bytes) >= end:
    if barr == bytes[start:end]:
      index = start
      break
    start += 1
    end += 1
  return index

def getByteString(bytes, count):
  result = ''
  c = 0
  while c < len(bytes) and c < count:
    result += '%d ' % bytes[c]
    c += 1
  return result

def readBUInt16(buffer):
  value = buffer[0:2]
  del buffer[0:2]
  return int.from_bytes(value, 'big', signed=False)

def readBUInt32(buffer):
  value = buffer[0:4]
  del buffer[0:4]
  return int.from_bytes(value, 'big', signed=False)

def readBytes(buffer, count):
  value = buffer[0:count]
  del buffer[0:count]
  return value

def readInt8(buffer):
  value = buffer[0:1]
  del buffer[0:1]
  return int.from_bytes(value, 'little', signed=True)

def readInt32(buffer):
  value = buffer[0:4]
  del buffer[0:4]
  return int.from_bytes(value, 'little', signed=True)

def readUInt8(buffer):
  value = buffer[0:1]
  del buffer[0:1]
  return int.from_bytes(value, 'little', signed=False)

def readUInt16(buffer):
  value = buffer[0:2]
  del buffer[0:2]
  return int.from_bytes(value, 'little', signed=False)

def readUInt32(buffer):
  value = buffer[0:4]
  del buffer[0:4]
  return int.from_bytes(value, 'little', signed=False)

def readString(buffer, maxLength=0):
  result = None
  count = 0
  while (count < len(buffer) and buffer[count] != 0 and buffer[count] >= 32 and buffer[count] <= 127 and (not maxLength or count < maxLength)):
    count += 1
  if count > 0:
    try:
      result = buffer[0:count].decode()
    except:
      pass # something out of order

  # delete null terminator if one was found
  # some strings in EQ dont have one for some reason
  if buffer[count] == 0:
    count += 1

  del buffer[0:count]
  return result