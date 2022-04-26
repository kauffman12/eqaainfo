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

def printBytes(buffer): print ([hex(i) for i in buffer])

def readBUInt16(buffer):
  value = buffer[0:2]
  del buffer[0:2]
  return int.from_bytes(value, 'big', signed=False)

def readBUInt32(buffer):
  value = buffer[0:4]
  del buffer[0:4]
  return int.from_bytes(value, 'big', signed=False)

def readBytes(buffer, count, endian='little'):
  value = buffer[0:count]
  del buffer[0:count]
  if endian == 'big': value.reverse()
  return value

def readFloat32(buffer):
  value = buffer[0:4]
  del buffer[0:4]
  return float(('%.6f' % struct.unpack('<f', value)[0]).rstrip('0').rstrip('.'))

def readInt8(buffer):
  value = buffer[0:1]
  del buffer[0:1]
  return int.from_bytes(value, 'little', signed=True)

def readInt16(buffer):
  value = buffer[0:2]
  del buffer[0:2]
  return int.from_bytes(value, 'little', signed=True)

def readInt32(buffer):
  value = buffer[0:4]
  del buffer[0:4]
  return int.from_bytes(value, 'little', signed=True)

def readInt64(buffer):
  value = buffer[0:8]
  del buffer[0:8]
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
  result = ''
  count = 0

  if buffer:
    while (count < len(buffer) and buffer[count] != 0 and (not maxLength or count < maxLength)):
      count += 1
    if count > 0:
      try:
        result = buffer[0:count].decode()
      except:
        del buffer[0:count]
        return '' # something out of order

    # delete null terminator if one was found
    # some strings in EQ dont have one for some reason
    if count < len(buffer) and buffer[count] == 0:
      count += 1

    del buffer[0:count]
  return result
