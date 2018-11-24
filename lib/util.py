# useful when searching for new fields or when existing ones have been moved
def findIndexOf(bytes, data, size=4):
  index = -1
  start = 0
  if isinstance(data, str):
    barr = bytearray(data.encode())
  else:
    barr = bytearray(data.to_bytes(size, byteorder='little'))
  end = len(barr)
  while len(bytes) >= end:
    if barr == bytes[start:end]:
      index = start
      break
    start += 1
    end += 1
  return index

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

def readString(buffer):
  result = None
  count = 0
  while (buffer[count] != 0 and buffer[count] >= 32 and buffer[count] <= 127):
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