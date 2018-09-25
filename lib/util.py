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