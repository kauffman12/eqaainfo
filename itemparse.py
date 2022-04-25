#
# Script to parse pcap output for items.
# Saves in an old format similar to what EQ websites rely on so
# others are more familiar with the data output
#

import io
import json
import signal
import sys
import traceback
from datetime import date
from scapy.all import *

from lib.util import *
from lib.eqdata import *
from lib.eqreader import *

FORMAT = 'EQR'
CharmCache = dict()
ClientData = dict()
Columns = []
ColumnsFile = 'columns.txt'
ExtraInfo = dict()
IdNameCache = dict()
ItemData = dict()
MadeBy = dict()
OutputFile = 'items'
ReadingFile = False
SortByTime = True
StartTime = ''
TimeRangeFormat = '%d%m%y%H%M%S'
UpdateTime = dict()
UpdateTimeFormat = '%Y-%m-%d %H:%M:%S'

class ParseError (Exception):
  pass

def getClientData(port):
  global ClientData
  if port in ClientData:
    return ClientData[port]

  ClientData[port] = dict()
  ClientData[port]['extraOpcode'] = -1
  ClientData[port]['charmOpcode'] = -1
  ClientData[port]['charmFiles'] = []
  return ClientData[port]

def readItem(bytes):
  global IdNameCache, CharmCache
  data = []

  convertToName = ''
  convertToId = 0
  evolveId = 0
  evolveLevel = 0
  evolveMaxLevel = 0

  readUInt8(bytes)                    # quantity
  readBytes(bytes, 58)                # unknown

  # can be converted / name length
  convertable = readUInt32(bytes)
  if convertable > 0:
    convertToName = readString(bytes, convertable)
  convertToId = readInt64(bytes)

  # is evolving item
  evolvable = readUInt8(bytes)
  if evolvable:
    evolveId = readInt32(bytes)
    evolveLevel = readUInt8(bytes)
    readBytes(bytes, 3)
    readBytes(bytes, 8)               # how far into level?
    evolveMaxLevel = readUInt8(bytes)
    readBytes(bytes, 7)
    if evolveLevel > evolveMaxLevel: 
      raise ParseError

  readBytes(bytes, 33)                # unknown

  # main item structure starts here 
  itemClass = readUInt8(bytes)
  if itemClass > 2:
    raise ParseError
  data.append(itemClass)

  # handle name and throw error if invalid since is the
  # most common sign that we're not at the right place
  # in the item data structure
  name = readString(bytes)
  if not name or len(name) < 2 or len(name) > 254 or not name.isprintable():
    raise ParseError # parsing error
  data.append(name)

  data.append(readString(bytes))      # item lore
  data.append(readInt32(bytes))       # idfile
  data.append(readInt32(bytes))       # idfile2

  # handle if and also throw errors if one does not exist
  id = readInt32(bytes)
  if not id: raise ParseError
  data.append(id)

  data.append(readInt32(bytes))       # weight

  # FYI this just handles 4 fields in a single loop since they're all
  # the same size. the key names aren't important but they'll describe
  # the field being handled at that index instead of adding code comments
  for misc in ['norent', 'notrade', 'attunable', 'size']:
    data.append(readInt8(bytes))

  for misc in ['inventory slots the item fits', 'sell price', 'icon id']:
    data.append(readUInt32(bytes))

  for misc in ['benefit flag?', 'used in tradeskills']:
    data.append(readInt8(bytes))

  for resist in ['cold', 'disease', 'poison', 'magic', 'fire', 'corrupt']:
    data.append(readInt8(bytes))

  for stat in ['str', 'sta', 'agi', 'dex', 'cha', 'int', 'wis']:
    data.append(readInt8(bytes))

  for bigstat in ['hp', 'mana', 'end', 'ac', 'hpReg', 'manaReg', 'endReg']:
    data.append(readInt32(bytes))
  
  # class restrictions
  reqClasses = readUInt32(bytes)
  if reqClasses > 131072: raise ParseError   # account for mercs
  data.append(reqClasses)

  # race restrictions
  reqRaces = readUInt32(bytes)
  if reqRaces > 131072: raise ParseError     # 1 higher than max
  data.append(reqRaces)

  # deity restrictions
  reqDeity = readUInt32(bytes)
  if reqDeity > 131072: raise ParseError     # 1 higher than max
  data.append(reqDeity)

  # dodge/tradeskill/etc
  for skillMod in ['percent amount', 'max', 'skill', 'other']:
    data.append(readInt32(bytes))

  # bane damage stuff
  for bane in ['race', 'body', 'race amount', 'body amount']:
    data.append(readInt32(bytes))

  # if a magic item
  data.append(readInt8(bytes))

  for misc in ['food/drink duration', 'req level', 'rec level']:
    data.append(readUInt32(bytes))

  # some extra error checking for level requirements
  if data[len(data) - 1] > 254 or data[len(data) - 2] > 254:
    raise ParseError

  data.append(readUInt32(bytes))      # bard type?
  data.append(readInt32(bytes))       # bard value?
  data.append(readInt8(bytes))        # light level

  for weaponStuff in ['weapon delay', 'element type', 'element damage']:
    data.append(readInt8(bytes))

  data.append(readUInt8(bytes))       # weapon range
  data.append(readInt32(bytes))       # weapon damage

  for misc in ['color', 'prestige']:  # prestige is often expansion
    data.append(readUInt32(bytes))

  data.append(readUInt8(bytes))       # item type (book/general)

  for mat in [ 'type', 'unknown', 'elite', 'heroes forge', 'heroes forge' ]:
    data.append(readInt32(bytes))

  data.append(readFloat32(bytes))     # sell rate

  # damage mod 8 = backstab, 10 = base, 26 = flying kick, 30 = kick, etc
  for damageMod in ['type', 'damage']:
    data.append(readInt32(bytes))

  data.append(readUInt32(bytes))      # charm file id
  data.append(readString(bytes))      # charm file

  for forAugs in ['type 7/8/etc', 'some restriction', 'type 1h/2h/range']: 
    data.append(readUInt32(bytes))

  # there are 6 possible aug slots in an item
  for augSlots in range(6):
    # type (3/4/8/etc)
    slot = readUInt32(bytes)
    if slot > 32: raise ParseError

    data.append(slot)
    data.append(readUInt8(bytes))     # visible?
    data.append(readUInt8(bytes))     # unknown

  for ldonStuff in ['point type', 'theme', 'buy price', 'sell rate', 'sell price']:
    data.append(readUInt32(bytes))

  for containerInfo in ['type', 'capacity', 'maxItems', 'weightReduction']:
    data.append(readUInt8(bytes))

  for book in ['type', 'language']:
    data.append(readInt8(bytes))

  data.append(readString(bytes))      # book filename
  data.append(readInt32(bytes))       # lore group

  data.append(readInt8(bytes))        # artifact
  data.append(readUInt32(bytes))      # tribute
  data.append(readInt8(bytes))        # fv nodrop

  for mods in ['attack', 'haste']:
    data.append(readInt32(bytes))

  for misc in ['guild tribute', 'aug distiller needed']:
    data.append(readUInt32(bytes))

  data.append(readUInt32(bytes))      # UNKNOWN 01 | -1
  data.append(readUInt32(bytes))      # UNKNOWN 02 |  0
  data.append(readInt8(bytes))        # nopet
  data.append(readUInt8(bytes))       # UNKNOWN 03
  data.append(readUInt32(bytes))      # stack size
  data.append(readInt8(bytes))        # notransfer
  data.append(readInt8(bytes))        # expendable arrow

  # unknown section that's always zeros
  for unknown in range(19):
    data.append(readUInt32(bytes))    # UNKNOWN 04 to 22 

  data.append(readUInt16(bytes))      # UNKNOWN 23

  # 7 clickie/focus effects/worn/etc
  for ecount in range(7):
    data.append(readInt32(bytes))     # spell ID  
    data.append(readUInt8(bytes))     # required level
    data.append(readInt8(bytes))      # type
    data.append(readInt32(bytes))     # spell level
    data.append(readInt32(bytes))     # charges
    data.append(readUInt32(bytes))    # cast time
    data.append(readUInt32(bytes))    # recast delay
    data.append(readInt32(bytes))     # recast type
    data.append(readInt32(bytes))     # proc mod
    data.append(readString(bytes))    # name
    data.append(readInt32(bytes))     # not used?
  data.append(readInt32(bytes))       # right click script id

  data.append(readInt8(bytes))        # quest item
  data.append(readUInt32(bytes))      # power source cap
  data.append(readUInt32(bytes))      # purity
  data.append(readUInt32(bytes))      # backstab damage

  for heroic in ['str', 'int', 'wis', 'agi', 'dex', 'sta', 'cha']:
    data.append(readInt32(bytes))

  for mods in ['healAmount', 'spellDmg', 'clairvoyance']:
    data.append(readInt32(bytes))

  # some clickie type field
  # 2 = cure pot, 5 = celestial heal pot, 7 = dragon magic, 17 = fast mounts
  data.append(readInt8(bytes))        # UNKNOWN 24

  data.append(readUInt32(bytes))      # UNKNOWN 25
  data.append(readUInt32(bytes))      # UNKNOWN 26
  data.append(readInt8(bytes))        # heirloom
  data.append(readUInt8(bytes))       # placeable

  for unknown in range(7):
    data.append(readUInt32(bytes))    # UNKNOWN 27 to 33

  data.append(readString(bytes))      # placeable npc name

  for unknown in range(7):
    data.append(readUInt32(bytes))    # UNKNOWN 34 to 40

  for misc in ['collectable', 'nodestroy', 'nonpc', 'nozone']:
    data.append(readInt8(bytes))

  for unknown in range(4):
    data.append(readUInt8(bytes))      # UNKNOWN 41 to 44

  # unk45 is always zero?
  for misc in ['noground', 'UNKNOWN 45', 'marketplace', 'freestorage']:
    data.append(readInt8(bytes))

  data.append(readUInt8(bytes))        # UNKNOWN 46
  data.append(readUInt32(bytes))       # UNKNOWN 47
  data.append(readUInt32(bytes))       # UNKNOWN 48

  minLuck = readInt32(bytes)           # min luck
  maxLuck = readInt32(bytes)           # max luck
  if minLuck < 0 or minLuck > 500 or maxLuck < 0 or maxLuck > 500:
    raise ParseError
  data.append(minLuck)
  data.append(maxLuck)

  data.append(readInt32(bytes))        # lore equipped

  # add evolving related fields
  data.append(evolvable)
  data.append(evolveId)
  data.append(evolveLevel)
  data.append(evolveMaxLevel)

  # add item convertable fields
  data.append(convertable)
  data.append(convertToId)
  data.append(convertToName)

  # add default value for charm text 
  data.append('')

  # add default value for extra item info
  data.append('')

  # add default value for madeby field
  data.append('')

  # add default value for update time
  data.append('')

  # cache id and names for testing requests
  IdNameCache[data[5]] = data[1]

  # charm file cache
  if data[71] and data[71] not in CharmCache:
    CharmCache[data[71]] = ''
  return data

# instead of relying on opcodes look for 16 character printable strings that seem to go along
# with each item entry and try to parse them
def handleEQPacket(opcode, bytes, timeStamp, clientToServer, clientPort):
  global ItemData, IdNameCache, MadeBy, ReadingFile, ExtraInfo, CharmCache

  client = getClientData(clientPort)

  if clientToServer:
    handled = False
    if len(bytes) > 22:
      charmFile = readString(bytes[22:])
      if charmFile and charmFile in CharmCache:
        handled = True
        client['charmOpcode'] = opcode 
        client['charmFiles'].append(charmFile)
    if not handled and len(bytes) > 9:
      id = readUInt32(bytes)
      code = readUInt32(bytes)
      # madeby
      if code < 64:
        nameLen = readUInt32(bytes)
        if nameLen > 0:
          name = readString(bytes)
          if name and len(name) == nameLen and id in IdNameCache and IdNameCache[id] == name:
            if id not in ExtraInfo:
              # use this to know a madeby request has been made
              client['extraOpcode'] = opcode
              ExtraInfo[id] = ''
  else:
    if opcode == client['charmOpcode']:
      if len(client['charmFiles']) > 0:
        charmFileNext = client['charmFiles'].pop(0)
      else:
        charmFileNext = ''

    if opcode == client['charmOpcode'] and len(bytes) > 20 and len(charmFileNext) > 0:
      code = readInt32(bytes)
      space = readInt32(bytes)
      space2 = readInt16(bytes)
      if (code >= 0 and code <= 32) and space == -1 and space2 == -1:
        chrmtxt = readString(bytes[12:])
        if chrmtxt and len(chrmtxt) > 1 and charmFileNext in CharmCache and CharmCache[charmFileNext] != chrmtxt:
          CharmCache[charmFileNext] = chrmtxt 
          if not ReadingFile:
            print('Update charmtext %s to %s' % (charmFileNext, chrmtxt))
      else:
        print('Error: code = %d' % code)
    # item info opcode
    elif opcode == client['extraOpcode'] and len(bytes) > 9:
      id = readUInt32(bytes[0:4])
      if id > 0 and id in ExtraInfo:
        sp = readUInt16(bytes[4:6])
        nameLen = readUInt32(bytes[6:10])
        # true for madeby
        if sp == 0 and nameLen > 0:
          name = readString(bytes[10:])
          if len(name) == nameLen:
            remain = bytes[10+nameLen:]
            sp = readUInt32(remain)
            one = readUInt32(remain)
            sp2 = readUInt32(remain)
            sp3 = readUInt8(remain)
            if sp == 0 and one == 1 and sp2 == 0 and sp3 == 0 and not len(remain):
              if (id not in MadeBy) or (MadeBy[id] != name):
                MadeBy[id] = name
                UpdateTime[id] = datetime.fromtimestamp(int(timeStamp))
                if not ReadingFile:
                  print('Update item %d as made by %s' % (id, name))
        # maybe its item info with id in packet
        elif sp == 0 and nameLen == 0:
          descLen = readUInt32(bytes[10:14])
          if descLen > 0:
            desc = readString(bytes[14:])
            if len(desc) == (descLen + 1) and (id not in ExtraInfo or ExtraInfo[id] != desc[:-1]):
              ExtraInfo[id] = desc[:-1]
              UpdateTime[id] = datetime.fromtimestamp(int(timeStamp))
              if not ReadingFile:
                print('Update item %d with extratxt: %s' % (id, ExtraInfo[id]))
    else:
      while len(bytes) > 800:
        strSearch = 0
        i = 0
        while i < len(bytes) and strSearch < 16:
          # check for some valid characters that seem appropriate
          if bytes[i] > 42 and bytes[i] < 123 and bytes[i] not in [47, 64, 92]:
            strSearch += 1
          else:
            strSearch = 0
          i += 1

        begin = i - strSearch;
        if begin > 0:
          del bytes[0:begin]
    
        if strSearch == 16:
          try:
            # test that it's really a string of length 16 by trying to read
            # a longer string and making sure it stops at 16
            test = readString(bytes[0:20], 20)
            del bytes[0:len(test) + 1] # plus null

            if len(test) == 16:
              data = readItem(bytes)
              if data and (len(data) == len(Columns)):
                # save by opcode incase we want to compare items that show
                # up from more than one
                if data[5] not in ItemData:
                  ItemData[data[5]] = data
                  UpdateTime[data[5]] = datetime.fromtimestamp(int(timeStamp))
                  if not ReadingFile:
                    print('Read Item: %s (%d)' % (data[1], data[5]))
          except ParseError:
            #traceback.print_exc()
            pass
          except:
            traceback.print_exc()
            pass

def saveData():
  global Columns, CharmCache, ItemData, ExtraInfo, StartTime, SortByTime

  if len(ItemData) > 0:
    for id in ItemData:
      if id in MadeBy:
        ItemData[id][-2] = MadeBy[id]
      if id in ExtraInfo:
        ItemData[id][-3] = ExtraInfo[id]
      if ItemData[id][71] and ItemData[id][71] in CharmCache:
        ItemData[id][-4] = CharmCache[ItemData[id][71]]
    if SortByTime:
      sort = sorted(UpdateTime, key=UpdateTime.get)
    else:
      sort = sorted(ItemData.keys())
          
    if FORMAT == 'EQR':
      endTime = datetime.now().strftime(TimeRangeFormat)
      if ReadingFile:
        fileName = ('%s.txt' % OutputFile)
      else:
        fileName = ('%s%s+%s.txt' % (OutputFile, StartTime, endTime))
      file = open(fileName, 'w')
      file.write('^'.join(str(s) for s in Columns))
      file.write('\n')
      for id in sort:
        file.write('^'.join(str(s) for s in ItemData[id]))
        file.write('%s' % UpdateTime[id].strftime(UpdateTimeFormat))
        file.write('\n')

      file.close()
      print('Saved %d items to %s' % (len(ItemData), fileName), flush=True)
    else:
      fileName = ('%s.txt' % OutputFile)
      file = open(fileName, 'w')
      for id in sort:
        row = dict()
        for c in range(len(ItemData[id])):
          if c > 0 and 'UNK' not in Columns[c]:
            if ItemData[id][c] not in [-1, 0, '', 4278190080, 4294967295]:
              row[Columns[c]] = ItemData[id][c]
        json.dump(row, file)
        file.write('\n')
      file.close()
  else:
    print('No item data found. Format change?', flush=True)
  exit(1)

def packet_callback(packet):
  if packet and packet[UDP] and packet[UDP].payload:
    try:
      if (UDP in packet and Raw in packet and len(packet[UDP].payload) > 2):
        processPacket(handleEQPacket, packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport, bytearray(packet[UDP].payload.load), packet.time, False)
    except Exception as error:
      print(error, flush=True)

def printSortType():
  if SortByTime:
    print('Sorting Output by Time', flush=True)
  else:
    print('Sorting Output by ID', flush=True)

def main(args):
  global ReadingFile, StartTime, SortByTime

  if (len(args) < 2):
    print ('Usage: ' + args[0] + '-capture | -file <pcap file> [-sort id]')
  else:
    try:
      StartTime = datetime.now().strftime(TimeRangeFormat)
      file = open(ColumnsFile, 'r')
      for line in file: Columns.append(line.strip()) 

      if '-capture' == args[1]:
        if len(args) == 4 and args[2] == '-sort' and args[3] == 'id':
          SortByTime = False
        printSortType()
        ReadingFile = False
        signal.signal(signal.SIGINT, lambda signum, frame: saveData())
        print('Waiting for data. You may need to zone. (Ctrl+C to Save/Exit)', flush=True)
        sniff(filter="udp and (src net 69.174 or dst net 69.174)", timeout=None, prn=packet_callback, store=0)
      elif '-file' == args[1]:
        if len(args) == 5 and args[3] == '-sort' and args[4] == 'id':
          SortByTime = False
        printSortType()
        ReadingFile = True
        print('Reading %s' % args[2])
        readPcap(handleEQPacket, args[2])
        saveData()
      else:
        print ('Usage: ' + args[0] + '-capture | -file <pcap file> [-sort id]', flush=True)
    except Exception as error:
      print(error, flush=True)

main(sys.argv)
