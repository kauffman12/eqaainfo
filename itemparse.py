#
# Script for parse pcap output for items.
# Saves in old format similar to what EQ websites use to make
# it easy for everyone to use if needed.
#

import io
import sys
import traceback
from lib.util import *
from lib.eqdata import *
from lib.eqreader import *

ColumnsFile = 'columns.txt'
OutputFile = 'iteminfo.txt'
ItemData = dict()
Columns = []

class ParseError (Exception):
  pass

def readItem(bytes):
  data = []

  convertToName = ''
  convertToId = 0
  evolveId = 0
  evolveLevel = 0
  evolveMaxLevel = 0

  readString(bytes, 16)               # 16 character string
  readUInt8(bytes)                    # quantity
  readBytes(bytes, 14)                # unknown
  readUInt32(bytes)                   # price @ merchant
  readBytes(bytes, 40)                # unknown

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

  readBytes(bytes, 33)                # unknown

  # main item structure starts here 
  data.append(readUInt8(bytes))       # item class

  # handle name and throw error if invalid since is the
  # most common sign that we're not at the right place
  # in the item data structure
  name = readString(bytes)
  if not name or len(name) < 2 or len(name) > 254 or not name.isprintable():
    raise ParseError # parsing error
  data.append(name)

  data.append(readString(bytes))      # item lore

  idfile = readInt32(bytes)
  if idfile == 0 or idfile > 0xffffff: raise ParseError
  data.append(idfile)

  idfile2 = readInt32(bytes)
  if idfile2 > 0xffffff: raise ParseError
  data.append(idfile2)

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
  if reqClasses > 65535: raise ParseError
  data.append(reqClasses)

  # race restrictions
  reqRaces = readUInt32(bytes)
  if reqRaces > 65535: raise ParseError
  data.append(reqRaces)

  # deity restrictions
  reqDeity = readUInt32(bytes)
  if reqDeity > 65535: raise ParseError
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

  # some extra error checking
  if data[len(data) - 1] > 254 or data[len(data) - 2] > 254: raise ParseError

  data.append(readUInt32(bytes))      # skill required to use
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

  for header in ['artifact', 'summoned']:
    data.append(readInt8(bytes))

  data.append(readUInt32(bytes))      # tribute
  data.append(readInt8(bytes))        # fv nodrop

  for mods in ['attack', 'haste']:
    data.append(readInt32(bytes))

  for misc in ['guild tribute', 'aug distiller needed']:
    data.append(readUInt32(bytes))

  data.append(readUInt32(bytes))      # UNKNOWN 01
  data.append(readUInt32(bytes))      # UNKNOWN 02
  data.append(readInt8(bytes))        # nopet
  data.append(readUInt8(bytes))       # UNKNOWN 03
  data.append(readUInt32(bytes))      # stack size
  data.append(readInt8(bytes))        # notransfer
  data.append(readInt8(bytes))        # expendable arrow

  # unknown section that's always zeros
  for unknown in range(5):
    data.append(readUInt32(bytes))    # UNKNOWN 04 to 08

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
    data.append(readUInt32(bytes))    # proc mod
    data.append(readString(bytes))    # name
    data.append(readInt32(bytes))     # not used?

  data.append(readInt32(bytes))       # right click script id
  data.append(readInt8(bytes))        # quest item
  data.append(readUInt32(bytes))      # power source cap
  data.append(readUInt32(bytes))      # purity
  data.append(readInt8(bytes))        # epic
  data.append(readUInt32(bytes))      # backstab damage

  for heroic in ['str', 'int', 'wis', 'agi', 'dex', 'sta', 'cha']:
    data.append(readInt32(bytes))

  for mods in ['healAmount', 'spellDmg', 'clairvoyance']:
    data.append(readInt32(bytes))

  # some clickie type field
  # 2 = cure pot, 5 = celestial heal pot, 7 = dragon magic, 17 = fast mounts
  data.append(readInt8(bytes))        # UNKNOWN 9

  data.append(readUInt32(bytes))      # UNKNOWN 10
  data.append(readUInt32(bytes))      # UNKNOWN 11
  data.append(readInt8(bytes))        # heirloom
  data.append(readInt8(bytes))        # placeable

  for unknown in range(7):
    data.append(readUInt32(bytes))    # UNKNOWN 12 to 18

  data.append(readString(bytes))      # placeable npc name

  for unknown in range(7):
    data.append(readUInt32(bytes))    # UNKNOWN 19 to 25

  for misc in ['collectable', 'nodestroy', 'nonpc', 'nozone']:
    data.append(readInt8(bytes))

  for unknown in range(4):
    data.append(readUInt8(bytes))      # UNKNOWN 26 to 29

  for misc in ['noground', 'UNKNOWN 30', 'marketplace', 'freestorage']:
    data.append(readInt8(bytes))

  data.append(readUInt8(bytes))        # UNKNOWN 31
  data.append(readUInt32(bytes))       # UNKNOWN 32
  data.append(readUInt32(bytes))       # UNKNOWN 33

  data.append(readInt32(bytes))        # min luck
  data.append(readInt32(bytes))        # max luck
  data.append(readInt8(bytes))         # lore equipped

  # add evolving related fields
  data.append(evolvable)
  data.append(evolveId)
  data.append(evolveLevel)
  data.append(evolveMaxLevel)

  # add item convertable fields
  data.append(convertable)
  data.append(convertToId)
  data.append(convertToName)

  #print('|'.join(str(s) for s in data))
  return data

# instead of relying on opcodes look for 16 character printable strings that seem to go along
# with each item entry and try to parse them
def handleEQPacket(opcode, bytes, timeStamp):
  global ItemData

  while len(bytes) > 400:
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
        data = readItem(bytes)
        if data and (len(data) == len(Columns)):
          if not opcode in ItemData: ItemData[opcode] = dict()
          ItemData[opcode][data[5]] = data
      except ParseError:
        pass
      except:
        traceback.print_exc()
        pass

def saveItemData():
  if len(ItemData) > 0:
    file = open(OutputFile, 'w')
    file.write('|'.join(str(s) for s in Columns))
    file.write('\n')

    # only save the two most used opcodes since they're most likely
    # the correct ones
    counts = []
    for key in ItemData:
      counts.append({ 'opcode': key, 'count': len(ItemData[key]) })

    combined = dict()
    for item in sorted(counts, reverse=True, key=lambda item: item['count'])[0:2]:
      for id in ItemData[item['opcode']]:
        combined[id] = ItemData[item['opcode']][id]
 
    for id in sorted(combined.keys()):
      file.write('|'.join(str(s) for s in combined[id]))
      file.write('\n')

    file.close()
    print('Saved data for %d Items to %s' % (len(combined), OutputFile))
  else:
    print('No item data found. Format change?')

def main(args):
  if (len(args) < 2):
    print ('Usage: ' + args[0] + ' <pcap file>')
  else:
    try:
      file = open(ColumnsFile, 'r')
      for line in file: Columns.append(line.strip()) 

      print('Reading %s' % args[1])
      readPcap(handleEQPacket, args[1])
      saveItemData()
    except Exception as error:
      print(error)

main(sys.argv)
