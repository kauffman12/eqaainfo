#
# Script for reading network stream from PCAP recording and attempting to parse Everquest Item data
#

import io
import pprint
import re
import sys
from lib.util import *
from lib.eqdata import *
from lib.eqreader import *

OutputFile = 'iteminfo.txt'
ItemData = dict()
DBDescStrings = dict()
DBTitleStrings = dict()
DBSpells = dict()

def updateItem(item, key, value, rule=None):
  if not rule or rule(value):
    item[key] = value

def updateSubItem(item, subItem, key, value, rule=None):
  if not rule or rule(value):
    if not subItem in item:
      item[subItem] = dict()
    item[subItem][key] = value

def updateSubList(item, key, value, rule=None):
  if not rule or rule(value):
    if not key in item:
      item[key] = []
    item[key].append(value)

# this list also has unique items
def updateSubList2(item, key, display, value, rule=None):
  if not rule or rule(value):
    if not key in item:
      item[key] = []
    item[key].append(display)

def readItemEffect(bytes):
  effect = dict()
  effect['spellID'] = readInt32(bytes)
  updateItem(effect, 'levelReq', readUInt8(bytes), lambda x: x > 0)
  effect['type'] = readInt8(bytes)
  updateItem(effect, 'level', readInt32(bytes), lambda x: x > 0)
  updateItem(effect, 'charges', readInt32(bytes), lambda x: x > 0)
  effect['castTime'] = readUInt32(bytes) # cast time not used for procs
  effect['recastDelay'] = readUInt32(bytes) # recast time not used for procs
  effect['recastType'] = readInt32(bytes)
  effect['procMod'] = readUInt32(bytes)
  updateItem(effect, 'text', readString(bytes), lambda x: x != None)
  readInt32(bytes) # unknown
  return effect

def readItem(bytes):
  item = dict()

  readString(bytes, 16) # 16 character string
  item['quantity'] = readUInt8(bytes)

  readBytes(bytes, 14)
  # price an item will be bought for at merchant
  updateSubItem(item, 'price', 'buy', readUInt32(bytes))

  readBytes(bytes, 40) # added 2 bytes since last time. evolving fields different?

  # items that can be converted show the name of the item they can be convereted to here
  convertToNameLen = readUInt32(bytes) # length to read
  if convertToNameLen > 0:
    item['convertToName'] = readString(bytes, convertToNameLen)
  updateItem(item, 'convertToID', readInt64(bytes), lambda x: x > 0)

  #readUInt32(bytes) # unknown

  # if evolving item? seems to lineup but values vary. works for trophy, skull of null, etc
  evolving = readUInt8(bytes)
  if evolving:
    readInt32(bytes)# some id maybe
    updateSubItem(item, 'evolving', 'level', readUInt8(bytes))
    readBytes(bytes, 3)
    readBytes(bytes, 8) # somehow describes percent into current level and/or difficulty
    updateSubItem(item, 'evolving', 'maxLevel', readUInt8(bytes))
    readBytes(bytes, 7)

  readBytes(bytes, 33)
  item['itemClass'] = readUInt8(bytes) # 2 book, container, 0 general
  item['name'] = readString(bytes)
  updateItem(item, 'text', readString(bytes), lambda x: x != None)
  readUInt8(bytes) # used to be itemFile
  readUInt8(bytes) # used to be itemFile
  readUInt8(bytes) # used to be itemFile2
  readBytes(bytes, 5) # no idea
  item['id'] = readInt32(bytes)
  item['weight'] = readInt32(bytes) / 10
  updateSubList2(item, 'header', 'norent', readInt8(bytes), lambda x: x == 0)
  updateSubList2(item, 'header', 'notrade', readInt8(bytes), lambda x: x == 0)
  updateSubList2(item, 'header', 'attunable', readInt8(bytes), lambda x: x != 0)
  item['size'] = readUInt8(bytes)

  # bit mask of slots
  item['slotMask'] = readUInt32(bytes)
  updateSubItem(item, 'price', 'sell', readUInt32(bytes))
  item['icon'] = readUInt32(bytes)
  readBytes(bytes, 1) # dont know
  item['usedInTradeskills'] = readUInt8(bytes) > 0

  # resists
  for resist in ['cold', 'disease', 'poison', 'magic', 'fire', 'corrupt']:
    updateSubItem(item, 'resists', resist, readInt8(bytes), lambda x: x)

  # stats
  for stat in ['str', 'sta', 'agi', 'dex', 'cha', 'int', 'wis']:
    updateSubItem(item, 'stats', stat, readInt8(bytes), lambda x: x)

  # larger stats
  for stat in ['hp', 'mana', 'end', 'ac']:
    updateSubItem(item, 'stats', stat, readInt32(bytes), lambda x: x)
  
  # mod2
  for mods in ['hpRegen', 'manaRegen', 'endRegen']:
    updateSubItem(item, 'mods', mods, readInt32(bytes), lambda x: x)

  # class/race/diety restrictions
  item['classMask'] = readUInt32(bytes)
  item['raceMask'] = readUInt32(bytes)
  updateItem(item, 'deity', readUInt32(bytes), lambda x: x)

  # skill modifier
  for skillMod in ['percent', 'max', 'skill']:
    updateSubItem(item, 'skillMod', skillMod, readInt32(bytes), lambda x: x > 0)

  readBytes(bytes, 20) # skip bane damage stuff for now
  updateSubList2(item, 'header', 'magic', readUInt8(bytes), lambda x: x)

  # used if item is food or a drink
  updateItem(item, 'duration', readUInt32(bytes), lambda x: x > 0)
  updateItem(item, 'levelReq', readUInt32(bytes), lambda x: x > 0)
  updateItem(item, 'levelRec', readUInt32(bytes), lambda x: x > 0)
  updateItem(item, 'skillReq', readUInt32(bytes), lambda x: x > 0)

  readBytes(bytes, 8) # bard checks?
  updateItem(item, 'light', readInt8(bytes), lambda x: x)

  # some weapon stats
  updateItem(item, 'delay', readUInt8(bytes), lambda x: x)

  # elemental damage
  for elem in ['type', 'damage']:
    updateSubItem(item, 'elemental', elem, readUInt8(bytes), lambda x: x)

  # more weapon stats
  updateItem(item, 'range', readUInt8(bytes), lambda x: x)
  updateItem(item, 'damage', readInt32(bytes), lambda x: x)

  readUInt32(bytes) # color according to lucy
  # flag but expansion related with EoK (24, 25, 26)
  updateSubList2(item, 'header', 'prestige', readUInt32(bytes), lambda x: x)
  # weapon/armor/inventory/book/etc
  item['itemType'] = readInt8(bytes)
  updateSubList2(item, 'header', 'augmentation', item['itemType'], lambda x: x == 54)

  # 0 = cloth, 1 = leather, 16 = plain robe, etc
  # parse for armor only
  material = readUInt32(bytes)
  if item['itemType'] == 10:
    item['material'] = material
  readBytes(bytes, 12) # unknown
  # repeated material type?
  readBytes(bytes, 4)
  # listed unknown value on lucy but usually has value shared by multiple items
  readUInt32(bytes)

  # damage mod 8 = backstab, 10 = base, 26 = flying kick, 30 = kick, 74 = frenzy
  for damageMod in ['type', 'damage']:
    updateSubItem(item, 'damageMod', damageMod, readUInt32(bytes), lambda x: x)

  # items with 'gains power by' text have data here
  readUInt32(bytes) 

  # Ex: PS-POS-CasterDPS, ITEMTransAug1HHTH
  updateItem(item, 'charmFile', readString(bytes), lambda x: x)

  # type of aug 3, 4, 19, etc
  updateItem(item, 'augTypeMask', readUInt32(bytes), lambda x: x)

  # -1 for everything so far
  readBytes(bytes, 4)

  # 4 = 2h only, 3 = 1h only
  updateItem(item, 'augRestrictions', readUInt32(bytes), lambda x: x)

  # types of aug slots for the 6 possible
  for augSlots in range(6):
    updateSubList(item, 'augSlots', readUInt32(bytes))
    readBytes(bytes, 2)
  if not any(item['augSlots']):
    item.pop('augSlots')

  # unknown
  readBytes(bytes, 20)

  # container details
  for containerInfo in ['type', 'capacity', 'maxItems', 'weightReduction']:
    updateSubItem(item, 'container', containerInfo, readUInt8(bytes), lambda x: x)

  # 1 if book
  readBytes(bytes, 1)
  updateItem(item, 'bookType', readUInt8(bytes), lambda x: x)
  updateItem(item, 'bookFile', readString(bytes), lambda x: x)

  # unknown
  readBytes(bytes, 6)

  # vendor prices
  updateSubItem(item, 'price', 'tribute', readUInt32(bytes))

  # unknwon
  readInt8(bytes)

  # mode modifiers
  for mods in [ 'attack', 'haste' ]:
    updateSubItem(item, 'mods', mods, readInt32(bytes), lambda x: x)

  readBytes(bytes, 4) # tribute duplicate
  updateItem(item, 'augmentDistLevel', readInt8(bytes), lambda x: x)
  readBytes(bytes, 3) # unknown
  readInt32(bytes) # some -1?
  readBytes(bytes, 6) # unknown
  item['maxStackSize'] = readUInt32(bytes)
  readBytes(bytes, 22) # unknown

  # effects/clickie/focus
  # should be up to 6?
  for ecount in range(6):
    updateSubList(item, 'effects', readItemEffect(bytes), lambda x: x['spellID'] > -1)

  readBytes(bytes, 39) # unknown
  updateSubList2(item, 'header', 'quest', readInt8(bytes), lambda x: x == 1)
  readBytes(bytes, 4) # unknown
  updateItem(item, 'purity', readUInt32(bytes), lambda x: x)
  readBytes(bytes, 1)
  updateItem(item, 'backstabDmg', readUInt32(bytes), lambda x: x) # Ex Backstab Dmg 76

  # heroics
  for heroic in ['str', 'int', 'wis', 'agi', 'dex', 'sta', 'cha']:
    updateSubItem(item, 'heroics', heroic, readInt32(bytes), lambda x: x)

  # more mods stats
  for mods in ['healAmount', 'spellDmg', 'clairvoyance']:
    updateSubItem(item, 'mods', mods, readInt32(bytes), lambda x: x)

  readBytes(bytes, 1) # Ex 2 = cure potion, 5 = latest celestial heal, 7 = spider's bite/dragon magic, 17 = fast mounts
  readBytes(bytes, 5) # unknown
  readBytes(bytes, 3) # unknown
  updateSubList2(item, 'header', 'heirloom', readInt8(bytes), lambda x: x == 1)

  readBytes(bytes, 5) # unknown
  updateSubList2(item, 'header', 'placeable', readInt8(bytes), lambda x: x)

  # not always the end but we search for the next item
  readBytes(bytes, 73)
  updateItem(item, 'luckMin', readInt32(bytes), lambda x: x > 0)
  updateItem(item, 'luckMax', readInt32(bytes), lambda x: x > 0)
  return item

# instead of relying on opcodes look for 16 character printable strings that seem to go along
# with each item entry and try to parse them
def handleEQPacket(opcode, bytes, timeStamp):
  global ItemData

  list = []
  while len(bytes) > 500:
    strSearch = 0
    index = 0
    while index < len(bytes) and strSearch < 16:
      if bytes[index] > 32 and bytes[index] <= 127:
        strSearch += 1
      else:
        strSearch = 0
      index += 1

    begin = index - strSearch;
    if begin > 0:
      del bytes[0:begin]
    
    if strSearch == 16:
      try:
        item = readItem(bytes)
        if item['name'] and item['name'].isprintable() and item['id'] and item['raceMask'] <= 65535 and item['classMask'] <= 65535:
          list.append(item)
      except:
        pass

  # if at least a few parsed OK then keep them
  for item in list:
    ItemData[item['name']] = item

def saveItemData():
  file = open(OutputFile, 'w')
  printer = pprint.PrettyPrinter(indent=2, stream=file)
  bleh = None
  try:
    for key in sorted([*ItemData]):
      bleh = key
      printer.pprint(ItemData[key])
  except:
    print (ItemData[bleh])
    pass
  file.close()
  print('Saved data for %d Items to %s' % (len(ItemData), OutputFile))

def main(args):
  if (len(args) < 2):
    print ('Usage: ' + args[0] + ' <pcap file>')
  else:
    try:
      #DBDescStrings, DBTitleStrings = loadDBStrings()
      #DBSpells = loadDBSpells()

      print('Reading %s' % args[1])
      readPcap(handleEQPacket, args[1])
      if (len(ItemData) > 0):
        saveItemData()
      else:
        print('Item Format has most likely changed and can not be parsed')
    except Exception as error:
      print(error)

main(sys.argv)
