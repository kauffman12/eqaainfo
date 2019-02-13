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

def readItemEffect(bytes):
  effect = dict()
  effect['spellID'] = readInt32(bytes)
  effect['reqLevel'] = readUInt8(bytes)
  effect['type'] = readInt8(bytes)
  effect['level'] = readInt32(bytes)
  effect['charges'] = readInt32(bytes)
  effect['castTime'] = readUInt32(bytes) # cast time not used for procs
  effect['recastDelay'] = readUInt32(bytes) # recast time not used for procs
  effect['recastType'] = readInt32(bytes)
  effect['procMod'] = readUInt32(bytes)
  effect['name'] = readString(bytes)
  effect['unknown'] = readInt32(bytes)
  return effect

def readItem(bytes):
  item = dict()

  readString(bytes, 16) # 16 character string
  item['quantity'] = readUInt8(bytes)

  readBytes(bytes, 14)
  # price an item will be bought for at merchant
  updateSubItem(item, 'price', 'buy', readUInt32(bytes))
  readBytes(bytes, 41)

  # items that can be converted show the name of the item they can be convereted to here
  convertToNameLen = readUInt32(bytes) # length to read
  if convertToNameLen > 0:
    item['convertToName'] = readString(bytes, convertToNameLen)
  updateItem(item, 'convertToID', readInt32(bytes), lambda x: x > 0)

  readUInt32(bytes) # unknown

  # if evolving item? seems to lineup but values vary. works for trophy, skull of null, etc
  item['evolving'] = readUInt8(bytes)
  if item['evolving']:
    readInt32(bytes)# some id maybe
    item['evolvedLevel'] = readUInt8(bytes)
    readBytes(bytes, 3)
    readBytes(bytes, 8) # somehow describes percent into current level and/or difficulty
    item['evolvedLevelMax'] = readUInt8(bytes)
    readBytes(bytes, 7)

  readBytes(bytes, 27)
  item['itemClass'] = readUInt8(bytes) # 2 book, container, 0 general
  item['name'] = readString(bytes)
  item['description'] = readString(bytes)
  item['itemFile'] = readString(bytes)
  updateItem(item, 'itemFile2', readString(bytes), lambda x: x)
  item['id'] = readInt32(bytes)
  item['weight'] = readInt32(bytes) / 10
  item['temporary'] = readUInt8(bytes) == 0
  item['tradeable'] = readUInt8(bytes) > 0
  item['attunable'] = readUInt8(bytes) > 0
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
  
  # mod2s
  for mod2 in ['hpRegen', 'manaRegen', 'endRegen']:
    updateSubItem(item, 'mod2', mod2, readInt32(bytes), lambda x: x)

  item['classMask'] = readUInt32(bytes)
  item['races'] = readUInt32(bytes)
  updateItem(item, 'deity', readUInt32(bytes), lambda x: x)

  # skill modifier
  for skillModifier in ['percent', 'max', 'skill']:
    updateSubItem(item, 'skillModifier', skillModifier, readInt32(bytes), lambda x: x > 0)

  #if 'Air Powered Blade of Repulsion' in item['name']:
  #  readBytes(bytes, 449)
  readBytes(bytes, 20) # skip bane damage stuff for now
  item['magic'] = readInt8(bytes) != 0

  # used if item is food or a drink
  item['consumable'] = readInt32(bytes) != 0
  updateItem(item, 'reqLevel', readUInt32(bytes), lambda x: x > 0)
  updateItem(item, 'recLevel', readUInt32(bytes), lambda x: x > 0)

  readBytes(bytes, 12) # req skill? bard checks
  item['lightSource'] = readInt8(bytes)

  # some weapon stats
  updateItem(item, 'delay', readUInt8(bytes), lambda x: x)

  # elemental damage
  for elem in ['type', 'damage']:
    updateSubItem(item, 'elemental', elem, readUInt8(bytes), lambda x: x)

  # more weapon stats
  updateItem(item, 'range', readUInt8(bytes), lambda x: x)
  updateItem(item, 'damage', readInt32(bytes), lambda x: x)

  item['color'] = readUInt32(bytes)
  item['prestige'] = readUInt32(bytes) # flag but expansion related with EoK (24, 25, 26)
  item['itemType'] = readInt8(bytes) # weapon/armor/inventory/book/etc

  item['materialType'] = readUInt32(bytes) # 0 = cloth, 1 = leather, 16 = plain robe, etc
  readBytes(bytes, 8) # unknown
  readBytes(bytes, 4) # unknown
  item['materialType2'] = readUInt32(bytes) # repeated material type?
  readUInt32(bytes) # listed unknown value on lucy but it usually has a value thats shared by multiple items

  # damage modifier like 8 = backstab, 10 = base, 26 = flying kick, 30 = kick, 74 = frenzy
  for damageModifier in ['type', 'damage']:
    updateSubItem(item, 'damageModifier', damageModifier, readUInt32(bytes), lambda x: x)

  readUInt32(bytes) # more unknown
  updateItem(item, 'charmFile', readString(bytes), lambda x: x) # Ex: PS-POS-CasterDPS

  # aug types this item can be used with if it's an augment
  updateItem(item, 'augTypeMask', readUInt8(bytes), lambda x: x)
  readBytes(bytes, 3) # unknown
  readInt32(bytes) # some -1
  updateItem(item, 'augRestrictions', readUInt8(bytes), lambda x: x) # 4 = 2h only, 3 = 1h only
  readBytes(bytes, 3)

  # types of aug slots for the 6 possible
  for augSlots in range(6):
    updateSubList(item, 'augSlots', readUInt32(bytes))
    readBytes(bytes, 2)

  readBytes(bytes, 20) # unknown

  # container details
  for containerInfo in ['type', 'capacity', 'maxItems', 'weightReduction']:
    updateSubItem(item, 'container', containerInfo, readUInt8(bytes), lambda x: x)

  readBytes(bytes, 2) # unknown
  updateItem(item, 'bookContentsFile', readString(bytes), lambda x: x)
  item['lore'] = readInt32(bytes)
  readBytes(bytes, 2) # unknown
  updateSubItem(item, 'price', 'tribute', readUInt32(bytes))
  readBytes(bytes, 1) # unknown
  updateSubItem(item, 'mod2', 'attack', readInt32(bytes), lambda x: x)
  readBytes(bytes, 12) # unknown
  readInt32(bytes) # some -1?
  readBytes(bytes, 6) # unknown
  item['maxStackSize'] = readUInt32(bytes)
  readBytes(bytes, 22) # unknown

  # effects/clickie/focus
  for ecount in range(9):
    updateSubList(item, 'effects', readItemEffect(bytes), lambda x: x['spellID'] > -1)

  readBytes(bytes, 9) # unknown
  item['purity'] = readUInt32(bytes)
  readBytes(bytes, 1)
  updateItem(item, 'backstabDmg', readUInt32(bytes), lambda x: x) # Ex Backstab Dmg 76

  # heroics
  for heroic in ['str', 'int', 'wis', 'agi', 'dex', 'sta', 'cha']:
    updateSubItem(item, 'heroics', heroic, readInt32(bytes), lambda x: x)

  # more mod2 stats
  for mod2 in ['healAmount', 'spellDmg', 'clairvoyance']:
    updateSubItem(item, 'mod2', mod2, readInt32(bytes), lambda x: x)

  readBytes(bytes, 1) # Ex 2 = cure potion, 5 = latest celestial heal, 7 = spider's bite/dragon magic, 17 = fast mounts
  readBytes(bytes, 9) # unknown
  item['placeable'] = readInt8(bytes) != 0

  # not always the end but we search for the next item
  readBytes(bytes, 50)
  return item

# instead of relying on opcodes look for 16 character printable strings that seem to go along
# with each item entry and try to parse them
def handleEQPacket(opcode, bytes):
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
        if item['name'] and item['name'].isprintable() and item['itemFile'] and item['itemFile'].startswith('IT') and sum(item['augSlots']) < 150:
          list.append(item)
      except:
        pass

  # if at least a few parsed OK then keep them
  for item in list:
    ItemData[item['name']] = item

def saveItemData():
  file = open(OutputFile, 'w')
  printer = pprint.PrettyPrinter(indent=2, stream=file)
  for key in sorted([*ItemData]):
    printer.pprint(ItemData[key])
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