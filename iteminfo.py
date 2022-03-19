#
# Script for reading network stream from PCAP recording and attempting to parse Everquest Item data
#

import io
import pprint
import re
import sys
import traceback
from lib.util import *
from lib.eqdata import *
from lib.eqreader import *

OutputFile = 'iteminfo.txt'
ItemData = dict()
DBDescStrings = dict()
DBTitleStrings = dict()
DBSpells = dict()

class ParseError (Exception):
  pass

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
  updateItem(effect, 'reqLevel', readUInt8(bytes), lambda x: x > 0)
  effect['type'] = readInt8(bytes)
  updateItem(effect, 'spellLevel', readInt32(bytes), lambda x: x > 0)
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

  # 16 character string
  readString(bytes, 16)

  # quantity but no real point to include
  readUInt8(bytes)

  readBytes(bytes, 14)
  # price an item will be bought for at merchant
  updateSubItem(item, 'price', 'buy', readUInt32(bytes))

  readBytes(bytes, 40) # added 2 bytes since last time. evolving fields different?

  # items that can be converted show the name of the item they can be convereted to here
  convertToNameLen = readUInt32(bytes) # length to read
  if convertToNameLen > 0:
    item['convertToName'] = readString(bytes, convertToNameLen)
  updateItem(item, 'convertToID', readInt64(bytes), lambda x: x > 0)

  # evolving item? works for trophies/tbl gear and has to be skipped otherwise
  if readUInt8(bytes):
    readInt32(bytes)# some id maybe
    updateSubItem(item, 'evolving', 'level', readUInt8(bytes))
    readBytes(bytes, 3)
    readBytes(bytes, 8) # somehow describes percent into current level and/or difficulty
    updateSubItem(item, 'evolving', 'maxLevel', readUInt8(bytes))
    readBytes(bytes, 7)

  # unknown
  readBytes(bytes, 33)

  updateSubItem(item, 'item', 'class', readUInt8(bytes)) 

  item['name'] = readString(bytes)
  if not item['name'] or not item['name'].isprintable():
    raise ParseError # parsing error

  # item lore
  updateItem(item, 'loreText', readString(bytes), lambda x: x != None)

  # used to be itemFile stuff?
  readBytes(bytes, 8)

  # basic item info
  item['id'] = readInt32(bytes)
  if not item['id']:
    raise ParseError # parsing error

  updateSubItem(item, 'item', 'weight', readInt32(bytes) / 10)
  updateSubList2(item, 'header', 'norent', readInt8(bytes), lambda x: x == 0)
  updateSubList2(item, 'header', 'notrade', readInt8(bytes), lambda x: x == 0)
  updateSubList2(item, 'header', 'attunable', readInt8(bytes), lambda x: x != 0)

  # size
  updateSubItem(item, 'item', 'size', readUInt8(bytes))

  # bit mask of slots
  updateItem(item, 'fitsInvSlots', readUInt32(bytes), lambda x: x > 0)

  updateSubItem(item, 'price', 'sell', readUInt32(bytes))
  item['icon'] = readUInt32(bytes)

  # seems to be zero all the time
  readBytes(bytes, 1)

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
  item['reqClasses'] = readUInt32(bytes)
  if item['reqClasses'] == 0 or item['reqClasses'] > 65535:
    raise ParseError # parse error

  item['reqRaces'] = readUInt32(bytes)
  if item['reqRaces'] == 0 or item['reqRaces'] > 65535:
    raise ParseError # parse error

  updateItem(item, 'deity', readUInt32(bytes), lambda x: x)

  # skill modifier
  for skillMod in ['percent', 'max', 'skill']:
    updateSubItem(item, 'skillMod', skillMod, readInt32(bytes), lambda x: x > 0)

  # skip bane damage stuff for now
  readBytes(bytes, 20)

  updateSubList2(item, 'header', 'magic', readUInt8(bytes), lambda x: x)

  # used if item is food or a drink
  updateItem(item, 'duration', readUInt32(bytes), lambda x: x > 0)
  updateItem(item, 'reqLevel', readUInt32(bytes), lambda x: x > 0)
  updateItem(item, 'recLevel', readUInt32(bytes), lambda x: x > 0)
  if 'reqLevel' in item and item['reqLevel'] > 250 or 'recLevel' in item and item['recLevel'] > 250:
    raise ParseError # parse error

  # skill required
  updateItem(item, 'reqSkill', readUInt32(bytes), lambda x: x > 0)

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

  # color?
  readUInt32(bytes)

  # flag but expansion related with EoK (24, 25, 26)
  updateSubList2(item, 'header', 'prestige', readUInt32(bytes), lambda x: x)

  # weapon/armor/inventory/book/etc
  updateSubItem(item, 'item', 'type', readUInt8(bytes))
  updateSubList2(item, 'header', 'augmentation', item['item']['type'], lambda x: x == 54)

  # 0 = cloth, 1 = leather, 16 = plain robe, etc
  # parse for armor only
  material = readUInt32(bytes)
  if item['item']['type'] == 10:
    item['material'] = material
  readBytes(bytes, 12) # unknown
  # repeated material type?
  readBytes(bytes, 4)

  # usually has values shared by multiple items
  readUInt32(bytes)

  # damage mod 8 = backstab, 10 = base, 26 = flying kick, 30 = kick, 74 = frenzy
  for damageMod in ['type', 'damage']:
    updateSubItem(item, 'damageMod', damageMod, readUInt32(bytes), lambda x: x)

  # items with 'gains power by' text have data here
  readUInt32(bytes) 

  # Ex: PS-POS-CasterDPS, ITEMTransAug1HHTH
  updateItem(item, 'charmFile', readString(bytes), lambda x: x)

  # type of aug 3, 4, 19, etc
  updateItem(item, 'fitsAugSlots', readUInt32(bytes), lambda x: x > 0)

  # -1 for everything so far
  readBytes(bytes, 4)

  # 4 = 2h only, 3 = 1h only
  updateItem(item, 'fitsAugType', readUInt32(bytes), lambda x: x)

  # types of aug slots for the 6 possible
  for augSlots in range(6):
    slot = readUInt32(bytes)
    if slot > 32:
      raise ParseError
    updateSubList(item, 'augSlots', slot)
    readBytes(bytes, 2)
  if not any(item['augSlots']):
    item.pop('augSlots')

  # unknown except bytes[12] is 70 for TBL gear and newer?
  readBytes(bytes, 20)

  # container details
  for containerInfo in ['type', 'capacity', 'maxItems', 'weightReduction']:
    updateSubItem(item, 'container', containerInfo, readUInt8(bytes), lambda x: x)

  # 1 if book
  readBytes(bytes, 1)
  updateItem(item, 'bookType', readUInt8(bytes), lambda x: x)
  updateItem(item, 'bookFile', readString(bytes), lambda x: x)

  # possibly item lore
  updateSubList2(item, 'header', 'lore', readInt32(bytes), lambda x: x)

  # artifact/summoned
  for header in ['artifact', 'summoned']:
    updateSubList2(item, 'header', header, readInt8(bytes), lambda x: x == 1)

  # vendor prices
  updateSubItem(item, 'price', 'tribute', readUInt32(bytes))

  # not sure but lots of very different items have it set to 1
  readInt8(bytes)

  # mode modifiers
  for mods in [ 'attack', 'haste' ]:
    updateSubItem(item, 'mods', mods, readInt32(bytes), lambda x: x)

  # tribute duplicate
  readBytes(bytes, 4)

  updateItem(item, 'augDistiller', readInt8(bytes), lambda x: x)

  # unknown
  readBytes(bytes, 3)

  # always -1?
  readBytes(bytes, 4)

  # always 0?
  readBytes(bytes, 4)

  # unknown but usually prizes
  readBytes(bytes, 2)

  item['maxStackSize'] = readUInt32(bytes)

  # unknown
  readBytes(bytes, 22)

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

  readBytes(bytes, 8) # unknown
  updateSubList2(item, 'header', 'heirloom', readInt8(bytes), lambda x: x == 1)
  updateSubList2(item, 'header', 'placeable', readInt8(bytes), lambda x: x)

  # not sure where items end so check if we've reached the beginning
  # of a new one within the data still meant to be parsed
  readBytes(bytes, 78)
  updateSubItem(item, 'luck', 'min', readInt32(bytes), lambda x: x > 0)
  updateSubItem(item, 'luck', 'max', readInt32(bytes), lambda x: x > 0)
  updateSubList2(item, 'header', 'loreEquiped', readInt8(bytes), lambda x: x)
  return item

# instead of relying on opcodes look for 16 character printable strings that seem to go along
# with each item entry and try to parse them
def handleEQPacket(opcode, bytes, timeStamp):
  global ItemData

  list = []
  while len(bytes) > 150:
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
        list.append(readItem(bytes))
      except ParseError:
        pass
      except:
        traceback.print_exc()
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
      printer.pprint(ItemData[key])
  except e as Exception:
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
