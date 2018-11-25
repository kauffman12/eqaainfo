#
# Script for reading network stream from PCAP recording and attempting to parse Everquest Item data
#

import io
import pprint
import re
import struct
import sys
from lib.util import *
from lib.eqreader import *

OutputFile = 'iteminfo.txt'
ItemData = dict()
DBDescStrings = dict()
DBTitleStrings = dict()
DBSpells = dict()

def readItemEffect(bytes):
  result = dict()
  result['SpellID'] = readInt32(bytes)
  readBytes(bytes, 1) # unknown
  result['Type'] = readBytes(bytes, 1)[0]
  result['Level'] = readInt32(bytes) # unknown
  result['Charges'] = readInt32(bytes) # unknown
  result['CastTime'] = readUInt32(bytes) # cast time not used for procs
  result['RecastDelay'] = readUInt32(bytes) # recast time not used for procs
  result['RecastType'] = readInt32(bytes) # unknown
  result['ProcMod'] = readUInt32(bytes)
  result['Name'] = readString(bytes)
  readInt32(bytes) # unknown -1 on guardian
  return result

def readItem(bytes):
  item = dict()
  item['dbStr'] = readString(bytes, 16) # 16 character string
  item['quantity'] = readUInt8(bytes)

  # lots of unknown
  readBytes(bytes, 59)

  # sometimes a 2nd name is set. Round Cut Tool might say Oval Cut Tool in this value
  # some mount items have a slightly different name here, ornaments say a different name
  dbStr2Len = readUInt32(bytes) # length to read
  if dbStr2Len > 0:
    item['dbStr2'] = readString(bytes, dbStr2Len)

  item['id2'] = readUInt32(bytes)
  readUInt32(bytes) # unknown

  # if evolving item? seems to lineup but values vary
  item['evolving'] = readUInt8(bytes)
  if item['evolving']:
    readInt32(bytes)# some id maybe
    item['evolvedLevel'] = readUInt8(bytes)
    readBytes(bytes, 3)
    readBytes(bytes, 8) # somehow describes percent into current level and/or difficulty
    item['evolvedLevelMin'] = readUInt8(bytes)
    item['evolvedLevelMax'] = readUInt8(bytes)
    readBytes(bytes, 7)

  readBytes(bytes, 27)
  item['itemClass'] = readUInt8(bytes) # 2 book, container, 0 normal
  item['name'] = readString(bytes)
  item['details'] = readString(bytes)
  item['fileID'] = readString(bytes)
  readBytes(bytes, 1) # dont know
  item['itemID'] = readInt32(bytes)
  item['weight'] = readInt8(bytes) / 10
  readBytes(bytes, 3) # dont know
  item['temporary'] = readUInt8(bytes) ^ 1
  item['tradeable'] = readUInt8(bytes)
  item['attunable'] = readUInt8(bytes)
  item['size'] = readUInt8(bytes)
  item['slots'] = readUInt32(bytes)
  item['sellPrice'] = readUInt32(bytes)
  item['icon'] = readUInt32(bytes)
  readBytes(bytes, 1) # dont know
  item['usedInTradeskills'] = readUInt8(bytes)
  item['cr'] = readInt8(bytes)
  item['dr'] = readInt8(bytes)
  item['pr'] = readInt8(bytes)
  item['mr'] = readInt8(bytes)
  item['fr'] = readInt8(bytes)
  item['scr'] = readInt8(bytes)
  item['str'] = readInt8(bytes)
  item['sta'] = readInt8(bytes)
  item['agi'] = readInt8(bytes)
  item['dex'] = readInt8(bytes)
  item['cha'] = readInt8(bytes)
  item['int'] = readInt8(bytes)
  item['wis'] = readInt8(bytes)
  item['hp'] = readInt32(bytes)
  item['mana'] = readInt32(bytes)
  item['endurance'] = readInt32(bytes)
  item['ac'] = readInt32(bytes)
  item['regen'] = readInt32(bytes)
  item['manaRegen'] = readInt32(bytes)
  item['enduranceRegen'] = readInt32(bytes)
  item['classMask'] = readUInt32(bytes)
  item['races'] = readUInt32(bytes)
  item['deity'] = readUInt32(bytes)
  item['skillModPercent'] = readInt32(bytes)
  item['skillModMax'] = readInt32(bytes)
  item['skillModType'] = readInt32(bytes)
  readBytes(bytes, 20) # skip bane damage stuff for now
  item['magic'] = readInt8(bytes)
  item['castTime'] = readInt32(bytes)
  item['reqLevel'] = readUInt32(bytes)
  item['recLevel'] = readUInt32(bytes)
  readBytes(bytes, 12) # req skill? bard checks
  item['lightsource'] = readInt8(bytes)
  item['delay'] = readInt8(bytes)
  item['elemDamage'] = readInt8(bytes)
  item['elemDamageType'] = readInt8(bytes)
  item['range'] = readInt8(bytes)
  item['damage'] = readInt32(bytes)
  item['color'] = readUInt32(bytes)
  item['prestige'] = readUInt32(bytes)
  item['itemType'] = readInt8(bytes)
  item['material'] = readUInt32(bytes)

  readBytes(bytes, 8) # more material stuff
  readBytes(bytes, 4) # sell rate as a float?
  readBytes(bytes, 4) # not sure
  readUInt32(bytes) # listed unknown value on lucy and its the same for staff and feral guardian
  readBytes(bytes, 12) # more unknown

  item['charmFile'] = readString(bytes) # Ex: PS-POS-CasterDPS

  readBytes(bytes, 4) # unknown
  readInt32(bytes) # some -1
  readBytes(bytes, 3)

  # what aug slots are in the item
  # always up to 6 slots?
  augSlots = 0
  augList = []
  while augSlots < 6:
    readBytes(bytes, 1) # unknown
    augList.append(readInt8(bytes))
    readUInt32(bytes) # always 1?
    augSlots += 1
  item['augSlots'] = augList

  readBytes(bytes, 21) # unknown

  # type of container or 0 if not one
  item['containerType'] = readUInt8(bytes)
  item['containerCapacity'] = readUInt8(bytes)
  item['containerItemSize'] = readUInt8(bytes)
  item['containerWeightReduction'] = readUInt8(bytes)
  readBytes(bytes, 25) # unknown
  readInt32(bytes) # some -1?
  readBytes(bytes, 23) # unknown
  readInt32(bytes) # some -1?
  readBytes(bytes, 6) # unknown

  item['stackSize'] = readUInt32(bytes) # maybe stack size

  effs = 0
  effectsList = []
  while effs < 9:
    effectsList.append(readItemEffect(bytes))
    effs += 1 
  item['effects'] = effectsList

  readBytes(bytes, 6)
  test = readUInt32(bytes)
  readBytes(bytes, 8) # unknown
  item['hstr'] = readInt32(bytes)
  item['hint'] = readInt32(bytes)
  item['hwis'] = readInt32(bytes)
  item['hagi'] = readInt32(bytes)
  item['hdex'] = readInt32(bytes)
  item['hsta'] = readInt32(bytes)
  item['hcha'] = readInt32(bytes)
  item['healAmt'] = readInt32(bytes)
  item['spellDmg'] = readInt32(bytes)
  item['clair'] = readInt32(bytes)

  readBytes(bytes, 10) # unknown
  item['placeable2'] = readUInt8(bytes)
  readBytes(bytes, 60)
  return item

# I don't really see a good use for this data but this is what the structure looks like when you search for items
# in the bazaar. Instead of knownig the opcode you could probably just execute this search on every item and if the
# if the 16 character string is read successfully 2 or 3 times assume its the right one. I don't have any plans to 
# implement this any futher right now.
def NOT_CURRENTLY_USED_handleEQBazaarList(opcode, bytes):
  if opcode == 22944:
    readBytes(bytes, 18)
    try:
      while len(bytes) > 40: # min size i guess 
        readString(bytes) # 16 character unique string
        cost = readUInt32(bytes)
        quantity = readUInt32(bytes)
        id = readInt32(bytes)
        icon = readInt32(bytes)
        name = readString(bytes)
        searchStat = readUInt32(bytes) # value of stat you searched for otherwise 0 if you didn't specify one
        searchUnk = readUInt32(bytes) # set to 0 if item doesn't have the stat you searched for but it met the other criteria. in that case the item won't show up in-game
        print('name: %s, id: %d, cost: %d, quantity: %d, icon: %d, searchStat: %d, unk: %d' % (name, id, cost, qty, icon, searchStat, searchUnk))
    except:
      pass
 
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
        if item['name'] and item['name'].isprintable() and item['fileID'] and item['fileID'].startswith('IT'):
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
      DBDescStrings, DBTitleStrings = loadDBStrings()
      DBSpells = loadDBSpells()

      print('Reading %s' % args[1])
      readPcap(handleEQPacket, args[1])
      if (len(ItemData) > 0):
        saveItemData()
      else:
        print('Item Format has most likely changed and can not be parsed')
    except Exception as error:
      print(error)

main(sys.argv)