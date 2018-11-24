#
# Script for reading network stream from PCAP recording and attempting to parse Everquest Item data
#

import io
import pprint
import re
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
  result['EffectType'] = readBytes(bytes, 1)[0]
  readInt32(bytes) # unknown
  readInt32(bytes) # unknown
  result['CastTime'] = readUInt32(bytes) # cast time not used for procs
  result['RecastTime'] = readUInt32(bytes) # recast time not used for procs
  readInt32(bytes) # unknown
  result['ProcMod'] = meleeProcMod = readUInt32(bytes)
  result['EffectName'] = readString(bytes)
  readInt32(bytes) # unknown -1 on guardian
  return result

def readItem(bytes):
  item = dict()
  item['unkStr'] = readString(bytes) # 16 character string
  del bytes[0:64]
 
  item['unkStr2'] = readString(bytes) # ornaments have this other name string
  if item['unkStr2']:
    item['id2'] = readUInt32(bytes)
    readBytes(bytes, 1) # need to read 1 extra and its not using a good null terminator
  else:
    item['id2'] = readUInt32(bytes)

  readUInt32(bytes) # unknown

  # not really sure about this yet but skull of null has extra data
  extra = readInt8(bytes)
  if extra:
    readBytes(bytes, 25)

  readBytes(bytes, 27)
  item['name'] = readString(bytes)
  item['lore'] = readString(bytes)
  item['fileID'] = readString(bytes)
  readBytes(bytes, 1) # dont really know
  item['itemID'] = readInt32(bytes)
  item['weight'] = readInt8(bytes) / 10
  readBytes(bytes, 7) # dont really know
  item['slots'] = readUInt32(bytes)
  readBytes(bytes, 4) # dont really know
  item['icon'] = readUInt32(bytes)
  readBytes(bytes, 2) # dont really know
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
  item['endur'] = readInt32(bytes)
  item['ac'] = readInt32(bytes)
  item['regen'] = readInt32(bytes)
  item['mregen'] = readInt32(bytes)
  item['eregen'] = readInt32(bytes)
  item['classMask'] = readUInt32(bytes)
  item['races'] = readUInt32(bytes)
  item['deity'] = readUInt32(bytes)
  item['skillmodvalue'] = readInt32(bytes)
  item['skillmodmax'] = readInt32(bytes)
  item['skillmodtype'] = readInt32(bytes)  
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
  readBytes(bytes, 1) # unknown
  item['augType1'] = readInt8(bytes)
  readUInt32(bytes) # always 1?
  readBytes(bytes, 1) # unknown
  item['augType2'] = readInt8(bytes)
  readUInt32(bytes) # always 1?
  readBytes(bytes, 1) # unknown
  item['augType3'] = readInt8(bytes)
  readUInt32(bytes) # always 1?
  readBytes(bytes, 1) # unknown
  item['augType4'] = readInt8(bytes)
  readUInt32(bytes) # always 1?
  readBytes(bytes, 1) # unknown
  item['augType5'] = readInt8(bytes)
  readUInt32(bytes) # always 1?
  readBytes(bytes, 1) # unknown
  item['augType6'] = readInt8(bytes)
  readUInt32(bytes) # always 1?

  readBytes(bytes, 28) # unknown
  readInt32(bytes) # some -1?
  readBytes(bytes, 23) # unknown
  readInt32(bytes) # some -1?
  readBytes(bytes, 6) # unknown

  item['stackSize'] = readUInt32(bytes) # maybe stack size
  readBytes(bytes, 22) # unknown

  effs = 0
  effectsList = []
  while effs < 9:
    effectsList.insert(0, readItemEffect(bytes))
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
 
def handleEQPacket(opcode, bytes):
  global ItemData
 
  list = []
  while len(bytes) > 500:
    strSearch = 0
    index = 0
    while index < len(bytes) and strSearch < 16:
      if bytes[index] >= 32 and bytes[index] <= 127:
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
        if item['name'] and item['name'].isprintable() and item['itemType'] < 100:
          list.append(item)
      except:
        pass

  # if at least a few parsed OK then keep them
  if len(list) > 5:
    for item in list:
      ItemData[item['name']] = item

def saveItemData():
  file = open(OutputFile, 'w')
  printer = pprint.PrettyPrinter(indent=2, stream=file)
  for key in sorted(ItemData.keys()):
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