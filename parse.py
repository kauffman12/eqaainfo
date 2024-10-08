#
# Script for reading network stream from PCAP recording and attempting to parse Everquest AA data
#

import io
import json
import re
import sys
import datetime
from lib.util import *
from lib.eqdata import *
from lib.eqreader import *

AATableOpcode = 0
EQ64Bit = True
OutputFile = 'aainfo.txt'

#OutputFormat = 'EQSPELLPARSER'
OutputFormat = 'PRETTY'
#OutputFormat = 'EQCALC'

Categories = ['', '', 'Progression', '', '', 'Veteran Reward', 'Tradeskill', 'Expendable', 'Racial Innate', 'Everquest', '', 'Item Effect']
Types = ['Unknown', 'General', 'Archetype', 'Class', 'Special', 'Focus']

FOCUS_SPAS = [ 170, 212, 260, 273, 294, 339, 375, 124, 127, 128, 129, 132, 286, 296, 297, 302, 303, 340, 374, 389, 399, 413, 461, 462, 469, 470, 483, 484, 507 ]

# Slot count, SPA, base1, base2, num info used to search for the AATableOpcode if it is unknown
# Everyone has these and rank 1 seems to show up after a /resetAA
# Added 64bit versions
WellKnownAAList = [
  bytearray([1, 0, 0, 0, 107, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),     # Battle Ready 1
  bytearray([1, 0, 0, 0, 107, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),     # Battle Ready 2
  bytearray([1, 0, 0, 0, 107, 1, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),     # Battle Ready 3
  bytearray([1, 0, 0, 0, 107, 1, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),     # Battle Ready 4
  bytearray([16, 0, 0, 0, 83, 1, 0, 0, 40, 0, 0, 0, 36, 147, 0, 0, 1, 0, 0, 0]), # Banestrike 1
  bytearray([1, 0, 0, 0, 246, 0, 0, 0, 110, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),   # Innate Lung Capacity 1
  bytearray([1, 0, 0, 0, 233, 0, 0, 0, 110, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),   # Innate Metabolism 1
  bytearray([1, 0, 0, 0, 233, 0, 0, 0, 125, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),   # Innate Metabolism 2
  bytearray([1, 0, 0, 0, 233, 0, 0, 0, 150, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),   # Innate Metabolism 3
  bytearray([1, 0, 0, 0, 221, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),     # Packrat 1
  bytearray([1, 0, 0, 0, 221, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),     # Packrat 11
  bytearray([1, 0, 0, 0, 107, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),     # Battle Ready 1
  bytearray([1, 0, 0, 0, 107, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),     # Battle Ready 2
  bytearray([1, 0, 0, 0, 107, 1, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),     # Battle Ready 3
  bytearray([1, 0, 0, 0, 107, 1, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),     # Battle Ready 4
  bytearray([16, 0, 0, 0, 83, 1, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 36, 147, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]), # Banestrike 1
  bytearray([1, 0, 0, 0, 246, 0, 0, 0, 110, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),   # Innate Lung Capacity 1
  bytearray([1, 0, 0, 0, 233, 0, 0, 0, 110, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),   # Innate Metabolism 1
  bytearray([1, 0, 0, 0, 233, 0, 0, 0, 125, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),   # Innate Metabolism 2
  bytearray([1, 0, 0, 0, 233, 0, 0, 0, 150, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),   # Innate Metabolism 3
  bytearray([1, 0, 0, 0, 221, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),     # Packrat 1
  bytearray([1, 0, 0, 0, 221, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0])     # Packrat 11  
]

AAData = dict()
DBDescStrings = DBTitleStrings = DBSpells = None

class AARecord():
  pass

def eqSpellParserOutput(record):
  # output the spell in eqspellparser aa format
  data = []
  data.append(record.descID)
  data.append(record.aaID)
  data.append(record.prevDescSID)
  data.append(record.titleSID)
  data.append(record.descSID2)
  data.append(record.rank)
  data.append(record.maxRank)
  data.append(record.itemDBClassMask)
  data.append(record.reqLevel)
  data.append(record.cost)
  data.append(record.totalCost)
  data.append(record.spellID)
  data.append(record.refreshTime)
  data.append(record.abilityTimer)
  data.append(record.type)
  data.append(record.expansion)
  data.append(record.category)
  data.append(','.join([str(x) for x in record.spaData]))
  if record.reqSkills:
      data.append(','.join([str(x) + ',' + str(y) for x, y in zip(record.reqSkills, record.reqRanks)]))
  else:
      data.append('0,0') # just to match what the eqextractor dump was
  data.append(datetime.fromtimestamp(int(record.timeStamp)).isoformat()[0:10])
  
  title = DBTitleStrings.get(record.titleSID) 
  if (title == None):
    title = str(record.titleSID)
    if (len(DBTitleStrings) > 0):
      print('Warning: AA Title not found in DB for ID %d' % record.titleSID)  
  
  AAData['%s-%02d' % (title, record.rank)] = '^'.join([str(x) for x in data]) + '\n'

def eqCalcOutput(record):
  title = DBTitleStrings.get(record.titleSID) 
  if (title != None):
    entry = dict()
    entry['name'] = title
    entry['id'] = record.aaID
    entry['rank'] = record.rank

    spellFocus = False
    doesDamage = False
    slotList = []

    if (record.spaCount > 0):
      while len(record.spaData) > 3:
        slots = {}
        slots["spa"] = record.spaData.pop(0)
        slots["base1"] = record.spaData.pop(0)
        slots["base2"] = record.spaData.pop(0)
        slots["num"] = record.spaData.pop(0)
        slotList.append(slots)

        if (slots["spa"] == 0 or slots["spa"] == 79) and slots["base1"] < 0:
          doesDamage = True
        if slots["spa"] in FOCUS_SPAS:
          spellFocus = True

    if len(slotList) > 0:
      entry['slotList'] = slotList
    
    if doesDamage or spellFocus:
      AAData['%s-%02d' % (title, record.rank)] = entry

def prettyOutput(record):
  title = DBTitleStrings.get(record.titleSID) 
  if (title == None):
    title = '%d - %d' % (record.titleSID, record.spellID)
    if (len(DBTitleStrings) > 0):
      print('Warning: AA Title not found in DB for ID %d' % record.titleSID)  

  output = io.StringIO()
  output.write('Ability:         %s (%d)\n' % (title, record.rank))
  output.write('Activation ID:   %d\n' % record.aaID)

  if (record.type > -1):
    output.write('Category:        %s\n' % Types[record.type])
  if (record.category > -1):
    output.write('Category2:       %s\n' % Categories[record.category])

  # using class mask util which is based on the item format
  classString = getClassString(record.itemDBClassMask)
  output.write('Classes:         %s\n' % classString)

  expansion = 'Unknown ID %d' % record.expansion
  if (record.expansion >= 0 and record.expansion < len(Expansions)):
    expansion = Expansions[record.expansion]
  output.write('Expansion:       %s\n' % expansion)

  output.write('Min Level:       %d\n' % record.reqLevel)
  output.write('Rank:            %d / %d\n' % (record.rank, record.maxRank))
  output.write('Rank Cost:       %d AAs\n' % record.cost)

  if (record.refreshTime > 0):
    output.write('Reuse Time:      %ds\n' % record.refreshTime)
    output.write('Timer ID:        %d\n' % record.abilityTimer)
  else:
    output.write('Reuse Time:      Passive\n')

  if (record.spellID > 0):
    spellName = DBSpells.get(record.spellID)
    if (spellName == None and len(DBSpells) > 0):
      print('Spell Title not found in DB for %d, possible problem parsing data (format change?)' % record.spellID)
    if (spellName == None):
      spellName = record.spellID
    else:
      spellName = '%s #%d' % (spellName, record.spellID)
    output.write('Spell:           %s\n' % spellName)

  output.write('Total Cost:      %d AAs\n' % record.totalCost)

  for i in range(len(record.reqRanks)):
    output.write('Requirements:    Rank %d of AA/Skill: %d\n' % (record.reqRanks[i], record.reqSkills[i]))

  if (record.spaCount > 0):
    output.write('Found %d SPA Slots:\n' % record.spaCount)

  while len(record.spaData) > 3:
    spa = record.spaData.pop(0)
    base1 = record.spaData.pop(0)
    base2 = record.spaData.pop(0)
    slot = record.spaData.pop(0)
    output.write('   Slot:   %3d   SPA:   %3d   Base1:   %6d   Base2:   %6d\n' % (slot, spa, base1, base2))

  desc = DBDescStrings.get(record.descSID2)
  if (desc == None):
    desc = record.descSID2 
  else:
    desc = '\n   ' + desc.replace('<br><br>', '\n   ').replace('<br>', '\n   ')
  output.write('Description:     %s\n' % desc)

  output.write('\n')
  AAData['%s-%02d' % (title, record.rank)] = output.getvalue()
  output.close()

def findAAOpcode(opcode, bytes):
  global AATableOpcode, EQ64Bit

  # eliminate packets obviously too small for an AA
  count = 0
  size = len(bytes)
  if (size >= 100):
    found = False
    for aa in WellKnownAAList:
      start = 0
      end = len(aa)
      while (not found and end <= size):
        if (bytes[start:end] == aa):
          count += 1
          if (count > 1):
            AATableOpcode = opcode
            EQ64Bit = (len(aa) == 28)
            found = True
            print ('Found opcode: %s, EQ64Bit: %r' % (hex(AATableOpcode), EQ64Bit))
        else:
          start += 1
          end += 1
 
def handleEQPacket(opcode, bytes, timeStamp, clientToServer, clientPort):
  global AAData, AATableOpcode

  if clientToServer:
    return

  # handle search for opcode
  if AATableOpcode == 0:
    findAAOpcode(opcode, bytes)

  # save an AA if the opcode is correct
  elif AATableOpcode != 0 and opcode == AATableOpcode:
    try:
      record = AARecord()
      record.timeStamp = timeStamp
      record.descID = readInt32(bytes)
      readInt8(bytes) # always 1
      record.hotKeySID = readInt32(bytes)
      record.hotKeySID2 = readInt32(bytes)

      record.titleSID = readInt32(bytes)
      if (record.titleSID == -1):
        raise TypeError('handleEQPacket: Bad AA format, missing title')

      record.descSID2 = readInt32(bytes)
      record.reqLevel = readUInt32(bytes)
      record.cost = readUInt32(bytes)
      record.aaID = readUInt32(bytes)
      record.rank = readUInt32(bytes)
      
      record.reqSkills = []
      record.reqSkillCount = readUInt32(bytes)
      if (record.reqSkillCount < 5): # or some reasonable value so theres no crazy long loops
        for s in range(record.reqSkillCount):
          value = readUInt32(bytes)
          if (value > 0):
            record.reqSkills.insert(0, value)
      else:
        raise TypeError('handleEQPacket: Bad AA format')

      record.reqRanks = []
      record.reqRankCount = readUInt32(bytes)
      if (record.reqRankCount < 5): # or some reasonable value so theres no crazy long loops
        for p in range(record.reqRankCount):
          value = readUInt32(bytes)
          if (value > 0):
            record.reqRanks.insert(0, value)
      else:
        raise TypeError('handleEQPacket: Bad AA format')

      record.type = readUInt32(bytes)
      record.spellID = readInt32(bytes)
      test = readUInt32(bytes) # always 1 even with 64bit?
      if test != 0x01:
        print ('Problem reading spell ID, is it 64 bit now?')
      record.abilityTimer = readUInt32(bytes)
      record.refreshTime = readUInt32(bytes)
      record.classMask = readUInt16(bytes)
      record.berserkerMask = readUInt16(bytes)
      record.itemDBClassMask = (record.classMask >> 1) + (32768 if record.berserkerMask else 0)
      record.maxRank = readUInt32(bytes)
      record.prevDescSID = readInt32(bytes)
      record.nextDescSID = readInt32(bytes)
      record.totalCost = readUInt32(bytes)
      readBytes(bytes, 10) # unknown
      record.expansion = readUInt32(bytes)
      record.category = readInt32(bytes)
      record.expansion2 = readUInt32(bytes) # required expansion? it's not always set
      readBytes(bytes, 9) # unknown
      
      spaCount = readUInt32(bytes[0:4])
      if spaCount >= 256:
        # new byte added 2024 beta, maybe related to expansion count increasing 32+
        readBytes(bytes, 1)
      record.spaCount = readUInt32(bytes)
      record.spaData = []

      if record.spaCount < 256:
        for _ in range(record.spaCount):
          if EQ64Bit:
            record.spaData.append(readInt32(bytes))
            record.spaData.append(readInt64(bytes))
            record.spaData.append(readInt64(bytes))
            record.spaData.append(readInt32(bytes))
          else:
            record.spaData.append(readInt32(bytes))
            record.spaData.append(readInt32(bytes))
            record.spaData.append(readInt32(bytes))
            record.spaData.append(readInt32(bytes))

      # print
      if OutputFormat == 'EQSPELLPARSER':
        eqSpellParserOutput(record)
      elif OutputFormat == 'PRETTY':
        prettyOutput(record)
      elif OutputFormat == 'EQCALC':
        eqCalcOutput(record)
      else:
        print('Invalid OutputFormat specified')

    except TypeError as error:
      pass
      #print(error)

def saveAAData():
  file = open(OutputFile, 'w')

  if OutputFormat != 'EQCALC':
    for key in sorted(AAData.keys()):
      file.write(AAData[key])
  else:
    json.dump(list(AAData.values()), file)

  file.close()
  print('Saved data for %d AAs to %s' % (len(AAData), OutputFile))

def main(args):
  global OutputFile, DBDescStrings, DBTitleStrings, DBSpells, AATableOpcode, AAData

  if (len(args) < 2):
    print ('Usage: ' + args[0] + ' <pcap file> [<output file>]')
  else:
    if len(args) == 3:
      OutputFile = args[2]
    try:
      DBDescStrings, DBTitleStrings = loadDBStrings()
      DBSpells = loadDBSpells()

      print('Reading %s' % args[1])
      searchNeeded = (AATableOpcode == 0)
      readPcap(handleEQPacket, args[1])
      if (len(AAData) > 0):
        # read 2nd time if search was used to get any missed AAs
        if searchNeeded:
          readPcap(handleEQPacket, args[1])
        saveAAData()
      else:
        print('No AAs found using opcode: %s, searching for updated opcode' % hex(AATableOpcode))
        AATableOpcode = 0
        readPcap(handleEQPacket, args[1])
        if (AATableOpcode > 0):
          print('Found likely opcode: %s, trying to parse AA data again' % hex(AATableOpcode))
          AAData = dict()
          readPcap(handleEQPacket, args[1])
          if (len(AAData) > 0):
            saveAAData()
            print('Update the default opcode to speed up this process in the future')
          else:
            print('AA Format has most likely changed and can not be parsed')
        else:
            print('Could not find opcode, giving up')
    except Exception as error:
      print(error)

main(sys.argv)
