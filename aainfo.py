#
# Script for reading network stream from PCAP recording and attempting to parse Everquest AA data
# Currently works with Test Server as of 9/11/2018
#

import io
import re
import sys
from lib import eqreader

AATableOpcode = 0x41a4 # Test Server 9/11/18, 0x4cfb - Live 9/18/18

OutputFile = 'aainfo.txt'
DBStringsFile = 'data/dbstr_us.txt'
DBSpellsFile = 'data/spells_us.txt'

Categories = ['', '', 'Progression', '', '', 'Veteran Reward', 'Tradeskill', 'Expendable', 'Racial Innate', 'Everquest', '', 'Item Effect']
# list of classes in bitmask order
ClassList = ['BerNotUsedHere', 'War', 'Clr', 'Pal', 'Rng', 'Shd', 'Dru', 'Mnk', 'Brd', 'Rog', 'Shm', 'Nec', 'Wiz', 'Mag', 'Enc', 'Bst']
Expansions = ['Classic', 'Ruins of Kunark', 'The Scars of Velious', 'The Shadows of Luclin', 'The Planes of Power', 'The Legacy of Ykesha',
'Lost Dungeons of Norrath', 'Gates of Discord', 'Omens of War', 'Dragons of Norrath', 'Depths of Darkhollow', 'Prophecy of Ro',
'The Serpent\'s Spine', 'The Buried Sea', 'Secrets of Faydwer', 'Seeds of Destruction', 'Underfoot', 'House of Thule', 'Veil of Alaris',
'Rain of Fear', 'Call of the Forsaken', 'The Darkened Sea', 'The Broken Mirror', 'Empires of Kunark', 'Ring of Scale']
Types = ['Unknown', 'General', 'Archetype', 'Class', 'Special', 'Focus']

# Slot count + Slot 1/SPA info used to search for the AATableOpcode if it is unknown
# Everyone has these and rank 1 seems to show up after a /resetAA
WellKnownAAList = [
  [1, 0, 0, 0, 107, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0], # Battle Ready 1
  [1, 0, 0, 0, 107, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0], # Battle Ready 2
  [1, 0, 0, 0, 107, 1, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0], # Battle Ready 3
  [1, 0, 0, 0, 107, 1, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0], # Battle Ready 4
  [16, 0, 0, 0, 83, 1, 0, 0, 40, 0, 0, 0, 36, 147, 0, 0, 1, 0, 0, 0], # Banestrike 1
  [1, 0, 0, 0, 221, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0], # Packrat 1
  [1, 0, 0, 0, 221, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0], # Packrat 11
  [1, 0, 0, 0, 246, 0, 0, 0, 110, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0] # Innate Lung Capacity 1
]

AAData = dict()
DBDescStrings = dict()
DBTitleStrings = dict()
DBSpells = dict()

# Pulls all Titles from EQ DB files. 
# DB Srtings Example: 16366^1^Sorcerer's Vengeance^0^
def loadDBStrings():
  try:
    print('Loading Strings DB from %s' % DBStringsFile)
    db = open(DBStringsFile, 'r')
    for line in db:
      result = re.match(r'^(\d+)\^(\d)\^([\w\s\'\-\(\)\:\+\.\,\"\/\%\#\<\>]+?)\^[0]\^$', line)
      if (result != None and result.group(2) == '1'):
        DBTitleStrings[int(result.group(1))] = result.group(3)
      elif (result != None and result.group(2) == '4'):
        DBDescStrings[int(result.group(1))] = result.group(3)
        
    if (len(DBTitleStrings) > 0):
      print('Found %d titles' % len(DBTitleStrings))
    else:
      print('No titles found, copy over latest from your EQ directory?')
    if (len(DBDescStrings) > 0):
      print('Found %d descriptions' % len(DBDescStrings))
    else:
      print('No descriptions found, copy over latest from your EQ directory?')
  except Exception as error:
    print(error)

# Spells US Example: 2754^Frenzied Burnout I^
def loadDBSpells():
  try:
    print('Loading Spells DB from %s' % DBSpellsFile)
    db = open(DBSpellsFile, 'r')
    for line in db:
      result = re.match(r'^(\d+)\^([\w\s\'\-\(\)\:\+]+?)\^', line)
      if (result != None):
        DBSpells[int(result.group(1))] = result.group(2)
    if (len(DBSpells) > 0):
      print('Found %d entries' % len(DBSpells))
    else:
      print('No data found, copy over latest from your EQ directory?')
  except Exception as error:
    print(error)

def findOpcode(opcode, buffer):
  global AATableOpcode

  # eliminate packets obviously too small for an AA
  size = len(buffer)
  if (size >= 100):
    found = False
    for aa in WellKnownAAList:
      start = 0
      end = len(aa)
      while (not found and end <= size):
        if (buffer[start:end] == aa):
          AATableOpcode = opcode
          found = True
        else:
          start += 1
          end += 1

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

def handleEQPacket(opcode, size, bytes, pos):
  global AAData
 
  # handle search for opcode
  if (AATableOpcode == 0):
    findOpcode(opcode, list(bytes[pos:]))

  # save an AA if the opcode is correct
  elif (AATableOpcode != 0 and opcode == AATableOpcode):
    try:
      buffer = list(bytes[pos:pos+size])
      descID = readInt32(buffer)
      readBytes(buffer, 1) # always 1
      hotKeySID = readInt32(buffer)
      hotKeySID2 = readInt32(buffer)
      titleSID = readInt32(buffer)
      descSID2 = readInt32(buffer)
      reqLevel = readUInt32(buffer)
      cost = readUInt32(buffer)
      aaID = readUInt32(buffer)
      rank = readUInt32(buffer)

      reqSkills = []
      reqSkillCount = readUInt32(buffer)
      if (reqSkillCount < 5): # or some reasonable value so theres no crazy long loops
        for s in range(reqSkillCount):
          value = readUInt32(buffer)
          if (value > 0):
            reqSkills.insert(0, value)
      else:
        raise TypeError('handleEQPacket: Bad AA format')

      reqRanks = []
      reqRankCount = readUInt32(buffer)
      if (reqRankCount < 5): # or some reasonable value so theres no crazy long loops
        for p in range(reqRankCount):
          value = readUInt32(buffer)
          if (value > 0):
            reqRanks.insert(0, value)
      else:
        raise TypeError('handleEQPacket: Bad AA format')

      type = readUInt32(buffer)
      spellID = readInt32(buffer)
      readUInt32(buffer) # always 1
      abilityTimer = readUInt32(buffer)
      refreshTime = readUInt32(buffer)
      classMask = readUInt16(buffer)
      berserkerMask = readUInt16(buffer)
      maxRank = readUInt32(buffer)
      prevDescSID = readInt32(buffer)
      nextDescSID = readInt32(buffer)
      totalCost = readUInt32(buffer)
      readBytes(buffer, 10) # unknown
      expansion = readUInt32(buffer)
      category = readInt32(buffer)
      readBytes(buffer, 4) #unknown
      expansion2 = readUInt32(buffer) # required expansion? it's not always set
      maxActivationLevel = readUInt32(buffer) # max player level that can use the AA
      isGlyph = readBytes(buffer, 1)
      spaCount = readUInt32(buffer)

      # lookup Title from DB
      if (titleSID == -1):
        raise TypeError('handleEQPacket: Bad AA format, missing title')

      title = DBTitleStrings.get(titleSID) 
      if (title == None):
        title = str(titleSID)
        if (len(DBTitleStrings) > 0):
          print('AA Title not found in DB, possible problem parsing data (format change?)')

      output = io.StringIO()
      output.write('Ability:         %s (%d)\n' % (title, rank))
      output.write('Activation ID:   %d\n' % aaID)

      if (type > -1):
        output.write('Category:        %s\n' % Types[type])
      if (category > -1):
        output.write('Category2:       %s\n' % Categories[category])

      # list of classes
      classes = []
      for c in range(1, len(ClassList)):
        if ((classMask >> c & 1)):
          classes.append(ClassList[c]) 
      
      if (berserkerMask > 0):
        classes.append('Ber')

      if (len(classes) == len(ClassList)):
        output.write('Classes:         All\n')
      else:
        classes.sort()
        output.write('Classes:         %s\n' % ' '.join(classes))

      if (expansion >= 0 and expansion < len(Expansions)):
        expansion = Expansions[expansion]
      output.write('Expansion:       %s\n' % expansion)

      if (maxActivationLevel > 0):
        output.write('Max Level:       %d\n' % maxActivationLevel)
      output.write('Min Level:       %d\n' % reqLevel)
      output.write('Rank:            %d / %d\n' % (rank, maxRank))
      output.write('Rank Cost:       %d AAs\n' % cost)

      if (refreshTime > 0):
        output.write('Reuse Time:      %ds\n' % refreshTime)
        output.write('Timer ID:        %d\n' % abilityTimer)
      else:
        output.write('Reuse Time:      Passive\n')

      if (spellID > 0):
        spellName = DBSpells.get(spellID)
        if (spellName == None and len(DBSpells) > 0):
          print('Spell Title not found in DB for %d, possible problem parsing data (format change?)' % spellID)
        if (spellName == None):
          spellName = spellID
        else:
          spellName = '%s #%d' % (spellName, spellID)
        output.write('Spell:           %s\n' % spellName)

      output.write('Total Cost:      %d AAs\n' % totalCost)

      for i in range(len(reqRanks)):
        output.write('Requirements:    Rank %d of AA/Skill: %d\n' % (reqRanks[i], reqSkills[i]))

      if (spaCount > 0):
        output.write('Found %d SPA Slots:\n' % spaCount)

      for t in range(spaCount):
        spa = readUInt32(buffer)
        base1 = readInt32(buffer)
        base2 = readInt32(buffer)
        slot = readUInt32(buffer)
        output.write('   Slot:   %3d   SPA:   %3d   Base1:   %6d   Base2:   %6d\n' % (slot, spa, base1, base2))

      desc = DBDescStrings.get(descSID2)
      if (desc == None):
        desc = descSID2 
      else:
        desc = '\n   ' + desc.replace('<br><br>', '\n   ').replace('<br>', '\n   ')
      output.write('Description:    %s\n' % desc)

      output.write('\n')
      AAData['%s-%02d' % (title, rank)] = output.getvalue()
      output.close()
    except TypeError as error:
      pass #print(error)

def saveAAData():
  file = open(OutputFile, 'w')
  for key in sorted(AAData.keys()):
    file.write(AAData[key])
  file.close()
  print('Saved data for %d AAs to %s' % (len(AAData), OutputFile))

def main(args):
  global AATableOpcode, AAData

  if (len(args) < 2):
    print ('Usage: ' + args[0] + ' <pcap file>')
  else:
    loadDBStrings()
    loadDBSpells()

    try:
      print('Reading %s' % args[1])
      eqreader.readPcap(handleEQPacket, args[1])
      if (len(AAData) > 0):
        saveAAData()
      else:
        print('No AAs found using opcode: %s, searching for updated opcode' % hex(AATableOpcode))
        AATableOpcode = 0
        eqreader.readPcap(handleEQPacket, args[1])
        if (AATableOpcode > 0):
          print('Found likely opcode: %s, trying to parse AA data again' % hex(AATableOpcode))
          AAData = dict()
          eqreader.readPcap(handleEQPacket, args[1])
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