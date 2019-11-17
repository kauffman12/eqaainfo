import os.path
import re

# expansion list
Expansions = ['Classic', 'Ruins of Kunark', 'The Scars of Velious', 'The Shadows of Luclin', 'The Planes of Power', 'The Legacy of Ykesha',
'Lost Dungeons of Norrath', 'Gates of Discord', 'Omens of War', 'Dragons of Norrath', 'Depths of Darkhollow', 'Prophecy of Ro',
'The Serpent\'s Spine', 'The Buried Sea', 'Secrets of Faydwer', 'Seeds of Destruction', 'Underfoot', 'House of Thule', 'Veil of Alaris',
'Rain of Fear', 'Call of the Forsaken', 'The Darkened Sea', 'The Broken Mirror', 'Empires of Kunark', 'Ring of Scale', 'The Burning Lands', 'Torment of Velious']

# list in bit order for classes
ClassTypes = ['War', 'Clr', 'Pal', 'Rng', 'Shd', 'Dru', 'Mnk', 'Brd', 'Rog', 'Shm', 'Nec', 'Wiz', 'Mag', 'Enc', 'Bst', 'Ber', 'Merc']

def getClassString(classMask, playersOnly=True):
  classes = []
  for c in range(0, len(ClassTypes)):
    if ((classMask >> c & 1)):
      classes.append(ClassTypes[c])

  # dont count merc if the mask only includes players
  total = len(ClassTypes) - 1 if playersOnly else len(ClassTypes)
  if (len(classes) == total):
    result = 'All'
  else:
    classes.sort()
    result = ' '.join(classes)

  return result

DBStringsFile = 'data/dbstr_us.txt'
DBSpellsFile = 'data/spells_us.txt'

# Pulls all Titles from EQ DB files. 
# DB Srtings Example: 16366^1^Sorcerer's Vengeance^0^
def loadDBStrings():
  descs = dict()
  titles = dict()
  if os.path.isfile(DBStringsFile):
    print('Loading Strings DB from %s' % DBStringsFile)
    db = open(DBStringsFile, 'r')
    for line in db:
      result = re.match(r'^(\d+)\^(\d)\^([\w\s\'\-\(\)\:\+\.\,\"\/\%\#\<\>]+?)\^[0]\^$', line)
      if (result != None and result.group(2) == '1'):
        titles[int(result.group(1))] = result.group(3)
      elif (result != None and result.group(2) == '4'):
        descs[int(result.group(1))] = result.group(3)
        
    if (len(titles) > 0):
      print('Found %d titles' % len(titles))
    else:
      print('No titles found, copy over latest from your EQ directory?')
    if (len(descs) > 0):
      print('Found %d descriptions' % len(descs))
    else:
      print('No descriptions found, copy over latest from your EQ directory?')
  else:
    print('%s is missing No titles or descriptions will be loaded.' % DBStringsFile)
  return descs, titles

# Spells US Example: 2754^Frenzied Burnout I^
def loadDBSpells():
  spells = dict()
  if os.path.isfile(DBSpellsFile):
    print('Loading Spells DB from %s' % DBSpellsFile)
    db = open(DBSpellsFile, 'r')
    for line in db:
      result = re.match(r'^(\d+)\^([\w\s\'\-\(\)\:\+]+?)\^', line)
      if (result != None):
        spells[int(result.group(1))] = result.group(2)
    if (len(spells) > 0):
      print('Found %d entries' % len(spells))
    else:
      print('No data found, copy over latest from your EQ directory?')
  else:
    print('%s is missing. No spells will be loaded.' % DBSpellsFile)
  return spells
