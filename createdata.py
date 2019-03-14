import os.path

DBSpellsFile = 'data/spells_us.txt'
DBSpellsStrFile = 'data/spells_us_str.txt'
RANK_LETTERS = [ 'X', 'V', 'I', 'L', 'C', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' ]
IGNORE_LIST = [ 'Reserved', 'RESERVED', 'SKU', 'Type 3', 'Type3', 'BETA', 'Beta', 'Damage', 'N/A', 'NA ', 'TEST', 'PH', 'Placeholder' ]
NOT_PROC = [ 'Cacophony', 'Necromantic Curse', 'Shock of Magic' ]
IS_PROC = [ 'Arcane Fusion', 'Blood Pact Strike', 'Cryomantic Stasis', 'Decapitation', 'Envenomed Blades Strike', 'Infusion of Thunder Shock', 'Pyromantic Ignition', 'Second Spire of the Savage Lord Strike', 'Storm Blade Strike', 'Synergy Strike', 'Zan Fi\'s Echoes Strike' ]

def inNotProcList(name):
  for test in NOT_PROC:
    if test in name:
      return True 
  return False

def inProcList(name):
  for test in IS_PROC:
    if test in name:
      return True 
  return False

def abbreviate(name):
  result = name
  rankIndex = name.find(' Rk.')
  if rankIndex > -1:
    result = name[0:rankIndex]
  else:
    lastSpace = name.rfind(' ')
    if lastSpace > -1:
      hasRank = True
      for i in range(lastSpace+1, len(name)):
        if name[i] not in RANK_LETTERS:
          hasRank = False
          break
      if hasRank:
        result = name[0:lastSpace]
  return result

dbStrings = dict()
if os.path.isfile(DBSpellsStrFile):
  print('Loading Spell Strings from %s' % DBSpellsStrFile)
  db = open(DBSpellsStrFile, 'r')
  for line in db:
    data = line.split('^')
    id = data[0]
    landOnYou = data[3]
    landOnOther = data[4]
    dbStrings[id] = { 'landsOnYou': landOnYou, 'landsOnOther': landOnOther }

if os.path.isfile(DBSpellsFile):
  print('Loading Spells DB from %s' % DBSpellsFile)
  db = open(DBSpellsFile, 'r')
  myDB = []
  for line in db:
    data = line.split('^')
    id = data[0]
    name = data[1]
    if len(name) <= 3:
      continue

    skip = False
    for ignore in IGNORE_LIST:
      if ignore in name:
        skip = True
        break
    if skip:
      continue

    beneficial = int(data[30])
    proc = 0
    classMask = 0
    for i in range(38, 38+16):
      level = int(data[i])
      if level <= 254:
        classMask += (1 << (i - 38))

    if classMask == 0 and not inNotProcList(name):
      proc = 1
    elif classMask != 0 and inProcList(name):
      proc = 1
	  
    damaging = 0
    if beneficial == 0:
      for spa in data[-1].split('$'):
        values = spa.split('|')
        if len(values) > 1:
          if values[1] == '0' or values[1] == '79':
            damaging = 1

    if id in dbStrings:
      entry = '%s^%s^%d^%d^%s^%s^%s^%s' % (id, name, beneficial, classMask, dbStrings[id]['landsOnYou'], dbStrings[id]['landsOnOther'], damaging, proc)
      myDB.append(entry)

  output = open('output.txt', 'w')

  i = 0
  for entry in myDB:
    output.write('%s\n' % entry)
    i += 1

else:
  print('%s is missing. No spells will be loaded.' % DBSpellsFile)
