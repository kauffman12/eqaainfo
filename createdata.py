import os.path

DBSpellsFile = 'data/spells_us.txt'
DBSpellsStrFile = 'data/spells_us_str.txt'

RANK_LETTERS = [ 'X', 'V', 'I', 'L', 'C', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' ]

IGNORE_LIST = [ 'MRC -', 'Reserved', 'AB-Test-TAB', 'SumUNMm', 'RESERVED', 'Brittle Haste', 'SKU', 'Type 3', 'Type3', 'ShapeChange', 'BETA', 'Beta', 'ABTest', 'test ', 'Test ', ' Test ', ' test ', 'Test1', 'Test2', 'Test3', 'Test4', 'Test5', 'N/A', 'NA ', 'TEST', 'PH', 'Placeholder' ]

IS_NOT_PROC = [ 'Cloaked Blade', 'Twincast' ] # also appended to later
IS_PROC = [ 'Arcane Fusion', 'Banestrike', 'Blessing of Life', 'Blessing of the Faithful', 'Bite of the Asp', 'Call of Fire Strike', 'Cascade of Decay Rot', 'Cascading Theft of Defense', 'Cascading Theft of Life', 'Color Shock Stun', 'Cryomancy', 'Decapitation', 'Distracting Strike', 'Divine Surge of Battle', 'Envenomed Blade', 'Eye Gouge', 'Feral Swipe', 'Fists of Fury', 'Flurry of Daggers', 'Frenzied Volley', 'Gelid Claw', 'Gorilla Smash', 'Gut Punch Strike', 'Healing Light', 'Heavy Arrow', 'Hunter\'s Fury', 'Infused by Rage', 'Nature\'s Reprieve', 'Languid Bite', 'Phalanx of Fury', 'Phantasmic Reflex', 'Recourse of Life', 'Sanctified Blessing', 'Uncontained Frenzy', 'Lethality', 'Massive Strike', 'Mortal Coil', 'Overdrive Punch', 'Presence of Fear', 'Pyromancy', 'Reluctant Lifeshare', 'Resonant Kick', 'Resonant Strike', 'Soul Flay', 'Strike of Ire', 'Strike Fury', 'Thunderfoot', 'Theft of Essence', 'Touch of the Cursed', ]

ADPS_CASTER_VALUE = 1
ADPS_MELEE_VALUE = 2
ADPS_ALL_VALUE = ADPS_CASTER_VALUE + ADPS_MELEE_VALUE

BASE1_PROC_LIST = [ 85, 419, 427, 429 ]
BASE2_PROC_LIST = [ 339, 340, 374, 383, 481 ]

ADPS_CASTER = [ 15, 118, 124, 127, 132, 170, 212, 273, 286, 294, 302, 303, 339, 351, 358, 374, 375, 383, 399, 413, 461, 462, 501, 507 ]

ADPS_MELEE = [ 2, 4, 5, 6, 11, 118, 119, 169, 171, 176, 177, 182, 184, 185, 186, 189, 198, 200, 216, 220, 225, 227, 250, 252, 258, 266, 279, 280, 330, 339, 351, 364, 374, 383, 418, 427, 429, 433, 459, 471, 473, 482, 496, 498, 499 ]

ADPS_LIST = ADPS_CASTER + ADPS_MELEE

ADPS_B1_MIN = dict()
ADPS_B1_MIN[11] = 100

ADPS_B1_MAX = dict()
ADPS_B1_MAX[182] = 0

ADPS_EXT_DUR = dict()
# bard
ADPS_EXT_DUR[4516] = 1    # Improved Deftdance Disc
ADPS_EXT_DUR[8030] = 2    # Improved Thousand Blades Disc
# beast
ADPS_EXT_DUR[4671] = 1    # Improved Protective Spirit Disc
# berserker
ADPS_EXT_DUR[8003] = 90   # Extended Havoc
ADPS_EXT_DUR[36556] = 90
ADPS_EXT_DUR[36557] = 90
ADPS_EXT_DUR[36558] = 90
ADPS_EXT_DUR[5041] = 3    # Improved Berserking Disc
ADPS_EXT_DUR[10923] = 3
ADPS_EXT_DUR[10924] = 3
ADPS_EXT_DUR[10925] = 3
ADPS_EXT_DUR[14189] = 3
ADPS_EXT_DUR[14190] = 3
ADPS_EXT_DUR[14191] = 3
ADPS_EXT_DUR[30463] = 3
ADPS_EXT_DUR[30464] = 3
ADPS_EXT_DUR[30465] = 3
ADPS_EXT_DUR[36529] = 3
ADPS_EXT_DUR[36530] = 3
ADPS_EXT_DUR[36531] = 3
ADPS_EXT_DUR[27257] = 2   # Improved Cleaning Acrimony Disc
ADPS_EXT_DUR[27258] = 2
ADPS_EXT_DUR[27259] = 2
#ranger
ADPS_EXT_DUR[4506] = 20   # Improved Trueshot Disc
ADPS_EXT_DUR[15091] = 20
ADPS_EXT_DUR[15092] = 20
ADPS_EXT_DUR[15093] = 20
ADPS_EXT_DUR[19223] = 20
ADPS_EXT_DUR[19224] = 20
ADPS_EXT_DUR[19225] = 20
ADPS_EXT_DUR[25525] = 20
ADPS_EXT_DUR[25526] = 20
ADPS_EXT_DUR[25527] = 20
ADPS_EXT_DUR[40123] = 20
ADPS_EXT_DUR[40124] = 20
ADPS_EXT_DUR[40125] = 20
# rogue
ADPS_EXT_DUR[35333] = 5   # Extended Aspbleeder Disc
ADPS_EXT_DUR[35334] = 5
ADPS_EXT_DUR[35335] = 5
ADPS_EXT_DUR[44169] = 5
ADPS_EXT_DUR[44170] = 5
ADPS_EXT_DUR[44171] = 5
ADPS_EXT_DUR[56321] = 5
ADPS_EXT_DUR[56322] = 5
ADPS_EXT_DUR[56323] = 5
ADPS_EXT_DUR[59643] = 5
ADPS_EXT_DUR[59644] = 5
ADPS_EXT_DUR[59645] = 5
ADPS_EXT_DUR[35327] = 15  # Improved Fatal Aim Disc
ADPS_EXT_DUR[35328] = 15
ADPS_EXT_DUR[35329] = 15
ADPS_EXT_DUR[56288] = 15 
ADPS_EXT_DUR[56289] = 15
ADPS_EXT_DUR[56290] = 15
ADPS_EXT_DUR[6197] = 2    # Improved Frenzied Stabbing Disc
ADPS_EXT_DUR[8001] = 90   # Improved Thief's Eyes
ADPS_EXT_DUR[40294] = 90
ADPS_EXT_DUR[40295] = 90
ADPS_EXT_DUR[40296] = 90
ADPS_EXT_DUR[4695] = 5    # Improved Twisted Chance Disc
# monk
ADPS_EXT_DUR[14820] = 3   # Extended Crystalpalm Discipline 
ADPS_EXT_DUR[14821] = 3
ADPS_EXT_DUR[14822] = 3
ADPS_EXT_DUR[18925] = 3
ADPS_EXT_DUR[18926] = 3
ADPS_EXT_DUR[18927] = 3
ADPS_EXT_DUR[29030] = 3
ADPS_EXT_DUR[29031] = 3
ADPS_EXT_DUR[29032] = 3
ADPS_EXT_DUR[35071] = 3
ADPS_EXT_DUR[35072] = 3
ADPS_EXT_DUR[35073] = 3
ADPS_EXT_DUR[8473] = 3    # Extended Heel of Kanji Disc
ADPS_EXT_DUR[25941] = 3
ADPS_EXT_DUR[25942] = 3
ADPS_EXT_DUR[25943] = 3
ADPS_EXT_DUR[29048] = 3
ADPS_EXT_DUR[29049] = 3
ADPS_EXT_DUR[29050] = 3
ADPS_EXT_DUR[35086] = 3
ADPS_EXT_DUR[35087] = 3
ADPS_EXT_DUR[35088] = 3
ADPS_EXT_DUR[10938] = 2   # Extended Impenetrable Disc
ADPS_EXT_DUR[10939] = 2
ADPS_EXT_DUR[10940] = 2
ADPS_EXT_DUR[10941] = 2
ADPS_EXT_DUR[10942] = 2
ADPS_EXT_DUR[10943] = 2
ADPS_EXT_DUR[4690] = 2
ADPS_EXT_DUR[35089] = 2
ADPS_EXT_DUR[35090] = 2
ADPS_EXT_DUR[35091] = 2
ADPS_EXT_DUR[11922] = 2   # Improved Scaledfist Disc
ADPS_EXT_DUR[11923] = 2
ADPS_EXT_DUR[11924] = 2
ADPS_EXT_DUR[25923] = 2
ADPS_EXT_DUR[25924] = 2
ADPS_EXT_DUR[25925] = 2
ADPS_EXT_DUR[4691] = 3    # Improved Speed Focus Disc

def inProcList(name):
  for test in IS_PROC:
    if test in name:
      return True 
  return False

def inNotProcList(name):
  for test in IS_NOT_PROC:
    if name == test:
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

def getAdpsValue(current, spa):
  if current == ADPS_ALL_VALUE:
    return current
  updated = 0
  if spa in ADPS_CASTER:
    updated = ADPS_CASTER_VALUE
  if spa in ADPS_MELEE:
    updated = updated + ADPS_MELEE_VALUE
  if current > 0:
    updated = updated | current 
  return updated

dbStrings = dict()
if os.path.isfile(DBSpellsStrFile):
  print('Loading Spell Strings from %s' % DBSpellsStrFile)
  db = open(DBSpellsStrFile, 'r')
  for line in db:
    data = line.split('^')

    try:
      id = int(data[0])
      landOnYou = data[3]
      landOnOther = data[4]
      wearOff = data[5]
      dbStrings[id] = { 'landsOnYou': landOnYou, 'landsOnOther': landOnOther, 'wearOff': wearOff }
    except ValueError:
      pass

if os.path.isfile(DBSpellsFile):
  print('Loading Spells DB from %s' % DBSpellsFile)
  myDB = dict()
  procDB = dict()

  for line in open(DBSpellsFile, 'r'):
    data = line.split('^')
    id = int(data[0])
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

    abbrv = abbreviate(name)
    castTime = int(data[8])
    lockoutTime = int(data[9])
    recastTime = int(data[10])
    maxDuration = int(data[12])
    manaCost = int(data[14])
    beneficial = int(data[30])
    spellTarget = int(data[32])
    combatSkill = int(data[101])
    maxHits = int(data[105])
    durationExtendable = int(data[125])

    # apply 100% buff extension
    if beneficial != 0 and durationExtendable == 0 and combatSkill != 1 and maxDuration > 1:
      maxDuration = maxDuration * 2

    # add focus AAs that extend duration
    if id in ADPS_EXT_DUR:
      maxDuration = maxDuration + ADPS_EXT_DUR[id]

    classMask = 0
    minLevel = 255
    for i in range(38, 38+16):
      level = int(data[i])
      if level <= 254:
        classMask += (1 << (i - 38))
        minLevel = min(minLevel, level)

    adps = 0
    damaging = 0
    for slot in data[-1].split('$'):
      values = slot.split('|')
      if len(values) > 1:
        spa = int(values[1])
        base1 = int(values[2])
        base2 = int(values[3])
        if beneficial == 0 and (spa == 0 or spa == 79):
          damaging = 1

        if spa in BASE1_PROC_LIST:
          procDB[base1] = spa
        elif spa in BASE2_PROC_LIST:
          if (spa != 374 and spa != 340) or (manaCost == 0 and castTime == 0):
            if spa == 85:
              IS_NOT_PROC.append(abbrv) # there's a proc loop for things
            procDB[base2] = spa
        if spa in ADPS_LIST:
          if spa in ADPS_B1_MIN:
            if base1 >= ADPS_B1_MIN[spa]:
              adps = getAdpsValue(adps, spa)
          elif spa in ADPS_B1_MAX:
            if base1 < ADPS_B1_MAX[spa]:
              adps = getAdpsValue(adps, spa)
          elif base1 >= 0:
            adps = getAdpsValue(adps, spa)

    # ignore long term beneficial buffs like FIRE DAMAGE
    # howerver allow their SPAs to be checked for procs so continue at the end
    if maxDuration == 1950 and castTime == 0 and lockoutTime == 0 and recastTime == 0 and beneficial != 0:
      continue

    if id in dbStrings:
      spellData = '%s^%s^%d^%d^%d^%d^%d^%d^%d^%d^%d^%s^%s^%s' % (id, name, minLevel, maxDuration, beneficial, maxHits, spellTarget, classMask, damaging, combatSkill, adps, dbStrings[id]['landsOnYou'], dbStrings[id]['landsOnOther'], dbStrings[id]['wearOff'])
      myDB[id] = dict()
      myDB[id]['abbrv'] = abbrv
      myDB[id]['spellData'] = spellData
      myDB[id]['level'] = minLevel

  output = open('output.txt', 'w')

  i = 0
  for spellId in sorted(myDB.keys()):
    spellInfo = myDB[spellId]

    proc = 0
    if (spellId in procDB and not inNotProcList(spellInfo['abbrv'])) or inProcList(spellInfo['abbrv']):
      if spellInfo['level'] > 250: # extra check for regular spells picked up
        proc = 1

    spellData = '%s^%d' % (spellInfo['spellData'], proc)
    output.write('%s\n' % spellData)
    i += 1

else:
  print('%s is missing. No spells will be loaded.' % DBSpellsFile)
