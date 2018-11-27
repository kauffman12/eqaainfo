# list in bit order for augment types
AugTypes = []
for i in range(32):
  AugTypes.append(i + 1)

# list in bit order for classes
ClassTypes = ['War', 'Clr', 'Pal', 'Rng', 'Shd', 'Dru', 'Mnk', 'Brd', 'Rog', 'Shm', 'Nec', 'Wiz', 'Mag', 'Enc', 'Bst', 'Ber', 'Merc']

# list in bit order for slots
SlotTypes = [ 'Charm', 'Ear', 'Head', 'Face', 'Ear2', 'Neck', 'Shoulders', 'Arms', 'Back', 'Wrist', 'Wrist2', 'Range', 
          'Hands', 'Primary', 'Secondary', 'Fingers', 'Fingers2', 'Chest', 'Legs', 'Feet', 'Waist', 'Ammo', 'Power' ]


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