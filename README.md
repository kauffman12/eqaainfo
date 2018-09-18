# eqaainfo
Read EQ AA data from network capture

Instructions:
1. Capture network data to a PCAP file using tools such as Wireshark or tcpdump
2. Login to Test server and reset/rebuy your AAs during the capture
3. Copy dbstr_us.txt from your Everquest directory to ./data if you want titles to display
4. Copy spells_us.txt from your Everquest direction to ./data if you want spell names to display
5. Execute: py aainfo.py [path to pcap file]
