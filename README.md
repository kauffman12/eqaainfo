# eqaainfo
Parse EQ AA data from network capture

Requirements:
1. Install Python 3.6+ https://www.python.org/downloads/windows/
2. Install Scapy module (py -m pip install scapy)

Additional Requirements if using included capture script:
1. Install npcap from https://nmap.org/npcap/

Parse AA Data Instructions:
1. Start capturing UDP network data to a PCAP file using Wireshark, tcpdump or the provided capture.py script
2. Login to Test server and reset/rebuy your AAs while the capture is running
3. Make sure to purchase Battle Ready, Packrat, and Innate Metabolism so the AA opcode can be found, the opcode search happens automatically during parsing but one can be specified by editing the script at the top
4. Stop the capture once all AAs have been bought
5. Copy dbstr_us.txt and spells_us.txt from your Everquest directory to ./data
6. Edit parse.py and change the output format as desired.
7. Run the parse script (py parse.py [path to pcap file])
8. Data is written to aainfo.txt in the current directory

Using Network Capture Script:
1. py capture.py [path to output file]
2. Hit Ctrl+C to stop the capture

Notes:

The default output format is set to what is used by raidloot.com. If you change it to 'PRETTY' it'll be easier to read. Also, if you do capture new AAs which are not listed on raidloot.com then consider emailing a copy to them in their format so it's made available to everyone.

Additionally, an itemparse.py is included here for parsing item data. It's a work in-progress and may not be up to date. It can either read a pcap file or parse live data.
