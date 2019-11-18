# eqaainfo
Parse EQ AA data from network capture

Requirements:
1. Install Python 3.6+ https://www.python.org/downloads/windows/
2. Install Scapy module (py -m pip install scapy)

Additional Requirements to use included capture script
1. Install npcap from https://nmap.org/npcap/

Parse AA Data Instructions:
1. Start capturing UDP network data to a PCAP file using Wireshark, tcpdump or the provided capture.py script
2. Login to Test server and reset/rebuy your AAs while the capture is running
3. Stop the capture once all AAs have been bought
4. Copy dbstr_us.txt and spells_us.txt from your Everquest directory to ./data
5. Run the parse script (py parse.py [path to pcap file])
6. Data is written to aainfo.txt in the current directory

Using Network Capture Script:
1. py capture.py [path to output file]
2. Hit Ctrl+C to stop the capture
