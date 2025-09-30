# port-scanner
 A python based port scanner which will do tcp syn scan. The tool has two modes, like stealth and aggressive modes. Choosing aggressive scan will give more details about that port.

 <img width="727" height="719" alt="Screenshot 2025-09-29 153808" src="https://github.com/user-attachments/assets/6f7b02c0-c007-47ce-8530-8f1c12567976" />

# How to Use:

clone the repo by using this command

git clone https://github.com/Rajeevgaddam/port-scanner.git

To run this tool we require python, most of the linux based operating systems will have this python in built.

This tool uses scapy, so install scapy with this command

sudo apt install python3-scapy

now run the tool using this command

sudo python3 portscan.py

# for windows

Download the zip file from https://github.com/Rajeevgaddam/port-scanner

go to the port-scanner folder with this command

cd Downloads\port-scanner-main\port-scanner-main

To use this python mandatory, Download it from https://www.python.org/downloads/

Download scapy module to use this tool with this command

pip install scapy

Download npcap to send the tcp syn packets from this website https://npcap.com/#download

Execute the tool with administrator priviledges with this command

py portscan.py
