from scapy.all import *

def sniffer(pkt):
	#print(pkt.summary())   #summary()/show()FOR DISPLAYING ALL PACKETS IN YOUR NETWORK
	print(pkt[TCP].show())
	
sniff(filter='tcp and (port 80 or port 443)', count=10, prn=sniffer) #filter is used for http and https
