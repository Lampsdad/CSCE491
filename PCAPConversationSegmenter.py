#Takes a PCAP file and segments it into conversations between two IP addresses
#Saves each conversation to a file in the directory "Conversations". If this directory does not exist, create it.

#Imports
import pyshark
import os
import json
import tlsh

#Conversation Class
class Conversation:
    #Constructor
    def __init__(self, packet):
        #Create a list to store the packets
        self.packets = []
        #Add the packet to the list
        self.packets.append(packet)
        #Create a list to store the IP addresses
        self.ips = []
        #Add the source and destination IP addresses to the list
        self.ips.append(packet.ip.src)
        self.ips.append(packet.ip.dst)
        #Create a list to store the ports
        self.ports = []
        #Add the source and destination ports to the list
        self.ports.append(packet.tcp.srcport)
        self.ports.append(packet.tcp.dstport)
        #Create a string to store the name of the file
        self.name = "Conversations/" + self.ips[0] + "_" + self.ports[0] + "_" + self.ips[1] + "_" + self.ports[1] + ".pcap"
        #Create a file to store the conversation
        self.file = open(self.name, 'w')
        #Write the packet to the file
        self.file.write(str(packet))
        #Close the file
        self.file.close()
    
    #Add Packet Function
    def AddPacket(self, packet):
        #Open the file
        self.file = open(self.name, 'a')
        #Write the packet to the file
        self.file.write(str(packet))
        #Close the file
        self.file.close()
        #Add the packet to the list
        self.packets.append(packet)

#Main Function
def main():
    #add the functionality for command line arguments
    #take the file from the command line
    file = input("Enter the file to segment: ")
    #open the file
    pcap = pyshark.FileCapture(file)
    #create a list to store the conversations
    conversations = []
    #iterate through the file
    for packet in pcap:
        #check if the packet is part of a conversation
        found = False
        for conversation in conversations:
            if conversation.ips[0] == packet.ip.src and conversation.ips[1] == packet.ip.dst and conversation.ports[0] == packet.tcp.srcport and conversation.ports[1] == packet.tcp.dstport:
                conversation.AddPacket(packet)
                found = True
                break
            elif conversation.ips[0] == packet.ip.dst and conversation.ips[1] == packet.ip.src and conversation.ports[0] == packet.tcp.dstport and conversation.ports[1] == packet.tcp.srcport:
                conversation.AddPacket(packet)
                found = True
                break
        if not found:
            conversations.append(Conversation(packet))
    #close the file
    pcap.close()

    

#Call Main Function
if __name__ == "__main__":
    main()