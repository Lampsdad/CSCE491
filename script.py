# Plan For Python Program
#1. Ask user for input file
#2. Send file to a packet blocking function
#3. In the packet blocking function, read in x packets and send to a hashing function
#4. In the hashing function, run tlsh on the packet block and save output to the next line of a txt file
#5. Repeat steps 3 and 4 until all packets are read in
#6. Close the file and return to the main function
#7. Take in the output file
#8. Similiarity score bs the hashes
#9. look for massive variations in the hashes under a defined range
#10. Report any suspicious packet clusters
#11. Close the program

import pyshark
import tlsh
import os
from collections import defaultdict

def extract_identifier(packet):
    """
    Extracts a unique identifier from a packet based on IP addresses and ports.
    """
    try:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        src_port = packet[packet.transport_layer].srcport
        dst_port = packet[packet.transport_layer].dstport
        # Make identifier direction-agnostic.
        identifier = "_".join(["-".join(pair) for pair in sorted([(src_ip, src_port), (dst_ip, dst_port)])]) # does this work?
    except AttributeError:
        print("Attribute Error in extract_identifier")
        identifier = None
    return identifier

def hash_packets(packet_block):
    """
    Hashes a block of packets, prioritizing Modbus layer data; falls back to TCP layer data if Modbus is absent.
    """
    combined_packet_data = b''
    for packet in packet_block:
        combined_packet_data += str(packet).encode()
        # print(packet_block)
        # try:
        #     # Check for Modbus layer first
        #     if 'MODBUS' in packet:
        #         modbus_data = packet.modbus
        #         # Concatenate important fields from the Modbus layer
        #         # Adjust this according to the specific Modbus fields you're interested in
        #         data = str(modbus_data).encode('utf-8')
        #     elif 'TCP' in packet:
        #         # Fallback to TCP layer if no Modbus layer is present
        #         tcp_data = packet.tcp
        #         # Concatenate relevant fields from the TCP layer
        #         # Adjust based on the TCP attributes you're interested in
        #         data = str(tcp_data).encode('utf-8')
        #     else:
        #         data = b''
                
        # except AttributeError:
        #     # Skip packets that don't have the expected layers or attributes
        #     continue

    #print("Hashing the following: ", combined_packet_data)
    hash_result = tlsh.hash(combined_packet_data)
    return hash_result

def process_packets(filepath, block_size=10):
    """
    Processes packets from the pcap file, hashes them in blocks by conversation, and writes to files.
    """
    # Open the pcap file
    packets = pyshark.FileCapture(filepath)
    # Store packets in blocks by conversation
    conversation_blocks = defaultdict(list)
    file_handles = {}
    # Create a directory to store the output files if it doesn't already exist
    if not os.path.exists('conversations'):
        os.makedirs('conversations')
    os.chdir('conversations')

    # Loop through each packet in the pcap and process them into bocks
    for packet in packets:
        print("Creating File")
        # Extract a unique identifier for the conversation
        identifier = extract_identifier(packet)
        if identifier:
            conversation_blocks[identifier].append(packet)
            if len(conversation_blocks[identifier]) == block_size:
                # When a block for a conversation is complete, hash it and write the hash.
                print("sending to hash packets")
                hash_result = hash_packets(conversation_blocks[identifier])
                if identifier not in file_handles:
                    file_handles[identifier] = open(f'conversation_{identifier}.txt', 'w')
                file_handles[identifier].write(hash_result + '\n')
                # Clear the current block for the conversation.
                conversation_blocks[identifier] = []

    # Process any remaining packets in incomplete blocks.
    for identifier, block in conversation_blocks.items():
        if block:
            hash_result = hash_packets(block)
            file_handles[identifier].write(hash_result + '\n')

    # Clean up: close all file handles.
    for f in file_handles.values():
        f.close()

def main():
    filepath = "/home/willt/classes/csce491/CSCE491/datasets/Modbus Dataset/benign/ied1a/ied1a-network-capture/veth4edc015-normal-4.pcap"
    process_packets(filepath)
    print("Analysis Complete. Check the 'conversations' directory for output files of each conversation.")

if __name__ == "__main__":
    main()
