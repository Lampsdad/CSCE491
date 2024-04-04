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
    Extracts a unique identifier from a packet based on IP addresses and the destination port.
    Only cares about packets where the destination port is 502.
    """
    try:
        dst_port = packet[packet.transport_layer].dstport
        if dst_port == '502':
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            identifier = f"{src_ip}_to_{dst_ip}"
        else:
            return None
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

    hash_result = tlsh.hash(combined_packet_data)
    return hash_result

def process_packets(filepath, block_size=10):
    """
    Processes packets from the pcap file, hashes them in blocks by conversation, and writes to files.
    """
    packets = pyshark.FileCapture(filepath)
    conversation_blocks = defaultdict(list)
    file_handles = {}
    if not os.path.exists('../resources/conversations'):
        os.makedirs('../resources/conversations')
    os.chdir('../resources/conversations')

    for packet in packets:
        identifier = extract_identifier(packet)
        if identifier:
            conversation_blocks[identifier].append(packet)
            if len(conversation_blocks[identifier]) == block_size:
                hash_result = hash_packets(conversation_blocks[identifier])
                if identifier not in file_handles:
                    file_handles[identifier] = open(f'conversation_{identifier}.txt', 'w')
                file_handles[identifier].write(hash_result + '\n')
                conversation_blocks[identifier] = []

    for identifier, block in conversation_blocks.items():
        if block:
            hash_result = hash_packets(block)
            file_handles[identifier].write(hash_result + '\n')

    for f in file_handles.values():
        f.close()

def main():
    filepath = os.getcwd() + "/../resources/Modbus Dataset/benign/ied1b/ied1b-network-capture/vethd9e14c0-normal-10.pcap"
    process_packets(filepath)
    print("Analysis Complete. Check the 'conversations' directory for output files of each conversation.")

if __name__ == "__main__":
    main()
