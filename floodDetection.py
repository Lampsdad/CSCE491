import pyshark
import tlsh
import os
from collections import defaultdict
import csv


'''
Note that the ".." will need to be changed based on the enviroment it is being run in.

This script goes through an entire packet based on a block size of 20.
It splits based on converstations and the tlsh hashes are put into the file.
'''

def extract_identifier(packet):
    try:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        identifier = f"{src_ip}_to_{dst_ip}"
    except AttributeError:
        identifier = None
    return identifier


def hash_packets(packet_block):
    combined_packet_data = b''
    for packet in packet_block:
        combined_packet_data += str(packet).encode()

    hash_result = tlsh.hash(combined_packet_data)
    return hash_result


def process_packets(filepath, block_size):
    packets = pyshark.FileCapture(filepath)
    conversation_blocks = defaultdict(list)
    file_handles = {}
    os.makedirs('/home/noam/capstoneFiles/conversations')
    os.chdir('/home/noam/capstoneFiles/conversations')

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


def count_lines(file_path):
    with open(file_path, 'r') as file:
        return sum(1 for line in file)


def compare_hashes_and_score(input_file, output_file):
    with open(input_file, 'r') as f:
        hashes = f.read().splitlines()

    with open(output_file, 'a') as output:
        for i,base_hash in enumerate(hashes[:-1]):
            for other_hash in hashes[i:-1]:
                if base_hash and other_hash:
                    score = tlsh.diff(base_hash, other_hash)
                    if score > 80:
                        output.write(f"{base_hash},{other_hash},{score}\n")


if __name__ == "__main__":

    # Initial run (sometimes errors/crashes and takes a long time)

    file = "/home/noam/capstoneFiles/eth2dump-pingFloodDDoS-1m-12h_1.pcap"
    try:
        process_packets(file, 20) # Get converstation files with hashes, block size 20 
    except:
        print("error")
    print("Done processing.")

    # Find file with most lines

    max_lines = 0
    max_file = None
    directory = "/home/noam/capstoneFiles/conversations"
    
    for file_name in os.listdir(directory):
        file_path = os.path.join(directory, file_name)
        if os.path.isfile(file_path):
            lines = count_lines(file_path)
            if lines > max_lines:
                max_lines = lines
                max_file = file_path

    # Start similarity scores
    
    print("Max Lines:", max_lines)
    # print("File:", max_file)
    if max_lines > 10000: # Value can be changed or made dynamic as needed
        input_file = max_file
        output_file = "similarity_scores.csv"
        
        open(output_file, 'w').close()
        
        compare_hashes_and_score(input_file, output_file)
        print("Done comparing")
        
        with open(output_file, 'r') as file:
            lines = file.readlines()

        print("Lines:", len(lines))
        if len(lines) < 200: # Value can be changed or made dynamic as needed
            print("Detected.")
