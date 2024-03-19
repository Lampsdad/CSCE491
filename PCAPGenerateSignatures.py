#Look recursively through a directory of PCAP files and generate a signature for each file using tlsh.
#Imports
import json
import pyshark
import tlsh
import os

#Generate a list of pcap files in the directory
def GenerateFileList(directory):
    #Create an empty list to store the files
    files = []
    #Loop through all the files in the 'directory' list
    for file in os.listdir(directory):
        #Check if the file is a pcap file
        if file.endswith(".pcap"):
            #Add the file to the list
            files.append(directory + '/' + file)
        #Check if there is a subdirectory
        if os.path.isdir(directory + '/' + file):
            #Recursively call the function to get the files in the subdirectory
            files += GenerateFileList(directory + '/' + file)
    #Return the list of files
    return files

#Main Function
def main():
    #Ask the user for the directory to search through
    directory = input("Enter the directory to search through: ")
    files = GenerateFileList(directory)
    hashes = []
    #Loop through all the files in the 'directory' list and generate a signature for each file
    for file in files:
        #print out the hash
        print(tlsh.hash(open(file, 'rb').read()))
        #save the hash to the list
        hashes.append(tlsh.hash(open(file, 'rb').read()))
    
    #loop through the hashes and file names and save them to a json file
    #like this:
    # {
    #     "hashes": [
    #         {
    #             "hash": "hash1",
    #             "file": "file1"
    #         },
    #         {
    #             "hash": "hash2",
    #             "file": "file2"
    #         }
    #     ]
    # }
    data = {}
    data['hashes'] = []
    for i in range(len(hashes)):
        data['hashes'].append({
            'file': files[i],
            'hash': hashes[i]
        })
    with open('signatures.json', 'w') as outfile:
        json.dump(data, outfile, indent=4)

#Call the main function
if __name__ == "__main__":
    main()
