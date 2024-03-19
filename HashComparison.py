#Imports
import json
import tlsh
import os

#Take in a file and compare the hash against the JSON file of hashes
def main():
    #Ask the user for the file to hash
    file = input("Enter the file to hash: ")
    #Print out the hash
    print(tlsh.hash(open(file, 'rb').read()))
    #open the JSON file 'hashes.json'
    #compare the hash to the hashes in the JSON file and print out the top 10 closest matches
    
#Call the main function
if __name__ == "__main__":
    main()