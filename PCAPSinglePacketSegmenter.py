#imports
import tlsh
import pyshark
import json
import os

#binary tree class
class BinaryTree:
    def __init__(self, root):
        self.left = None
        self.right = None
        self.root = root

#Segment the file into seperate PCAPS in a binary search style
def createBinaryTreePCAPs(file):
    #open the file
    pcap = pyshark.FileCapture(file)
    #create the first node
    root = BinaryTree(pcap[0])
    #iterate through the file
    for packet in pcap:
        #check if the packet is less than the root
        if packet < root.root:
            #check if the left node is empty
            if root.left == None:
                #create a new node
                root.left = BinaryTree(packet)
            else:
                #iterate through the tree
                current = root.left
                while current != None:
                    #check if the packet is less than the current node
                    if packet < current.root:
                        #check if the left node is empty
                        if current.left == None:
                            #create a new node
                            current.left = BinaryTree(packet)
                            break
                        else:
                            #iterate through the tree
                            current = current.left
                    else:
                        #check if the right node is empty
                        if current.right == None:
                            #create a new node
                            current.right = BinaryTree(packet)
                            break
                        else:
                            #iterate through the tree
                            current = current.right
        else:
            #check if the right node is empty
            if root.right == None:
                #create a new node
                root.right = BinaryTree(packet)
            else:
                #iterate through the tree
                current = root.right
                while current != None:
                    #check if the packet is less than the current node
                    if packet < current.root:
                        #check if the left node is empty
                        if current.left == None:
                            #create a new node
                            current.left = BinaryTree(packet)
                            break
                        else:
                            #iterate through the tree
                            current = current.left
                    else:
                        #check if the right node is empty
                        if current.right == None:
                            #create a new node
                            current.right = BinaryTree(packet)
                            break
                        else:
                            #iterate through the tree
                            current = current.right
    #return the root
    return root

#main function
def main():
    #ask the user which file to segment
    file = input("Enter the file to segment: ")
    #create the binary tree
    root = createBinaryTreePCAPs(file)
    #iterate through the tree and generate a hash using tlsh for each node
    #verify that the packet is over 50 bytes of data
    #save the hash to a json file
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
    current = root
    while current != None:
        if len(current.root) > 50:
            data['hashes'].append({
                'file': file,
                'hash': tlsh.hash(current.root)
            })
        if current.left != None:
            current = current.left
        elif current.right != None:
            current = current.right
        else:
            current = None
    with open(file + '.json', 'w') as outfile:
        json.dump(data, outfile, indent=4)


#run main
if __name__ == "__main__":
    main()