#imports
import tlsh

#main function
def main():
    #ask the user which file to hash
    file = input("Enter the file to hash: ")
    #print out the hash
    print(tlsh.hash(open(file, 'rb').read()))

#call the main function
if __name__ == "__main__":
    main()