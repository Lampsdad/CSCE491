import tlsh
import csv
import os

def sort_csv_by_column_numerically(input_file, output_file, column_index, header_present=True):
    """
    Sorts a CSV file based on the specified column index numerically.

    Parameters:
    - input_file: Path to the input CSV file.
    - output_file: Path to the output CSV file where the sorted data will be written.
    - column_index: The index of the column to sort by (0-based).
    - header_present: Indicates whether the first row of the CSV is a header.
    """

    with open(input_file, mode='r', newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        if header_present:
            header = next(reader)
        else:
            header = None
        
        data = list(reader)

    sorted_data = sorted(data, key=lambda row: float(row[column_index]))

    with open(output_file, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        if header:
            writer.writerow(header)
        writer.writerows(sorted_data)

def compare_hashes_and_score(input_file, output_file):
    with open(input_file, 'r') as f:
        hashes = f.read().splitlines()

    with open(output_file, 'a') as output:
        for i,base_hash in enumerate(hashes[:-1]):
            for other_hash in hashes[i:-1]:
                if base_hash and other_hash:
                    score = tlsh.diff(base_hash, other_hash)
                    output.write(f"{base_hash},{other_hash},{score}\n")

def main():
    if not os.path.exists('../resources/hashes'):
        os.makedirs('../resources/hashes')

    input_file = os.getcwd() + "/../resources/conversations/conversation_185.175.0.3_to_185.175.0.5.txt"
    output_file = os.getcwd() + "/../resources/hashes/similarity_scores.csv"
    
    open(output_file, 'w').close()
    
    compare_hashes_and_score(input_file, output_file)
    print("hashes compared")
    sort_csv_by_column_numerically(output_file, "../resources/hashes/sorted.csv", 2, False)

    print("Process completed. Similarity scores appended to the output file.")

if __name__ == "__main__":
    main()
