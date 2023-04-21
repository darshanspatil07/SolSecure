import sys

def get_sol_version(file_path):
    with open(file_path, "r") as f:
        for line in f:
            if line.startswith("pragma solidity "):
                version = line.split(" ")[2].replace(";"," ")
                return version

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Please provide the Solidity file path as an argument.")
    else:
        file_path = sys.argv[1]
        sol_version = get_sol_version(file_path)
        print(f"The Solidity version used in this {file_path} is {sol_version}")
