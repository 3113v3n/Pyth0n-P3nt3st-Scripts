def match_credentials(file1_path, file2_path, output_path):
    # Read usernames from file1 into a set for efficient lookup
    with open(file1_path, 'r') as f1:
        usernames = set(line.strip() for line in f1 if line.strip())

    # Process file2 and match with usernames from file1
    with open(file2_path, 'r') as f2:
        # Open output file for writing
        with open(output_path, 'w') as out:
            for line in f2:
                # Skip empty lines
                if not line.strip():
                    continue
                
                # Split line into username and password
                parts = line.strip().split()
                if len(parts) != 2:
                    continue
                    
                username, password = parts
                # Check if username exists in file1's set
                if username in usernames:
                    # Write in username:password format
                    out.write(f"{username}:{password}\n")

# Example usage
if __name__ == "__main__":
    try:
        username_path = input("Enter path to your username file: ").strip()
        credential_path = input("Path to your Creds file: ").strip()

        match_credentials(username_path, credential_path, "matched.txt")
        print("Processing complete. Results written to matched.txt")
    except FileNotFoundError as e:
        print(f"Error: One of the input files was not found - {e}")
    except Exception as e:
        print(f"An error occurred: {e}")