
class HashUtil:
    # class to help deal with obtained hashes [ cracking and comparison]
    @staticmethod
    def format_username(username: str) -> str:
        """ Remove domain if is part of the username 

        :param username: username to format
        :return formated username
        """
        _parts = username.split('\\', 1)
        if len(_parts) < 2:
            return username
        return _parts[1]

    def compare_hash_from_dump(self, hash2compare, dump, userpass_list) -> str | list:
        """
        Compares a particular hash from a particular list and returns all
        possible matches:
        Appropriate for determining users with similar passwords
        :Param:
            hash to compare: The hash you would like to run a search on
            dump: List containing your dumped hash
        """
        cracked_hashes = {}
        with open(hash2compare, 'r') as hashes:
            # select unique hashes
            # Example: 7095e1b89261962493514d82f7b6f276:Shelxp10
            for line in hashes:
                if not line.strip():
                    continue
                try:
                    hash_val, password = line.strip().split(":", 1)  # Split on the first colon
                    cracked_hashes[hash_val] = password
                except ValueError:
                    print(
                        f"[-] Skipping malformed line in {hash2compare}:{line.strip()}")

        print(f"[*] Loaded {len(cracked_hashes)} cracked hashes")

        # Process dump file
        matches_found = 0
        enabled_users = 0
        with open(dump, 'r') as dumps:
            with open(userpass_list, 'a') as pass_file:
                for line in dumps:
                    if not line.strip():
                        continue

                    # Split the dumps into username and hash
                    # Guest:501:aad3b435b51404eeaa:31d6cfe0d16a::: (status=Disabled)

                    _parts = line.strip().split(":")

                    if len(_parts) != 7:
                        print(
                            f"[-] Skipping malformed dump line: {line.strip()}")
                        continue

                    # check is account is enabled
                    username, _, _, lmhash, _, _, status = _parts
                    if lmhash in cracked_hashes:
                        password = cracked_hashes[lmhash]
                        matches_found += 1
                        _check_status = "Enabled"
                        if _check_status in status:
                            # Only write enabled users
                            _formated = self.format_username(username)
                            pass_file.write(
                                f"{_formated}:{password}\n")
                            enabled_users += 1
                            print(f"[+] Match found: {_formated}:{password}")

        print(
            f"[*] Found {matches_found} matches, and written {enabled_users} "
            f"Enabled users to {userpass_list}")


if __name__ == "__main__":
    try:
        hashchecker = HashUtil()
        hashchecker._helper()
        h2c = input("[-] Enter path to your cracked hashes: ").strip()
        dump = input("[-] Enter Path to your dump file: ").strip()
        output = input("[-] Enter your output filename ")

        hashchecker.compare_hash_from_dump(h2c, dump, output)

    except FileNotFoundError as e:
        print(f"Error: One of the input files was not found - {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
