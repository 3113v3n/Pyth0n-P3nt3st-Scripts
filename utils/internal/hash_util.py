from ..shared.colors import Bcolors


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

    @staticmethod
    def get_hashes(h2c):
        cracked_hashes = {}
        with open(h2c, 'r') as hashes:
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
                        f"[-] Skipping malformed line in {h2c}:{line.strip()}")
        return cracked_hashes

    def compare_hash_from_dump(self, hash2compare, dump, userpass_list) -> str | list:
        """
        Compares a particular hash from a particular list and returns all
        possible matches:
        Appropriate for determining users with similar passwords
        :Param:
            hash to compare: The hash you would like to run a search on
            dump: List containing your dumped hash
        """

        cracked_hashes = self.get_hashes(hash2compare)
        print(
            f"[*] Loaded {Bcolors.BOLD}{len(cracked_hashes)}{Bcolors.ENDC} cracked hashes")

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
                            f"{Bcolors.FAIL}[-]{Bcolors.ENDC} Skipping malformed dump line: {line.strip()}")
                        continue

                    # check is account is enabled
                    username, _, _, nthash, _, _, status = _parts
                    if nthash in cracked_hashes:
                        password = cracked_hashes[nthash]
                        matches_found += 1
                        _check_status = "Enabled"
                        if _check_status in status:
                            # Only write enabled users
                            _formated = self.format_username(username)
                            pass_file.write(
                                f"{_formated}:{password}\n")
                            enabled_users += 1
                            print(
                                f"{Bcolors.OKGREEN}[+]{Bcolors.ENDC} Match found: "
                                f"{Bcolors.OKCYAN}{_formated}{Bcolors.ENDC}:"
                                f"{Bcolors.WARNING}{password}{Bcolors.ENDC}")

        return matches_found, enabled_users
