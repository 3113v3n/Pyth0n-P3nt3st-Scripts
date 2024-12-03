from handlers import FileHandler
from pprint import pprint


class HashUtil(FileHandler):
    # class to help deal with obtained hashes [ cracking and comparison]
    def __init__(self) -> None:
        self.dumped_hashes = []
        self.hash2compare = ""

    def compare_hash_from_dump(self, hash2compare, dump) -> str | list:
        """
        Compares a particular hash from a particular list and returns all
        possible matches:
        Appropriate for determining users with similar passwords
        Param:
            hash2compare: The hash you would like to run a search on
            dump: List containing your dumped hashe
        """
        self.dumped_hashes = dump
        self.hash2compare = hash2compare
        for hashes in read_all_lines(self.dumped_hashes):
            if self.hash2compare == hashes.split(":")[2]:
                pprint(read_all_lines(self.dumped_hashes))
