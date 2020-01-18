class Trie:
    """
    Trie implementation. 

    Each Trie stores a mapping from characters to children,
    whether the prefix is a finished word, and the Trie's
    parent node.
    """
    def __init__(self, parent = None):
        self.parent = parent
        self.word_finished = False
        self.children = dict()

    def add(self, word):
        if len(word) == 0:
            self.word_finished = True
        else:
            char = word[0]
            if char not in self.children:
                self.children[char] = Trie(self)
            self.children[char].add(word[1:])
            

    
        
            
            


