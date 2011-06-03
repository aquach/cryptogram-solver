#!/usr/bin/python2.7

"""A cryptogram substitution-cipher solver."""

import argparse
import re
import string

__version__ = '0.0.1'


def hashWord(word):
    """Hashes a word into its similarity equivalent.

    MXM becomes 010, ASDF becomes 0123, AFAFA becomes 01010, etc.
    """

    seen = {}
    out = []
    i = 0
    for c in word:
        if c not in seen:
            seen[c] = str(i)
            i += 1
        out.append(seen[c])
    return ''.join(out)


class Corpus(object):
    """Manages a corpus of words sorted by frequency descending."""

    def __init__(self, corpusFilename):
        wordList = []
        try:
            wordList = open(corpusFilename).read().splitlines()
        except IOError, err:
            print err

        self._hashDict = {}
        for word in wordList:
            wordHash = hashWord(word)
            if wordHash not in self._hashDict:
                self._hashDict[wordHash] = [word]
            else:
                self._hashDict[wordHash].append(word)


    def findCandidates(self, inputWord):
        """Finds words in the corpus that could match the given word in
           ciphertext.

        For example, MXM would match wow but not cat, and cIF would match cat
        but not bat. Uppercase letters indicate ciphertext letters and lowercase
        letters indicate plaintext letters.

        Args:
            inputWord: The word to search for. Can be mixed uppercase/lowercase.
        """

        inputWordHash = hashWord(inputWord)
        matchesHash = self._hashDict.get(inputWordHash) or []

        candidates = []
        for word in matchesHash:
            invalid = False
            for i in xrange(0, len(word)):
                if (inputWord[i].islower() or inputWord[i] == "'"
                    or word[i] == "'"):
                    if inputWord[i] != word[i]:
                        invalid = True
                        break
            if not invalid:
                candidates.append(word)

        return candidates

class SubSolver(object):
    """Solves substitution ciphers."""

    def __init__(self, ciphertext, corpusFilename, verbose=False):
        """Initializes the solver.

        Args:
            ciphertext: The ciphertext to solve.
            corpusFilename: The filename of the corpus to use.
            verbose: Print out intermediate steps.
        """
        self._corpus = Corpus(corpusFilename)
        self._translation = {}
        self.ciphertext = ciphertext.upper()
        self.verbose = verbose

    def solve(self):
        """Solves the cipher passed to the solver.

        This function invokes the recursive solver multiple times, starting
        with a very strict threshold on unknown words (which could be proper
        nouns or words not in the dictionary). It then expands this out to a
        final threshold, after which it considers the cipher unsolvable.
        """

        words = re.sub(r'[^\w ]+', '', self.ciphertext).split()
        words.sort(key=lambda word: -len(word))

        for maxUnknownWordCount in xrange(0, max(3, len(words) / 10)):
            solution = self._recursiveSolve(words, {}, 0,
                                            maxUnknownWordCount)
            if solution:
                self._translation = solution
                break

    def _recursiveSolve(self, remainingWords, currentTranslation,
                        unknownWordCount, maxUnknownWordCount):
        """Recursively solves the puzzle.

        The algorithm chooses the first word from the list of remaining words,
        then finds all words that could possibly match it using the current
        translation table and the corpus. For each candidate, it builds a new
        dict that assumes that that candidate is the correct word, then
        continues the recursive search. It also tries ignoring the current word
        in case it's a pronoun.

        Args:
            remainingWords: The list of remaining words to translate, in
                descending length order.
            currentTranslation: The current translation table for this recursive
                state.
            unknownWordCount: The current number of words it had to skip.
            maxUnknownWordCount: The maximum number before it gives up.

        Returns:
            A dict that translates the ciphertext, or None if it could not find
            one.
        """

        trans = self._makeTransFromDict(currentTranslation)

        if self.verbose:
            print self.ciphertext.translate(trans)

        if len(remainingWords) == 0:
            return currentTranslation

        if unknownWordCount > maxUnknownWordCount:
            return None

        cipherWord = remainingWords[0]
        candidates = self._corpus.findCandidates(cipherWord.translate(trans))

        for candidate in candidates:
            newTrans = dict(currentTranslation)
            translatedPlaintextChars = set(currentTranslation.values())
            badTranslation = False
            for i in xrange(0, len(candidate)):
                cipherChar = cipherWord[i]
                plaintextChar = candidate[i]
                # This translation is bad if it tries to translate a ciphertext
                # character we haven't seen to a plaintext character we already
                # have a translation for.
                if (cipherChar not in currentTranslation and
                    plaintextChar in translatedPlaintextChars):
                    badTranslation = True
                    break
                newTrans[cipherWord[i]] = candidate[i]

            if badTranslation:
                continue

            result = self._recursiveSolve(remainingWords[1:],
                                          newTrans, unknownWordCount,
                                          maxUnknownWordCount)
            if result:
                return result

        # Try not using the candidates and skipping this word, because it
        # might not be in the corpus if it's a proper noun.
        skipWordSolution = self._recursiveSolve(remainingWords[1:],
                                                currentTranslation,
                                                unknownWordCount + 1,
                                                maxUnknownWordCount)
        if skipWordSolution:
            return skipWordSolution

        return None

    @staticmethod
    def _makeTransFromDict(translations):
        """Takes a translation dictionary and returns a string fit for use with
           string.translate()."""

        fromStr = ''
        toStr = ''
        for key in translations:
            fromStr += key
            toStr += translations[key]
        return string.maketrans(fromStr, toStr)

    def printReport(self):
        """Prints the result of the solve process."""

        if not self._translation:
            print 'Failed to translate ciphertext.'
            return

        plaintext = self.ciphertext.translate(
                        SubSolver._makeTransFromDict(self._translation))
        print 'Ciphertext:'
        print self.ciphertext, '\n'
        print 'Plaintext:'
        print plaintext, '\n'

        print 'Substitutions:'
        items = [key + ' -> ' + word for key, word
                    in self._translation.items()]
        items.sort()
        i = 0
        for item in items:
            print item + ' ',
            if i % 5 == 4:
                print ''
            i += 1


def main():
    """Main entry point."""

    print 'SubSolver v' + __version__ + '\n'

    parser = argparse.ArgumentParser(
        description='Solves substitution ciphers.')
    parser.add_argument('input_text',
                        help='A file containing the ciphertext.')
    parser.add_argument('-c', metavar='corpus', required=False,
                        default='corpus.txt',
                        help='Filename of the word corpus.')
    parser.add_argument('-v', action='store_true',
                        help='Verbose mode.')

    args = parser.parse_args()

    ciphertext = ''
    try:
        ciphertext = open(args.input_text).read().strip()
    except IOError, err:
        print err
        return

    solver = SubSolver(ciphertext, args.c, args.v)
    solver.solve()
    solver.printReport()

if __name__ == '__main__':
    main()
