"""A cryptogram substitution-cipher solver."""

import argparse
import re

__version__ = '0.1.0'


def hash_word(word):
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

    def __init__(self, corpus_filename):
        word_list = []
        try:
            word_list = open(corpus_filename).read().splitlines()
        except IOError as err:
            print(err)

        self._hash_dict = {}
        for word in word_list:
            word_hash = hash_word(word)
            if word_hash not in self._hash_dict:
                self._hash_dict[word_hash] = [word]
            else:
                self._hash_dict[word_hash].append(word)

    def find_candidates(self, input_word):
        """Finds words in the corpus that could match the given word in
           ciphertext.

        For example, MXM would match wow but not cat, and cIF would match cat
        but not bat. Uppercase letters indicate ciphertext letters and lowercase
        letters indicate plaintext letters.

        Args:
            input_word: The word to search for. Can be mixed uppercase/lowercase.
        """

        input_word_hash = hash_word(input_word)
        matches_hash = self._hash_dict.get(input_word_hash) or []

        candidates = []
        for word in matches_hash:
            invalid = False
            for i in range(0, len(word)):
                if (input_word[i].islower() or input_word[i] == "'"
                        or word[i] == "'") and (input_word[i] != word[i]):
                    invalid = True
                    break
            if not invalid:
                candidates.append(word)

        return candidates


class SubSolver(object):
    """Solves substitution ciphers."""

    def __init__(self, ciphertext, corpus_filename, verbose=False):
        """Initializes the solver.

        Args:
            ciphertext: The ciphertext to solve.
            corpus_filename: The filename of the corpus to use.
            verbose: Print out intermediate steps.
        """
        self._corpus = Corpus(corpus_filename)
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

        for max_unknown_word_count in range(0, max(3, len(words) // 10)):
            solution = self._recursive_solve(words, {}, 0,
                                             max_unknown_word_count)
            if solution:
                self._translation = solution
                break

    def _recursive_solve(self, remaining_words, current_translation,
                         unknown_word_count, max_unknown_word_count):
        """Recursively solves the puzzle.

        The algorithm chooses the first word from the list of remaining words,
        then finds all words that could possibly match it using the current
        translation table and the corpus. For each candidate, it builds a new
        dict that assumes that that candidate is the correct word, then
        continues the recursive search. It also tries ignoring the current word
        in case it's a pronoun.

        Args:
            remaining_words: The list of remaining words to translate, in
                descending length order.
            current_translation: The current translation table for this recursive
                state.
            unknown_word_count: The current number of words it had to skip.
            max_unknown_word_count: The maximum number before it gives up.

        Returns:
            A dict that translates the ciphertext, or None if it could not find
            one.
        """

        trans = self._make_trans_from_dict(current_translation)

        if self.verbose:
            print(self.ciphertext.translate(trans))

        if len(remaining_words) == 0:
            return current_translation

        if unknown_word_count > max_unknown_word_count:
            return None

        cipher_word = remaining_words[0]
        candidates = self._corpus.find_candidates(cipher_word.translate(trans))

        for candidate in candidates:
            new_trans = dict(current_translation)
            translated_plaintext_chars = set(current_translation.values())
            bad_translation = False
            for i in range(0, len(candidate)):
                cipher_char = cipher_word[i]
                plaintext_char = candidate[i]
                # This translation is bad if it tries to translate a ciphertext
                # character we haven't seen to a plaintext character we already
                # have a translation for.
                if (cipher_char not in current_translation and
                        plaintext_char in translated_plaintext_chars):
                    bad_translation = True
                    break
                new_trans[cipher_word[i]] = candidate[i]

            if bad_translation:
                continue

            result = self._recursive_solve(remaining_words[1:],
                                           new_trans, unknown_word_count,
                                           max_unknown_word_count)
            if result:
                return result

        # Try not using the candidates and skipping this word, because it
        # might not be in the corpus if it's a proper noun.
        skip_word_solution = self._recursive_solve(remaining_words[1:],
                                                   current_translation,
                                                   unknown_word_count + 1,
                                                   max_unknown_word_count)
        if skip_word_solution:
            return skip_word_solution

        return None

    @staticmethod
    def _make_trans_from_dict(translations):
        """Takes a translation dictionary and returns a string fit for use with
           string.translate()."""

        from_str = ''
        to_str = ''
        for key in translations:
            from_str += key
            to_str += translations[key]
        return str.maketrans(from_str, to_str)

    def print_report(self):
        """Prints the result of the solve process."""

        if not self._translation:
            print('Failed to translate ciphertext.')
            return

        plaintext = self.ciphertext.translate(
            SubSolver._make_trans_from_dict(self._translation))
        print('Ciphertext:')
        print(self.ciphertext, '\n')
        print('Plaintext:')
        print(plaintext, '\n')

        print('Substitutions:')
        items = [key + ' -> ' + word for key, word
                 in self._translation.items()]
        items.sort()
        i = 0
        for item in items:
            print(item + ' ', end='')
            if i % 5 == 4:
                print('')
            i += 1


def main():
    """Main entry point."""

    print('SubSolver v' + __version__ + '\n')

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

    try:
        ciphertext = open(args.input_text).read().strip()
    except IOError as err:
        print(err)
        return

    solver = SubSolver(ciphertext, args.c, args.v)
    solver.solve()
    solver.print_report()


if __name__ == '__main__':
    main()
