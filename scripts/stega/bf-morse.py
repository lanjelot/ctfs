import sys
sys.path.append('/home/seb/tools/crypto/ngram_score')
sys.path.append('/home/seb/tools/crypto/pycipher')

from ngram_score import ngram_score
fitness = ngram_score('/home/seb/tools/crypto/practicalcryptography.com/quadgrams.txt') 

import morse_talk

#data = '-.-.-..-..--.--..-..---.-.--.--.'
data = '-.-. - ..-. .-- .--.'.replace(' ', '')
#data = '-.-' #.-..-..--.--..-..---.-.--.--.'
#data = 'ABCD'

'''
A B C
A BC
AB C
'''

'''
result =
A BCD
A B CD
A B C D
A BC D
AB CD
AB C D
ABC D
ABCD
'''

def decode(code):

  for i in range(1, 5):
    try:
      base = morse_talk.decode(code[:i])

      if len(code[i:]) == 0:
        yield base
        break

      else:
        for rest in decode(code[i:]):
          yield '%s%s' % (base, rest)
    
    except KeyError:
      break

if __name__ == '__main__':
  #parentscore = None
  for s in decode(data):
    print(s + 'PRAGYAN')
    #if parentscore is None:
    #  parentscore = fitness.score(s)
    #else:
    #  score = fitness.score(s)
    #  if score > parentscore:
    #    parentscore = score
    #    print s
