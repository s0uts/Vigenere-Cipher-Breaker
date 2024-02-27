import math

plaintext_Frequencies = {
    'a': 8.04,
    'b': 1.54,
    'c': 3.06,
    'd': 3.99,
    'e': 12.51,
    'f': 2.30,
    'g': 1.96,
    'h': 5.49,
    'i': 7.26,
    'j': 0.16,
    'k': 0.67,
    'l': 4.14,
    'm': 2.53,
    'n': 7.09,
    'o': 7.60,
    'p': 2.00,
    'q': 0.11,
    'r': 6.12,
    's': 6.54,
    't': 9.25,
    'u': 2.71,
    'v': 0.99,
    'w': 1.92,
    'x': 0.19,
    'y': 1.73,
    'z': 0.09
}


alphabet_to_index = {
    'a': 0,
    'b': 1,
    'c': 2,
    'd': 3,
    'e': 4,
    'f': 5,
    'g': 6,
    'h': 7,
    'i': 8,
    'j': 9,
    'k': 10,
    'l': 11,
    'm': 12,
    'n': 13,
    'o': 14,
    'p': 15,
    'q': 16,
    'r': 17,
    's': 18,
    't': 19,
    'u': 20,
    'v': 21,
    'w': 22,
    'x': 23,
    'y': 24,
    'z': 25
}

index_to_alphabet = {
    0: 'a',
    1: 'b',
    2: 'c',
    3: 'd',
    4: 'e',
    5: 'f',
    6: 'g',
    7: 'h',
    8: 'i',
    9: 'j',
    10: 'k',
    11: 'l',
    12: 'm',
    13: 'n',
    14: 'o',
    15: 'p',
    16: 'q',
    17: 'r',
    18: 's',
    19: 't',
    20: 'u',
    21: 'v',
    22: 'w',
    23: 'x',
    24: 'y',
    25: 'z'
}

def index_of_coincedence(ciphertext):  
    #Creating groups out of every xth letter in the ciphertext
    #Where x is the keysize, and we start from an index from [0...keysize]
    possible_KeyLengths=[]
    variation_from_English=[0]*20
    keysize=2
    index=0
    while keysize < 20:
        y=0
        groups=[]
        for x in range(0, keysize):
            groups.append(ciphertext[y: len(ciphertext): keysize])
            y+=1

        average_ic=0
        #Calculate the ic of each group
        for x in range(0, len(groups)):
            freqs = calculuateLetterFrequency(groups[x])
            n = len(groups[x])
            ic = (sum(ni * (ni-1) for ni in freqs.values())) / (n*(n-1))
            average_ic+=ic
       
        #Calculate the average ic across each group
        average_ic/=len(groups)
        variation_from_English[keysize-2]=abs(average_ic-0.0667)
    
        keysize+=1
        
    #If the average ic is close to the english value of 0.068 then assume n is the correct length
    minIc = float('inf')
    for z in range(1, len(variation_from_English)-2):
        if variation_from_English[z] < minIc:
                minIc=variation_from_English[z]
                possible_KeyLengths.append(z+2) #accounts for keylengths starting from 2
    return possible_KeyLengths

def frequencyAttackVigenere(ciphertext, keysize):
    #Creating groups out of every xth letter in the ciphertext
    #Where x is the keysize, and we start from an index from [0...keysize]

    groups=[]
    for x in range(0, keysize):
        groups.append(ciphertext[x: len(ciphertext): keysize])
    
    key=''
    possible_Keys=[]
    
    for groupNumber in range(0, keysize):
        minVariation= float('inf')
        minShift=0
        for shiftValue in range(0, 25):
            current_freqs = calculateNormalizedLetterFrequency(shiftCipherText(groups[groupNumber], shiftValue/-1))
            current_Variation = sum(abs(plaintext_Frequencies[char] - (current_freqs[char])) for char in plaintext_Frequencies)

            if current_Variation < minVariation:
                minVariation=current_Variation
                minShift=shiftValue
                possible_Keys.append(index_to_alphabet[minShift])

        print(f'Most likely key[{groupNumber}] = {index_to_alphabet[minShift]}')
        print(f'Total keys to consider for {groupNumber}: {possible_Keys}\n')
        possible_Keys=[]
        key+=index_to_alphabet[minShift]
    
    return key

def decodeVigenere(ciphertext, key, keysize):
    keyIndex=0
    plainText=''
    for char in ciphertext:
        shiftedBackValue=(alphabet_to_index[char] - alphabet_to_index[key[keyIndex]])
        if shiftedBackValue < 0:
            shiftedBackValue+=26
        plainText+=index_to_alphabet[shiftedBackValue]
        keyIndex+=1
        keyIndex%=keysize
    print(f'\nThe ciphertext using the key-{key} decodes to: \n{plainText}\n')
    
        
def shiftCipherText(ciphertext, shiftValue):
    newText=''
    for char in ciphertext:
        ##Appends the shifted value to newText, wrapping around the alphabet if needed
        newText+=index_to_alphabet.get((alphabet_to_index.get(char)+shiftValue)%26)
    return newText

def calculuateLetterFrequency(ciphertext): #i.e a:5 #normalized
    freqs = {
        'a': 0, 'b': 0, 'c': 0, 'd': 0, 'e': 0, 'f': 0, 'g': 0, 'h': 0,
        'i': 0, 'j': 0, 'k': 0, 'l': 0, 'm': 0, 'n': 0, 'o': 0, 'p': 0,
        'q': 0, 'r': 0, 's': 0, 't': 0, 'u': 0, 'v': 0, 'w': 0, 'x': 0,
        'y': 0, 'z': 0
    }
    #Getting frequencies
    for char in ciphertext:
           freqs[char]+=1
    return freqs
    
def calculateNormalizedLetterFrequency(ciphertext):
    freqs = calculuateLetterFrequency(ciphertext)
    
    #Normalizing    
    total = sum(freqs.values())
    for char in freqs:
       freqs[char] /= (float(total)/100)
    return freqs

def main():
    #ciphertext = 'ujksiiemrsmubgkhmzrxiilvivjemznoeaxflmfnozvmfrlvrakoiyuurnayozklgrfbvrerrljtpvpqxsufvmznbftpvfiimpfuavtpvymrtqetpvkqkcpvnzvlioiv'
    #ciphertext = 'ioswogmmbztiqmbdkffiosdjhituooafuteturjgsdkbfdnffidecpdppdauuoopegunfeasabpfatkovdpmmsuucqmlxtotruofocqwjfhuteiutdthjwesegvudffoutehmlbjyeqfjzetfhfyasweuunhpiwusjanprtiqsjdiveczneszeuuctoosbosmtjanbeacgndtogyioplfeskqrlewialmneutegurtfahmioetutexmlmihfztiqrfhomgtjandamfewjfhbropfnpfeuatiqegredftimtutefpiuartiovxdxqldamfmpqxidmtjantrrpyaokooqiofesqsuqdjztbwiosowqruteqasuafsabpfidecpdrfeppzdfztdgrjautxyfzovshbzeeutjanprtiqeooydxoqmeeuahmlbotjoautautaefhfsoppfpdtvzeuafbxlutrpggimtjyexmrqrrpyautoveaopyfmrtunuteggtvdeeqfjzeefhfyasweuunhpiwusjanprtiqsjdiveczneszeuuctoosbosmtjanbeacgndtogyioplfeskqrlewiawfdeutegurtfahmioetutexmlmihfztiqrfhomgtjandmmffhfbiowcvnidxeimdxunlqdpgtpreyusuqndqtiqmpzkfksimdtgnlmwbktpmbfftfddjyeoeipzfpddbzdbdtigrgauoptiqmtqlwqsjztiqennaswauuoomrfmogfhfehjbiuiatdautesembdtjfhjzkutettiqebsmnezexeajpfpddiawdmnzauuqlmmslqdbdtigrimvfkovsoueonqeyatjodfhidqfpdmfmsvdiostiqahqogyeumloaikgsurovzdutiteamqscdodtusqlzunhanutegxopdiueamatprtiquouvfdsfoaonezausesugfgmhmaoluwberjshurospjbnbfpauanfafuteqmgfe'
    ciphertext = 'akvheafoanlkoeotuionmfcernfyacwlwlewgpnsarfstzfslavunrivjpllmrathmvaooiekgninahyaypnsisptonilshuvhlwqcsgolfdnsevltitcaryupaeebyvntpvlnoeylenwnzeevfdimbzyedwxuawqenollsvnearudsszusidvhmivuaodqelonbylenwniutrlztaaylthwlnhtpzzdivelrwijjauoyahenfbndpzzhavuzhal'

    print(f'Attemping to decode attached ciphertext encoded with a vigenere cipher \n{ciphertext}\n')

    possible_KeyLengths = index_of_coincedence(ciphertext)
    print(f'Possible key lengths are: {possible_KeyLengths}')
    
    for keylength in possible_KeyLengths:
        print(f'Attempting keylength - {keylength}')
        key = frequencyAttackVigenere(ciphertext, keylength)
        decodeVigenere(ciphertext, key, keylength)
    
if __name__ == "__main__":
    main()