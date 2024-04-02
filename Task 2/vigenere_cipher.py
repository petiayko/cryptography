#!/usr/bin/env python
# coding: utf-8

# In[1]:


from pprint import pprint


# # Ввод констант: рабочий алфавит, шифртекст, частоты букв английского языка

# In[2]:


ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
CIPHER_TEXT = 'VYCPYTKECRBDJVPXLOVPNTHTOFLDTZRYYQXHKTQJUGVZRJMWQEAXIVGIUWXFGVYRAZGKRTKWPRLPEDJRZTMWUDYEISFKMXMGPLKTKWEVOJBJCCCCMSPTPNIHGUSHBBIRQXFDNVKPMVGDYIBQCCDJGQVZMCTBFTMCOSTKCSUOEBRDTZGKRTKHJVDDKAWCYJLSFDCPGGVYYIXOEYJTMHGICCVFAGRHMCQECDMVGIJTMHGIYCWPCTIPZOKEKTTBKEEIASEZNWXFKJCHLSPKGPEZARQITBFRPSLIDJRXMIVZMCVWRYCGPWVYYGNZGXMKXFPZLVPVKTFAXHVVPVHSUKMLAWEYYHLIEYGIAOUKFTPSCBLTLGGJMUTZNJSQLHKKSIBCPTGEASTJCPVVNVRIXFKJCCVWRYCGXRYZRWMVGWSCVHKFLIASEZNWXFUGPXFOTPUTTYPVQHVCOVQUKCOKFTYOEKRWTHKWRWXQTPNITBCCWHMQCEBXLQQMCGUMOVYCLCHWPTJIGEANTBCCWHBGDISIXTQIATZIGJQXGUQIMIASTNGHXHJVNATWPKCMMCHKUDVWRYCGMSZKAWTFCTRTKGVYCCMVGBCNVOPSCDUHCZLTWPAJMAOWPXYHBAWCRPGSQLQTJICKGDGGKEATPSMEMLTOPUKPKSTVJPMWXVJNIFKDCIAWUTYCUSWJCSMCTRNXWZAUGHVOTUKPGMHRJHXYGPQXGOPRSIHACKCSLMUKCBMVGJYBXHAGCDYHTRLHYCTDYIBCPLQTWWPRDUBBGTGEASTJGHNGGUGCEWPVYGVCPXPJXBVZYAZSPVPPMCTJYIRDGFDELSWUMGTBFFKCNADVPVXBGIYIHFVYGHZSPVPPMCTZQCHHCTPNIHQXPPIVKTYAEMUVAJKSRJCJWCTRLSHAPLKQXFIVLTKOVFPUHFVYCHTAGICPLCPKFPMHJVYUYWPVAXIVGIGHGCVJCRNF'
FREQUENCY = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228,
             2.015, 6.094, 6.966, 0.153, 0.772, 4.025,
             2.406, 6.749, 7.507, 1.929, 0.095, 5.987,
             6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
             1.974, 0.074]


# # Функция разбиения строки s на столбцы высоты t

# In[3]:


def get_layers(s, t):
    return [s[i::t] for i in range(t)]


# # Функция вычисления индекса совпадений

# In[4]:


def get_index(s, alph=ALPHABET):
    if len(s) < 2:
        return 0

    ind = 0
    for ch in alph:
        ch_count = s.count(ch)
        ind += ch_count * (ch_count - 1) / (len(s) * (len(s) - 1))
    return ind


# In[5]:


def get_mutual_index(s1, s2, alph=ALPHABET):
    ind = 0
    for ch in alph:
        ind += s1.count(ch) * s2.count(ch) / (len(s1) * len(s2))
    return ind


# # Поиск длины ключа

# In[6]:


data = dict()
max_ind = -1
key_length = -1
for t in range(1, len(CIPHER_TEXT)):
    data[t] = min([get_index(layer) for layer in get_layers(CIPHER_TEXT, t)])
    if data[t] > max_ind:
        max_ind = data[t]
        key_length = t

print(f'Длина ключа = {key_length}')


# # Поиск наиболее вероятного ключа

# In[7]:


key = str()

for i in range(key_length):
    count = [0] * len(ALPHABET)
    for j in range(i, len(CIPHER_TEXT), key_length):
        count[ord(CIPHER_TEXT[j]) - ord('A')] += 1

    max_dp = -1
    best_i = 0

    for j in range(len(ALPHABET)):
        cur_dp = sum([FREQUENCY[k] * count[(k + j) % len(ALPHABET)] for k in range(len(ALPHABET))])
        if cur_dp > max_dp:
            max_dp = cur_dp
            best_i = j
    key += chr(best_i + ord('A'))

key = key.upper()
print(f'Полученный ключ: {key}')


# # Расшифрование

# In[8]:


plaintext = str()
key_index = 0
for char in CIPHER_TEXT:
    shift = ord(key[key_index % len(key)]) - ord('A')
    decrypted_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
    plaintext += decrypted_char
    key_index += 1

print(f'Открытый текст: {plaintext}')
