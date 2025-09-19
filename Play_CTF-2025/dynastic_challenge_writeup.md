Dynastic Challenge Writeup Challenge Overview In the "Dynastic"
challenge, you awaken in a locked gas chamber with only a torch (low
battery) and cryptic wall etchings. A tape warns that lethal hydrogen
cyanide will fill the room in 15 minutes unless you unlock both the door
and your handcuffs using a single passcode carved into the wall. A
provided Python script reads a secret FLAG, applies an index-based
Caesar shift, and outputs the cipher text. Your task is to reverse this
process to recover the original flag.

1.  Inspecting the Provided Files You're given two files:

source.py -- the encryption script

output.txt -- the resulting cipher text

Begin by opening output.txt to see the garbled message:

text
DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!\_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL
2. Understanding the Encryption Script Open source.py and identify the
key components:

python def to_identity_map(a): return ord(a) - 0x41

def from_identity_map(a): return chr(a % 26 + 0x41)

def encrypt(m): c = '' for i in range(len(m)): ch = m\[i\] if not
ch.isalpha(): ech = ch else: chi = to_identity_map(ch) ech =
from_identity_map(chi + i) c += ech return c Mapping functions:

to_identity_map converts an uppercase letter A--Z to 0--25.

from_identity_map takes a numeric value, wraps it modulo 26, and
converts back to A--Z.

Shift logic:

For each character at position i (0-indexed), the script adds i to its
letter index.

Non-letters (underscores, punctuation) remain unchanged.

Hence, character at index 0 is shifted by 0 (no change), at index 1 by
+1, at index 2 by +2, etc. This is a Trithemius cipher (a progressive
Caesar cipher).

3.  Crafting the Decryption Approach To reverse the encryption, perform
    the inverse operation:

Iterate over each character of the cipher text with its index i.

If the character is a letter, map it to 0--25, subtract the index i,
then wrap modulo 26.

Convert back to a letter.

Leave non-letter characters unchanged.

This yields the original plaintext.

4.  Implementing the Decryption Script Below is a clean, self-contained
    Python snippet to decrypt:

python cipher =
"DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!\_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL"

def decrypt(cipher_text): plaintext = "" for i, ch in
enumerate(cipher_text): if 'A' \<= ch \<= 'Z': \# Map letter to 0--25
idx = ord(ch) - ord('A') \# Reverse the shift orig_idx = (idx - i) % 26
\# Map back to uppercase letter plaintext += chr(orig_idx + ord('A'))
else: \# Preserve underscores and punctuation plaintext += ch return
plaintext

print(decrypt(cipher)) Explanation:

We loop through each character with its index.

For letters, we perform the inverse shift by subtracting i (mod 26).

Non-letter characters (such as \_ and ?!) are appended directly.

5.  Recovering and Formatting the Flag Running the decryption script
    reveals:

text
DID_YOU_KNOW_ABOUT_THE_TRITHEMIUS_CIPHER?!\_IT_IS_SIMILAR_TO_CAESAR_CIPHER
Hack The Box requires flags in the format HTB{...}. Wrapping the
decrypted text gives:

HTB{DID_YOU_KNOW_ABOUT_THE_TRITHEMIUS_CIPHER?!\_IT_IS_SIMILAR_TO_CAESAR_CIPHER}

6.  Key Takeaways & Learning Points Index-based shifting (Trithemius
    cipher) increments the shift each character, unlike a fixed Caesar
    cipher.

Reversal requires subtracting the position index, not adding.

Modular arithmetic ensures wrap-around within A--Z.

Always preserve non-alphabetic characters exactly as in the ciphertext.
