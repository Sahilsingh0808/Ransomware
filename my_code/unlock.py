import os
from cryptography. fernet import Fernet

files=[]

for file in os.listdir():
    if file=="lock.py" or file=="decrypt.key" or file=="unlock.py":
        continue
if os.path.isfile(file):
    files.append(file)

with open("decrypt.key","rb") as key:
    secretKey=key.read()

for file in files:
    with open(file,"rb") as file1:
        contents=file1.read()
    contents_decrypt=Fernet (secretKey).decrypt (contents)
    with open(file,"wb") as file1:
        file1.write(contents_decrypt)