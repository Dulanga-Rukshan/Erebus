from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
import base64
import bcrypt
import os
import threading
import time
from essentials import Essentials
from banner import bannerSelect

class Encryptor:
    def __init__(self):
        self.Essentials = Essentials()

    def encrypt(self, password:str, salt, fileName: str):
        #stop threding event 
        stopEvent = threading.Event()
        name, extension = self.Essentials.fileFilter(fileName)
        with open(fileName, "rb") as toEncrypt:
            fileData = toEncrypt.read()

        #loading spinner animation with genarating key
        task1 = threading.Thread(target=self.Essentials.loadingSpinner, args=("key generating", 2, stopEvent))
        task1.start()
        key = self.Essentials.generateKeyFromPasswd(password, salt)
        fernet = Fernet(base64.urlsafe_b64encode(key))
        print("\nKEY GENERATED!")
        stopEvent.set()
        task1.join()
        time.sleep(1.25)

        #clearing stopEvent
        stopEvent.clear()

        #encrypt data from input file
        task2 =threading.Thread(target=self.Essentials.loadingSpinner, args=("Encrypting data", 2, stopEvent))
        task2.start()
        encryptedData = fernet.encrypt(fileData)
        print("\nDATA ENCRYPTED!")
        stopEvent.set()
        task2.join()
        time.sleep(1.25)

        #clearing stopEvent
        stopEvent.clear()

        #hashing password user entered  
        task3 = threading.Thread(target=self.Essentials.loadingSpinner, args=("Hashing password", 2, stopEvent))
        task3.start()
        hashPasswd = bcrypt.hashpw(password.encode(), salt)
        print("\nPASSWORD HASHED!")
        stopEvent.set()
        task3.join()
        time.sleep(1.25)

        #clearing stopEvent
        stopEvent.clear()

        #writing data to encrypted file with hashing password 
        task4 = threading.Thread(target=self.Essentials.loadingSpinner, args=("Writing encrypted data to file..", 2, stopEvent))
        task4.start()
        with open(name + extension + ".enc", "wb") as encrypted:
            encrypted.write(hashPasswd + b"\n")
            encrypted.write(salt + b"\n")
            #encrypted.write(key + b"\n")
            encrypted.write(encryptedData)
            print(f"\nSUCCESS - Encrypted file created {name}{extension}.enc")
        stopEvent.set()
        task4.join()
    def decrypt(self, password:str, fileName):
        stopEvent = threading.Event() #setting stop threading event
        name, extension = self.Essentials.fileFilter(fileName)
        extensionNew = os.path.splitext(fileName)[0].split(".")[-1]
        try:
            with open(fileName, "rb") as toDecrypt: #open encrypted file  as read binary
                fileData = toDecrypt.read()   #read all binary data from toDecrypt file
            lines = fileData.split(b"\n")   #separating line that has \n lines

            if len(lines) < 3:
                print("File format is Incorrect!")
                return

            salt = lines[1]     #setting salt to lines 2.
            storedHash = lines[0]   #setting hashpassword to lines 1
            storedData = b"\n".join(lines[2:])  #setting everything else to data

            task1 = threading.Thread(target=self.Essentials.loadingSpinner, args=("Verifing the password", 2, stopEvent))
            task1.start()

            if not bcrypt.checkpw(password.encode(), storedHash): #compare entered password to stored hash
                print("\nPassword Incorrect!")
                stopEvent.set()
                task1.join()
                return
            print("\nPassword is Correct!")
            stopEvent.set()
            task1.join()
            time.sleep(1.25)

            stopEvent.clear()

            task2 = threading.Thread(target=self.Essentials.loadingSpinner, args=("Generating Decryption Key", 2, stopEvent))
            task2.start()
            #Generate hashed key from salt + password
            hashedPassword = self.Essentials.generateKeyFromPasswd(password, salt)
            key=base64.urlsafe_b64encode(hashedPassword[:32])
            stopEvent.set()
            task2.join()
            time.sleep(1.25)

            stopEvent.clear()

            task3 = threading.Thread(target=self.Essentials.loadingSpinner, args=("Decrypting Data", 2, stopEvent))
            task3.start()
            fernet = Fernet(key)    #generate ley from hash key that generated from key
            decryptData = fernet.decrypt(storedData)  #trying to decrypt data from generated key
            stopEvent.set()
            task3.join()
            time.sleep(1.25)

            stopEvent.clear()

            task4 = threading.Thread(target=self.Essentials.loadingSpinner, args=("Writing data do file", 2, stopEvent))
            task4.start()
            with open(name +"Decryp."+extensionNew, "wb") as decryptFile:
                 decryptFile.write(decryptData)
            print(f"\nDECRYPTED IS SUCCESFULL! - Check {name}.{extensionNew} for data.")
            stopEvent.set()
            task4.join()
        except Exception as e:
            print("\n Decrypting failed - ", str(e))


def main():
    bannerSelect()
    print("""
        **********************************************************************
        *    Erebus is a tool designed by DulangaRukshan.                    *
        *    This tool is designed for encryption and decryption of files    *
        *    using symmetric key or password based encryption.               *
        *    Send your feedback - dulangarukshan@proton.me                   *
        **********************************************************************
          """)
    print("""
        [0] -  Encrpyt a file
        [1] -  Decrypt a file
        [2] -  Help

        """)
    helpText = """Usage:
        Options:
          0 - Encrypt a file
          1 - Decrypt a file
          2 - Display this help message

        Examples:
          1. Encrypt a file:
             Select what you want to do: 0
             > Enter the path to the file you want to encrypt: /path/to/file.txt
             > Enter a password for encryption: ********
             > File encrypted successfully! Encrypted file saved as /path/to/file.txt.enc

          2. Decrypt a file:
             Select what you want to do: 1
             > Enter the path to the encrypted file: /path/to/file.txt.enc
             > Enter the password for decryption: ********
             > File decrypted successfully! Decrypted file saved as /path/to/file.txt

          3. Display help:
              Select what you want to do: 2
             > This help message will be displayed

        Additional Notes:
        - Ensure you remember the password used for encryption. Without it, decryption will not be possible.
        - The tool uses symmetric key encryption for secure file handling.
        - For feedback or feature requests, email: dulangarukshan@proton.me

=====================================================================================

            """
    userInput = input("Select what you want to do: ")
    iv = bcrypt.gensalt()
    encryptor = Encryptor()
    essentials= Essentials()
    if userInput == "0":
        filename = input("> Enter the path to the file you want to encrypt: ").strip()
        if os.path.isfile(filename):
            password = essentials.passwdWithAsterisks("> Enter a password for encryption: ")
            essentials.generateKeyFromPasswd(password, iv)
            encryptor.encrypt(password,iv,filename)
        else:
            print(f"\n{filename} File Doens't Found!")
    elif userInput == "1":
        filename = input("> Enter the path to the encrypted file: ").strip()
        if os.path.isfile(filename):
            password = essentials.passwdWithAsterisks("> Enter a password for decryption: ")
            encryptor.decrypt(password, filename)
        else:
            print(f"\n{filename} File Doesn't Found!")
    elif userInput == "2":
        print(helpText)
    else:
        print(helpText)

if __name__ == "__main__":
    main()
