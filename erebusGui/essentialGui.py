from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import sys
import time
import platform
class Essentials:
    def __init__(self):
        pass

    def generateKeyFromPasswd(self, password: str, salt: bytes):
        encryptKey = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt = salt,
                iterations=100000
                )
        return encryptKey.derive(password.encode())

    def loadingSpinner(self, option, sleepTime, stopEvent):
        spinner = ['|','\\','-','/']
        while not stopEvent.is_set():
            for i in spinner:
                sys.stdout.write(f"\r {option}... {i} ")
                sys.stdout.flush()
                time.sleep(sleepTime)
                if stopEvent.is_set():
                    break

    def passwdWithAsterisks(self, prompt="> Enter a password: "):
        osName = platform.system()
        if osName == "windows":
            import msvcrt
            print(prompt, end="", flush=True)
            password = ""
            while True:
                char = msvcrt.getch().decode("utf-8")
                if char == "\r" or char =="\n":
                    print()
                    break
                elif char =="\b":
                    if len(password) > 0:
                        password = password[:-1]
                        sys.stdout.write("\b \b")
                else:
                    password += char
                    sys.stdout.write("*")
                sys.stdout.flush()
        elif osName in ["Linux", "Darwin"]:
            import termios
            import tty
            print(prompt, end="", flush=True)
            fd = sys.stdin.fileno()
            settings= termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                password =""
                while True:
                    char = sys.stdin.read(1)
                    if char =="\r"  or char=="\n":
                        print()
                        break
                    elif char =="\x74" or char =="\b":
                        if len(password)> 0:
                            password = password[:-1]
                            sys.stdout.write("\b \b")
                    else:
                        password +=char
                        sys.stdout.write("*")
                    sys.stdout.flush()
            finally:
                termios.tcsetattr(fd,termios.TCSADRAIN, settings)
        else:
            password = input(prompt)
        return password


    def fileFilter(self, filename):
        extension = "." + filename.split(".")[-1]
        fileName = filename.split(".")[0]
        return fileName, extension

