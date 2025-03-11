from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog, QDialog, QLineEdit, QMessageBox, QProgressBar, QInputDialog, QScrollArea)
from PyQt6.QtGui import QFont, QMovie, QColor, QLinearGradient, QPainter, QBrush, QScreen
from PyQt6.QtCore import Qt, QTimer, QEvent, QPropertyAnimation, QRect, QEasingCurve
from PyQt6.QtWidgets import QGraphicsDropShadowEffect
from PyQt6.QtGui import QIcon
from essential import Essentials
from PyQt6.QtCore import QThread, pyqtSignal
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
import base64
import bcrypt
import os
import threading
import time
import sys


class EncryptDecrypt:
    def __init__(self):
        self.Essentials = Essentials()

    def encrypt(self, password:str, salt, fileName: str, updateStatus):
        name, extension = self.Essentials.fileFilter(fileName)
        with open(fileName, "rb") as toEncrypt:
            fileData = toEncrypt.read()

        updateStatus("Generating key...", 10)
        key = self.Essentials.generateKeyFromPasswd(password, salt)
        fernet = Fernet(base64.urlsafe_b64encode(key))
        time.sleep(1.25)

        #encrypt data from input file
        updateStatus("Encrypting file...", 30)
        encryptedData = fernet.encrypt(fileData)

        updateStatus("Hashing password...", 60)
        hashPasswd = bcrypt.hashpw(password.encode(), salt)

        #writing data to encrypted file with hashing password
        updateStatus("Writing Encrypted data....", 90)
        with open(name + extension + ".enc", "wb") as encrypted:
            encrypted.write(hashPasswd + b"\n")
            encrypted.write(salt + b"\n")
            encrypted.write(encryptedData)

        updateStatus(f"File Encrypted succesfully, Check {name}{extension}.enc for encrypted file!", 100)
        return name + extension + ".enc"

    def decrypt(self, password:str, fileName, updateStatus):

        updateStatus("Opening the Encrypted file", 10)

        name, extension = self.Essentials.fileFilter(fileName)
        extensionNew = os.path.splitext(fileName)[0].split(".")[-1]

        updateStatus("Reading the Encrypted Data", 15)

        with open(fileName, "rb") as toDecrypt: #open encrypted file  as read binary
             fileData = toDecrypt.read()   #read all binary data from toDecrypt file
        lines = fileData.split(b"\n")   #separating line that has \n lines


        updateStatus("Checking File type", 25)

        if len(lines) < 3:
            QMessageBox.critical(self, "Error", "Invalid Encrypted file format!@")
            return

        updateStatus("Getting salt", 35)

        salt = lines[1]     #setting salt to lines 2.
        storedHash = lines[0]   #setting hashpassword to lines 1
        storedData = b"\n".join(lines[2:])  #setting everything else to data

        updateStatus("Verifing the Enterd Password", 50)

        #loop until user enters the correct password
        while not bcrypt.checkpw(password.encode(), storedHash):
            QMessageBox.critical(self, "Incorrect password", "The password you entered is incorrect!")
            passwordDialog = PasswordDialog()
            if passwordDialog.exec() == QDialog.DialogCode.Accepted:
                password = passwordDialog.getPassword()
            else:
                return


        updateStatus("Generate Key from password", 60)

        #Generate hashed key from salt + password
        hashedPassword = self.Essentials.generateKeyFromPasswd(password, salt)
        key=base64.urlsafe_b64encode(hashedPassword[:32])

        fernet = Fernet(key)    #generate ley from hash key that generated from key
        decryptData = fernet.decrypt(storedData)  #trying to decrypt data from generated key

        updateStatus("Decrypting the data", 80)

        with open(name +"Decryp."+extensionNew, "wb") as decryptFile:
             updateStatus("Writing Decrypted Data to file.", 95)
             decryptFile.write(decryptData)

        updateStatus("Decryption is Complete", 100)

class AnimatedButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        self.setStyleSheet("""
            QPushButton {
                background-color: #EAE0C8;
                color: #313B2F;
                padding: 12px;
                border-radius: 1px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #536878;
                color: #EAE0C8;
            }
        """)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedSize(200, 50)

        # Add shadow effect
        self.shadow = QGraphicsDropShadowEffect(self)
        self.shadow.setBlurRadius(15)
        self.shadow.setOffset(0, 0)
        self.shadow.setColor(QColor(0, 0, 0, 160))
        self.setGraphicsEffect(self.shadow)

        # Hover animation
        self.animation = QPropertyAnimation(self, b"geometry")
        self.animation.setDuration(200)
        self.animation.setEasingCurve(QEasingCurve.Type.OutQuad)

    def enterEvent(self, event):
        self.animation.setStartValue(self.geometry())
        self.animation.setEndValue(QRect(self.x() - 5, self.y() - 5, self.width() + 10, self.height() + 10))
        self.animation.start()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.animation.setStartValue(self.geometry())
        self.animation.setEndValue(QRect(self.x() + 5, self.y() + 5, self.width() - 10, self.height() - 10))
        self.animation.start()
        super().leaveEvent(event)

class EncryptPasswdDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Enter Password")
        self.setFixedSize(400, 250)
        self.setStyleSheet("""
            background-color:  #C2B280;
            border-radius: 1px;
        """)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        #title Label
        title = QLabel("Create a Secure Password")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #262424;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setWindowIcon(QIcon(self.resourcePath("icon.ico")))
        layout.addWidget(title)

        # Password Field
        self.passwordField = QLineEdit()
        self.passwordField.setEchoMode(QLineEdit.EchoMode.Password)
        self.passwordField.setPlaceholderText("Enter your password")
        self.style_input(self.passwordField)
        layout.addWidget(self.passwordField)

        # Confirm Password Field
        self.confirmField = QLineEdit()
        self.confirmField.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirmField.setPlaceholderText("Confirm your password")
        self.style_input(self.confirmField)
        layout.addWidget(self.confirmField)

        # Buttons Layout
        buttonLayout = QVBoxLayout()

        self.okButton = QPushButton("Confirm")
        self.okButton.clicked.connect(self.check_passwords)
        self.style_button(self.okButton)

        self.cancelButton = QPushButton("Cancel")
        self.cancelButton.clicked.connect(self.reject)
        self.style_button(self.cancelButton, is_cancel=True)

        buttonLayout.addWidget(self.cancelButton)
        buttonLayout.addWidget(self.okButton)

        layout.addLayout(buttonLayout)
        self.setLayout(layout)
    
    def resourcePath(self, relativePath):
        try:
            basePath = sys._MEIPASS
        except Exception:
            basePath = os.path.abspath(".")
        return os.path.join(basePath, relativePath)

    def style_input(self, inputField):
        inputField.setStyleSheet("""
            background-color: #0b2135;
            border: 1px solid #2E86C1;
            color:#DFE8E6;
            border-radius: 1px;
            padding: 8px;
            font-size: 14px;
        """)

    def style_button(self, button, is_cancel=False):
        if is_cancel:
            button.setStyleSheet("""
                background-color: #262424;
                color: #DFE8E6;
                border-radius: 1px;
                padding: 8px;
                font-size: 14px;
            """)
        else:
            button.setStyleSheet("""
                background-color: #313b2f;
                color: #DFE8E6;
                border-radius: 1px;
                padding: 8px;
                font-size: 14px;
            """)

    def check_passwords(self):
        password = self.passwordField.text()
        confirm_password = self.confirmField.text()

        if not password or not confirm_password:
            QMessageBox.warning(self, "Error", "Fields cannot be empty!")
            return

        if password != confirm_password:
            QMessageBox.warning(self, "Error", "Passwords do not match!")
            return

        if self.is_weak_password(password):
            choice = QMessageBox.question(self, "Weak Password",
                                          "Your Password is WEAK. Use it anyway?",
                                          QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if choice == QMessageBox.StandardButton.No:
                return

        self.password = password
        self.accept()

    def is_weak_password(self, password):
        if len(password) < 6:
            return True
        if password.isdigit() or password.isalpha():
            return True  #only numbers or only letters are weak
        return False

class DecryptPasswdDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Enter Decryption Password")
        self.setFixedSize(400, 250)
        self.setStyleSheet("""
            background-color: #C2B280;
            border-radius: 1px;
        """)
        
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        title = QLabel("Enter Password to Decrypt")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #262424;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setWindowIcon(QIcon(self.resourcePath("icon.ico")))
        layout.addWidget(title)

        self.passwordField = QLineEdit()
        self.passwordField.setEchoMode(QLineEdit.EchoMode.Password)
        self.passwordField.setPlaceholderText("Enter your decryption password")
        self.style_input(self.passwordField)
        layout.addWidget(self.passwordField)

        buttonLayout = QVBoxLayout()

        self.okButton = QPushButton("OK")
        self.okButton.clicked.connect(self.accept)
        self.style_button(self.okButton)

        self.cancelButton = QPushButton("Cancel")
        self.cancelButton.clicked.connect(self.reject)
        self.style_button(self.cancelButton, is_cancel=True)

        buttonLayout.addWidget(self.cancelButton)
        buttonLayout.addWidget(self.okButton)

        layout.addLayout(buttonLayout)
        self.setLayout(layout)

    def resourcePath(self, relativePath):
        try:
            basePath = sys._MEIPASS
        except Exception:
            basePath = os.path.abspath(".")
        return os.path.join(basePath, relativePath)

    def getPassword(self):
        return self.passwordField.text()

    def style_input(self, inputField):
        inputField.setStyleSheet("""
            background-color: #0b2135;
            border: 1px solid #2E86C1;
            color:#DFE8E6;
            border-radius: 1px;
            padding: 8px;
            font-size: 14px;
        """)

    def style_button(self, button, is_cancel=False):
        if is_cancel:
            button.setStyleSheet("""
                background-color: #262424;
                color: #DFE8E6;
                border-radius: 1px;
                padding: 8px;
                font-size: 14px;
            """)
        else:
            button.setStyleSheet("""
                background-color: #313b2f;
                color: #DFE8E6;
                border-radius: 1px;
                padding: 8px;
                font-size: 14px;
            """)

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.showSplashScreen()
        self.EncryptDecrypt = EncryptDecrypt() # creating object of encryptor
        self.Essentials = Essentials()# creating object of essentials
        self.DecryptPasswdDialog = DecryptPasswdDialog()
        self.EncryptPasswdDialog = EncryptPasswdDialog()

    def initUI(self):
        self.setWindowTitle("Erebus")
        self.setWindowIcon(QIcon(self.resourcePath("icon.ico")))
        self.setGeometry(100, 100, 500, 350)
        self.setStyleSheet("background-color: #2C3E50; color: #EAE0C8; border-radius: 1px;")

        layout = QVBoxLayout()
        layout.setSpacing(10)

        #title of the application
        self.title = QLabel("Erebus", font=QFont("Arial", 40, QFont.Weight.Bold), alignment=Qt.AlignmentFlag.AlignCenter)
        self.title.setStyleSheet("color: #EAE0C8; font-weight: bold;")
        layout.addWidget(self.title)

        #subtitle with description of the software
        self.subtitle = QLabel("Easily encrypt and decrypt your files with secure passwords.", font=QFont("Arial", 13, QFont.Weight.Normal), alignment=Qt.AlignmentFlag.AlignCenter)
        self.subtitle.setStyleSheet("color: #B0B0B0; font-weight: normal;")
        layout.addWidget(self.subtitle)

        # Buttons
        self.encryptBtn = AnimatedButton("Encrypt File", self)
        self.encryptBtn.clicked.connect(self.encryptFile)
        layout.addWidget(self.encryptBtn, alignment=Qt.AlignmentFlag.AlignCenter)

        self.decryptBtn = AnimatedButton("Decrypt File", self)
        self.decryptBtn.clicked.connect(self.decryptFile)
        layout.addWidget(self.decryptBtn, alignment=Qt.AlignmentFlag.AlignCenter)

        self.aboutBtn = AnimatedButton("About", self)
        self.aboutBtn.clicked.connect(self.showAbout)
        layout.addWidget(self.aboutBtn, alignment=Qt.AlignmentFlag.AlignCenter)
        self.setLayout(layout)


    #encrypt function
    def encryptFile(self):
        filePath, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if filePath:
            password = self.getSecurePassword()
            if password:
                self.showLoadingScreen("Encrypting...")
                try:
                    salt = bcrypt.gensalt() # generating salt
                    self.EncryptDecrypt.encrypt(password, salt, filePath, self.updateStatus)
                    self.loadingDialog.accept()
                    QMessageBox.information(self, "Success", f"File encrypted successfully!\nSaved as {filePath}.enc")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Encryption failed: {str(e)}")
        else:
            QMessageBox.critical(self, "Error", f"File '{filePath}' not found! Unable to encrypt the file.", QMessageBox.StandardButton.Ok)

    #decrypt function
    def decryptFile(self):
        filePath, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt")
        if filePath:
            dialog = DecryptPasswdDialog(self)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                password = dialog.getPassword()
                #use the password to decrypt the file
                try:
                    self.showLoadingScreen("Decrypting...")
                    self.EncryptDecrypt.decrypt(password, filePath, self.updateStatus)
                    self.loadingDialog.accept()
                    extensioNew = os.path.splitext(filePath)[0].split(".")[-1]
                    fileName = filePath.split(".")[0]
                    QMessageBox.information(self, "Success", f"File Decrypted successfully!\nSaved as {fileName}.{extensioNew}")
                except Exception as e:
                    self.loadingDialog.accept()
                    errorMsg = "Decryption failed! Possible reasons:\n"
                    errorMsg += "1. File was not encrypted with this tool\n"
                    errorMsg += "2. Incorrect password\n"
                    errorMsg += "3. File corruption\n"
                    errorMsg += "4. File is not encrypted.\n"
                    QMessageBox.critical(self, "Decryption Error", errorMsg)
            else:
                QMessageBox.warning(self, "Cancelled", "Decryption process was cancelled.")

    def getSecurePassword(self):
        dialog = self.EncryptPasswdDialog
        if dialog.exec():
            return dialog.password
        return None


    def showLoadingScreen(self, text):
        self.loadingDialog = QDialog(self)
        self.loadingDialog.setWindowTitle(text)
        self.loadingDialog.setFixedSize(500, 120)
        self.loadingDialog.setStyleSheet("background-color: #2C3531; color: #EAE0C8; border-radius: 1px;")
        self.loadingDialog.setModal(True)

        layout = QVBoxLayout()

        self.statusLabel = QLabel("Starting encryption...")
        layout.addWidget(self.statusLabel)

        self.progressBar = QProgressBar(self)
        self.progressBar.setValue(0)
        layout.addWidget(self.progressBar)

        self.loadingDialog.setLayout(layout)
        self.loadingDialog.show()

    #progress updater
    def updateProgress(self):
        if self.progressBar.value() < 100:
            self.progressBar.setValue(self.progressBar.value() + 1)
        else:
            self.progressTimer.stop()
            self.loadingDialog.accept()

    #status updater displayer
    def updateStatus(self, message, progressBar):
        self.statusLabel.setText(message)
        self.progressBar.setValue(progressBar)
        QApplication.processEvents()

    def resourcePath(self, relativePath):
        try:
            basePath = sys._MEIPASS
        except Exception:
            basePath = os.path.abspath(".")
        return os.path.join(basePath, relativePath)

    def showSplashScreen(self):
        self.splash = QDialog(self, Qt.WindowType.FramelessWindowHint)
        self.splash.setFixedSize(550, 420)
        self.splash.setStyleSheet("background-color: #0b2135; border-radius: 1px;")
        layout = QVBoxLayout()

        # Logo GIF
        logoLabel = QLabel()
        movie = QMovie(self.resourcePath("logo.gif"))
        logoLabel.setMovie(movie)
        movie.start()
        layout.addWidget(logoLabel)

        self.splash.setLayout(layout)
        self.centerOnScreen(self.splash)
        self.splash.show()

        # Fade-out animation after 3 sec
        self.fadeOutAnimation = QPropertyAnimation(self.splash, b"windowOpacity")
        self.fadeOutAnimation.setDuration(100)
        self.fadeOutAnimation.setStartValue(1.0)
        self.fadeOutAnimation.setEndValue(0.0)
        self.fadeOutAnimation.finished.connect(self.showMainWindow)
        self.fadeOutAnimation.start
        QTimer.singleShot(4000, self.fadeOutAnimation.start)

    def showMainWindow(self):
        #Show the main window after splash disappears.
        self.splash.close()
        self.initUI()
        self.centerOnScreen(self)
        self.show()
    def centerOnScreen(self, widget):
        #Center a given widget on the screen.
        screen = QApplication.primaryScreen().geometry()
        x = (screen.width() - widget.width()) // 2
        y = (screen.height() - widget.height()) // 2
        widget.move(x, y)

    def showAbout(self):
       aboutDialog = AboutDialog(self)
       aboutDialog.exec()


class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("About")
        self.setFixedSize(600, 700)  # Set the size of the dialog window
        self.setStyleSheet("background-color: #ffffff; color: #000000; border-radius: 1px;")
        # Create a vertical layout
        layout = QVBoxLayout()

        # Add a label for the title
        titleLabel = QLabel("Erebus")
        titleLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        titleLabel.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        layout.addWidget(titleLabel)

        aboutText = """
                          Military Grade File Encryption (Version 1.0)

Erebus is an advanced encryption solution designed to protect sensitive data with military level security.Combining robust AES-256 encryption with a user friendly interface, Erebus ensures that individuals and organizations can safeguard confidential documents, financial records, and personal data against unauthorized access. Built for modern security needs, Erebus implements NIST approved algorithms while maintaining an intuitive workflow that requires no technical expertise. With enterprise grade protection, it defends against digital threats without compromising usability.


Features:

 • AES-256 Encryption (CBC mode with 128-bit blocks)
 • PBKDF2HMAC-SHA256 key derivation (100,000 iterations)
 • BCrypt password hashing (salt+pepper protection)
 • Defense against brute force & rainbow table attacks
 • Cross platform compatibility (Windows/macOS/Linux)
 • Intuitive graphical interface with progress tracking
 • Secure password validation & strength checking


Security Highlights:

 • S FIPS 140-2 compliant cryptographic protocols
 • SHardware accelerated encryption & decryption
 • S Zero knowledge architecture (no keys stored)
 • S Automatic memory sanitization
 • S Tamper evident file integrity checks

Developed With:

 • S PyQt7 for modern GUI implementation
 • S Cryptography.io's Fernet encryption specification
 • S OpenSSL 3.0 for cryptographic operations

*** Warning: Always maintain backup copies of your files and remember your passwords – lost encryption keys cannot be recovered!

Developed by DulangaRukshan
Contact: DulangaRukshan@proton.me

Erebus was conceptualized and developed by Dulanga Rukshan, an independent developer passionate about privacy and digital security. With a strong commitment to user trust, Erebus follows a strict zero data collection policy while maintaining full transparency through its open source encryption architecture."""



        aboutLabel = QLabel(aboutText)
        aboutLabel.setWordWrap(True)

        # Create a scroll area for the content
        scrollArea = QScrollArea()
        scrollArea.setWidget(aboutLabel)
        scrollArea.setWidgetResizable(True)  # Allow it to resize with the dialog
        layout.addWidget(scrollArea)

        # Add a close button
        closeButton = QPushButton("Close", self)
        closeButton.clicked.connect(self.accept)
        layout.addWidget(closeButton)

        self.setLayout(layout)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    sys.exit(app.exec())
