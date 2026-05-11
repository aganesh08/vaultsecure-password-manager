from PyQt5.QtWidgets import QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox, QFrame
from PyQt5.QtGui import QPixmap, QFont
from PyQt5.QtCore import Qt
import qrcode
import urllib.parse
from vaultsecure_backend import register_user

class RegisterScreen(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window

        # Outer frame for styling and padding
        frame = QFrame()
        frame.setStyleSheet("background-color: #23233a; border-radius: 16px;")
        frame_layout = QVBoxLayout(frame)
        frame_layout.setAlignment(Qt.AlignCenter)
        frame_layout.setContentsMargins(48, 48, 48, 48)
        frame_layout.setSpacing(20)  # Reduced spacing to fit more content

        self.title = QLabel("Register New Account")
        self.title.setFont(QFont("Arial", 28, QFont.Bold))
        self.title.setStyleSheet("color: white; margin-bottom: 16px;")
        self.title.setAlignment(Qt.AlignCenter)
        frame_layout.addWidget(self.title)

        self.subtitle = QLabel("Create your VaultSecure account below.")
        self.subtitle.setFont(QFont("Arial", 16))
        self.subtitle.setStyleSheet("color: #b0b0b0; margin-bottom: 32px;")
        self.subtitle.setAlignment(Qt.AlignCenter)
        frame_layout.addWidget(self.subtitle)

        self.username = QLineEdit()
        self.username.setPlaceholderText("Choose a username")
        self.username.setFont(QFont("Arial", 16))
        self.username.setStyleSheet("padding: 12px; border-radius: 8px; background-color: #181828; color: white;")
        frame_layout.addWidget(self.username)

        self.password = QLineEdit()
        self.password.setPlaceholderText("Choose a password")
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setFont(QFont("Arial", 16))
        self.password.setStyleSheet("padding: 12px; border-radius: 8px; background-color: #181828; color: white;")
        frame_layout.addWidget(self.password)

        self.submit = QPushButton("Register")
        self.submit.setFont(QFont("Arial", 16, QFont.Bold))
        self.submit.setStyleSheet("background-color: #1ec1a2; color: white; border-radius: 8px; padding: 12px;")
        self.submit.clicked.connect(self.handle_register)
        frame_layout.addWidget(self.submit)

        # QR code with viewable size
        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setStyleSheet("border: 2px solid #181828; border-radius: 8px; margin: 10px;")
        frame_layout.addWidget(self.qr_label)
        self.qr_label.hide()

        self.fallback = QLabel()
        self.fallback.setStyleSheet("color: #ffd600; font-weight: bold; font-size: 12px;")
        self.fallback.setAlignment(Qt.AlignCenter)
        self.fallback.setWordWrap(True)
        frame_layout.addWidget(self.fallback)
        self.fallback.hide()

        # Success info label (hidden initially)
        self.success_info = QLabel()
        self.success_info.setFont(QFont("Arial", 14))
        self.success_info.setStyleSheet("color: #1ec1a2; margin-top: 10px;")
        self.success_info.setAlignment(Qt.AlignCenter)
        self.success_info.setWordWrap(True)
        frame_layout.addWidget(self.success_info)
        self.success_info.hide()

        # Continue to Login button (hidden initially)
        self.continue_btn = QPushButton("Continue to Login")
        self.continue_btn.setFont(QFont("Arial", 16, QFont.Bold))
        self.continue_btn.setStyleSheet("""
            background-color: #1ec1a2; 
            color: white; 
            border-radius: 8px; 
            padding: 12px;
            margin-top: 10px;
        """)
        self.continue_btn.clicked.connect(self.go_to_login)
        frame_layout.addWidget(self.continue_btn)
        self.continue_btn.hide()

        # Center the frame in the window
        outer_layout = QVBoxLayout(self)
        outer_layout.setAlignment(Qt.AlignCenter)
        outer_layout.addWidget(frame)
        self.setLayout(outer_layout)

    def reset_form(self):
        """Reset the registration form to its initial state"""
        # Clear input fields
        self.username.clear()
        self.password.clear()
        
        # Reset title and subtitle
        self.title.setText("Register New Account")
        self.subtitle.setText("Create your VaultSecure account below.")
        
        # Hide post-registration elements
        self.qr_label.hide()
        self.qr_label.clear()  # Clear the QR code image
        self.fallback.hide()
        self.fallback.clear()  # Clear the manual setup key
        self.success_info.hide()
        self.continue_btn.hide()
        
        # Show registration form elements
        self.username.show()
        self.password.show()
        self.submit.show()
        self.subtitle.show()
        
        # Set focus to username field
        self.username.setFocus()

    def handle_register(self):
        username = self.username.text()
        password = self.password.text()
        
        # Basic validation
        if not username or not password:
            QMessageBox.warning(self, "Input Error", "Please fill in both username and password.")
            return
            
        if len(password) < 8:
            QMessageBox.warning(self, "Weak Password", "Password must be at least 8 characters long.")
            return
        
        success, result = register_user(username, password)
        if not success:
            QMessageBox.critical(self, "Registration Failed", result)
            return
            
        # Registration successful, show QR code setup
        secret = result
        label = urllib.parse.quote(f"VaultSecure:{username}")
        url = f"otpauth://totp/{label}?secret={secret}&issuer=VaultSecure"
        
        # Generate and display QR code with appropriate size
        qr = qrcode.make(url)
        path = "temp_qr.png"
        qr.save(path)
        pixmap = QPixmap(path)
        # Scale the QR code to a reasonable size
        scaled_pixmap = pixmap.scaled(200, 200, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.qr_label.setPixmap(scaled_pixmap)
        self.qr_label.show()
        
        # Show manual setup key
        self.fallback.setText(f"Manual Setup Key: {secret}")
        self.fallback.show()
        
        # Show success message and instructions
        self.success_info.setText("Scan this QR Code with your Authenticator App\n(Google Authenticator, Microsoft Authenticator)")
        self.success_info.show()
        
        # Hide registration form and show continue button
        self.username.hide()
        self.password.hide()
        self.submit.hide()
        self.subtitle.hide()
        self.continue_btn.show()
        
        # Update title to show completion
        self.title.setText("Setup Two-Factor Authentication")

    def go_to_login(self):
        """Navigate to login screen after successful registration"""
        self.main_window.show_login()