from PyQt5.QtWidgets import QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QMessageBox, QFrame
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from vaultsecure_backend import verify_totp

class MFAWindow(QWidget):
    def __init__(self, username, secret, success_callback, back_callback=None):
        super().__init__()
        self.secret = secret
        self.success_callback = success_callback
        self.back_callback = back_callback
        self.setWindowTitle("Multi-Factor Authentication")
        self.setFixedSize(450, 350)
        
        # Outer frame for styling and padding
        frame = QFrame()
        frame.setStyleSheet("background-color: #23233a; border-radius: 16px;")
        frame_layout = QVBoxLayout(frame)
        frame_layout.setAlignment(Qt.AlignCenter)
        frame_layout.setContentsMargins(40, 40, 40, 40)
        frame_layout.setSpacing(20)

        # Title
        title = QLabel("Two-Factor Authentication")
        title.setFont(QFont("Arial", 22, QFont.Bold))
        title.setStyleSheet("color: white; margin-bottom: 8px;")
        title.setAlignment(Qt.AlignCenter)
        frame_layout.addWidget(title)

        # Subtitle
        subtitle = QLabel("Please enter your 6-digit authentication code")
        subtitle.setFont(QFont("Arial", 14))
        subtitle.setStyleSheet("color: #b0b0b0; margin-bottom: 20px;")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setWordWrap(True)
        frame_layout.addWidget(subtitle)

        # Token input
        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("Enter 6-digit code")
        self.token_input.setFont(QFont("Arial", 20, QFont.Bold))
        self.token_input.setStyleSheet("""
            QLineEdit {
                padding: 15px; 
                border: 2px solid #181828;
                border-radius: 10px; 
                background-color: #181828; 
                color: white;
                font-size: 20px;
                font-weight: bold;
                letter-spacing: 3px;
                min-height: 20px;
            }
            QLineEdit:focus {
                border: 2px solid #1ec1a2;
                background-color: #1f1f2e;
            }
            QLineEdit::placeholder {
                color: #666;
                font-size: 16px;
                letter-spacing: normal;
            }
        """)
        self.token_input.setMaxLength(6)
        self.token_input.setAlignment(Qt.AlignCenter)
        # Enable only numeric input
        self.token_input.setInputMask("000000")
        frame_layout.addWidget(self.token_input)

        # Add some spacing
        frame_layout.addSpacing(10)

        # Buttons layout
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(15)

        # Back button (if callback provided)
        if back_callback:
            back_button = QPushButton("← Back to Login")
            back_button.setFont(QFont("Arial", 14))
            back_button.setStyleSheet("""
                QPushButton {
                    background-color: #636e72; 
                    color: white; 
                    border: none;
                    border-radius: 8px; 
                    padding: 12px 20px;
                    min-width: 120px;
                }
                QPushButton:hover {
                    background-color: #7a8084;
                }
                QPushButton:pressed {
                    background-color: #525558;
                }
            """)
            back_button.clicked.connect(self.go_back)
            buttons_layout.addWidget(back_button)

        # Verify button
        verify_button = QPushButton("Verify Code")
        verify_button.setFont(QFont("Arial", 14, QFont.Bold))
        verify_button.setStyleSheet("""
            QPushButton {
                background-color: #1ec1a2; 
                color: white; 
                border: none;
                border-radius: 8px; 
                padding: 12px 20px;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #17a085;
            }
            QPushButton:pressed {
                background-color: #138f75;
            }
        """)
        verify_button.clicked.connect(self.verify_token)
        verify_button.setDefault(True)  # Make it the default button (Enter key)
        buttons_layout.addWidget(verify_button)

        frame_layout.addLayout(buttons_layout)

        # Center the frame in the window
        outer_layout = QVBoxLayout(self)
        outer_layout.setAlignment(Qt.AlignCenter)
        outer_layout.setContentsMargins(20, 20, 20, 20)
        outer_layout.addWidget(frame)
        self.setLayout(outer_layout)

        # Connect Enter key to verify
        self.token_input.returnPressed.connect(self.verify_token)
        
        # Focus on input field
        self.token_input.setFocus()

    def verify_token(self):
        token = self.token_input.text().strip().replace(" ", "")  # Remove any spaces
        
        if len(token) != 6 or not token.isdigit():
            QMessageBox.warning(self, "Invalid Input", "Please enter a 6-digit numeric code.")
            self.token_input.clear()
            self.token_input.setFocus()
            return

        if verify_totp(self.secret, token):
            self.success_callback()
            self.close()
        else:
            QMessageBox.critical(self, "MFA Failed", "Invalid MFA token. Please try again.")
            self.token_input.clear()
            self.token_input.setFocus()

    def go_back(self):
        if self.back_callback:
            self.back_callback()
            self.close()