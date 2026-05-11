from PyQt5.QtWidgets import QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox, QFrame
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont
from vaultsecure_backend import authenticate_user
from mfa_ui import MFAWindow

class LoginScreen(QWidget):
    login_successful = pyqtSignal(str, str)

    def __init__(self, main_window=None):
        super().__init__()
        self.main_window = main_window

        # Outer frame for styling and padding
        frame = QFrame()
        frame.setStyleSheet("background-color: #23233a; border-radius: 16px;")
        frame_layout = QVBoxLayout(frame)
        frame_layout.setAlignment(Qt.AlignCenter)
        frame_layout.setContentsMargins(48, 48, 48, 48)
        frame_layout.setSpacing(24)

        title = QLabel("Login to VaultSecure")
        title.setFont(QFont("Arial", 28, QFont.Bold))
        title.setStyleSheet("color: white; margin-bottom: 16px;")
        title.setAlignment(Qt.AlignCenter)
        frame_layout.addWidget(title)

        subtitle = QLabel("Welcome back! Please enter your credentials.")
        subtitle.setFont(QFont("Arial", 16))
        subtitle.setStyleSheet("color: #b0b0b0; margin-bottom: 32px;")
        subtitle.setAlignment(Qt.AlignCenter)
        frame_layout.addWidget(subtitle)

        self.username = QLineEdit()
        self.username.setPlaceholderText("Username")
        self.username.setFont(QFont("Arial", 16))
        self.username.setStyleSheet("padding: 12px; border-radius: 8px; background-color: #181828; color: white;")
        frame_layout.addWidget(self.username)

        self.password = QLineEdit()
        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setFont(QFont("Arial", 16))
        self.password.setStyleSheet("padding: 12px; border-radius: 8px; background-color: #181828; color: white;")
        frame_layout.addWidget(self.password)

        login_button = QPushButton("Login")
        login_button.setFont(QFont("Arial", 16, QFont.Bold))
        login_button.setStyleSheet("background-color: #1ec1a2; color: white; border-radius: 8px; padding: 12px;")
        frame_layout.addWidget(login_button)
        login_button.clicked.connect(self.handle_login)

        register_button = QPushButton("Register")
        register_button.setFont(QFont("Arial", 16, QFont.Bold))
        register_button.setStyleSheet("background-color: #23233a; color: #1ec1a2; border: 2px solid #1ec1a2; border-radius: 8px; padding: 12px;")
        frame_layout.addWidget(register_button)
        
        # Handle case where main_window is None
        if main_window is not None:
            register_button.clicked.connect(main_window.show_register)
        else:
            register_button.setEnabled(False)  # Disable the button if no main_window

        # Center the frame in the window
        outer_layout = QVBoxLayout(self)
        outer_layout.setAlignment(Qt.AlignCenter)
        outer_layout.addWidget(frame)
        self.setLayout(outer_layout)

    def show_login_from_mfa(self):
        """Callback to return to login screen from MFA"""
        if hasattr(self, 'mfa') and self.mfa:
            self.mfa.close()
        self.show()
        self.username.clear()
        self.password.clear()
        self.username.setFocus()

    def handle_login(self):
        user = self.username.text()
        pw = self.password.text()
        success, mfa_secret = authenticate_user(user, pw)
        if not success:
            from vaultsecure_backend import user_exists
            if not user_exists(user):
                reply = QMessageBox.question(
                    self,
                    "User Not Found",
                    f"No account found for '{user}'. Would you like to create a new account?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.Yes and self.main_window is not None:
                    self.main_window.show_register()
                return
            QMessageBox.critical(self, "Login Failed", "Invalid username or password.")
            return

        if not mfa_secret:
            if self.main_window is not None:
                self.main_window.show_dashboard(user, pw)
            else:
                self.login_successful.emit(user, pw)
            return
        
        # Hide login screen before showing MFA
        self.hide()
        
        # Handle case where main_window is None
        if self.main_window is not None:
            self.mfa = MFAWindow(
                user, 
                mfa_secret, 
                lambda: self.main_window.show_dashboard(user, pw),
                self.show_login_from_mfa  # Add back callback
            )
            self.mfa.show()
        else:
            # Emit signal for successful login instead of directly creating dashboard
            def on_mfa_success():
                self.login_successful.emit(user, pw)
            
            self.mfa = MFAWindow(
                user, 
                mfa_secret, 
                on_mfa_success,
                self.show_login_from_mfa  # Add back callback
            )
            self.mfa.show()