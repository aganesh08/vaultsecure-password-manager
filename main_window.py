from PyQt5.QtWidgets import QWidget, QStackedWidget, QVBoxLayout
from login_screen import LoginScreen
from register_screen import RegisterScreen
from dashboard_ui import DashboardWindow

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VaultSecure")
        self.stack = QStackedWidget()
        self.login = LoginScreen(self)
        self.register = RegisterScreen(self)
        self.stack.addWidget(self.login)
        self.stack.addWidget(self.register)
        
        # Connect login successful signal
        self.login.login_successful.connect(self.show_dashboard)

        layout = QVBoxLayout()
        layout.addWidget(self.stack)
        self.setLayout(layout)
        self.stack.setCurrentWidget(self.login)

        # Initialize dashboard to None
        self.dashboard = None

    def show_register(self):
        self.register.reset_form()
        self.stack.setCurrentWidget(self.register)

    def show_login(self):
        """Show login screen and clear credentials for security"""
        # Clear login form fields for security
        self.login.username.clear()
        self.login.password.clear()
        self.login.username.setFocus()
        
        self.stack.setCurrentWidget(self.login)

    def show_dashboard(self, username, encryption_key):
        # Remove existing dashboard if present AND not None
        if hasattr(self, 'dashboard') and self.dashboard is not None:
            self.stack.removeWidget(self.dashboard)
            self.dashboard.deleteLater()
            self.dashboard = None
        
        # Create new dashboard
        self.dashboard = DashboardWindow(username, encryption_key, self)
        
        # Connect logout signal to secure logout handler
        self.dashboard.logout_requested.connect(self.handle_secure_logout)
        
        self.stack.addWidget(self.dashboard)
        self.stack.setCurrentWidget(self.dashboard)

    def handle_secure_logout(self):
        """Handle logout with proper security cleanup"""
        # Close and cleanup dashboard - Check for None
        if hasattr(self, 'dashboard') and self.dashboard is not None:
            self.stack.removeWidget(self.dashboard)
            self.dashboard.deleteLater()
            self.dashboard = None
        
        # Clear login credentials and show login screen
        self.show_login()