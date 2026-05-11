def evaluate_password_strength(password):
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    length = len(password)
    complexity = sum([has_upper, has_digit, has_symbol])

    if length >= 12 and complexity == 3:
        return "Strong", "green"
    elif length >= 8 and complexity >= 2:
        return "Medium", "orange"
    else:
        return "Weak", "red"

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTableWidget,
    QTableWidgetItem, QHBoxLayout, QMessageBox, QInputDialog
)
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtCore import Qt
from vaultsecure_backend import retrieve_passwords, store_password, authenticate_user, get_user_timezone

# --- Timezone abbreviation mapping ---
TIMEZONE_ABBR = {
    "America/Los_Angeles": "PST",
    "America/Chicago": "CST",
    "America/New_York": "EST"
}

def normalize_service(service):
    return service.strip().lower()

class VaultManager(QWidget):
    def __init__(self, username="test_user", encryption_key="test_encryption_key"):
        super().__init__()
        self.username = username
        self.encryption_key = encryption_key
        self.view_states = {}
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignTop)
        layout.setSpacing(32)
        layout.setContentsMargins(32, 32, 32, 32)

        # Styled Title
        title = QLabel("Password Management")
        title.setFont(QFont("Arial", 28, QFont.Bold))
        title.setStyleSheet("margin-bottom: 8px;")
        layout.addWidget(title)

        subtitle = QLabel("Manage your saved passwords below.")
        subtitle.setFont(QFont("Arial", 18))
        subtitle.setStyleSheet("margin-bottom: 24px;")
        layout.addWidget(subtitle)

        # Table styling
        self.table = QTableWidget()
        self.table.verticalHeader().setVisible(False)
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["Service", "Password", "", "", "", "Strength", "Last Updated"])
        self.table.setColumnWidth(0, 200)
        self.table.setColumnWidth(1, 200)
        self.table.setColumnWidth(5, 120)
        self.table.setColumnWidth(6, 300)  # Wider column for Last Updated
        self.table.setStyleSheet("""
            QTableWidget {
                font-size: 18px;
                background-color: #23233a;
                color: white;
                border-radius: 8px;
            }
            QHeaderView::section {
                font-size: 18px;
                background-color: #23233a;
                color: #b0b0b0;
                padding: 8px;
            }
        """)
        self.table.setMinimumHeight(400)
        layout.addWidget(self.table)

        # Add form styling
        form_layout = QHBoxLayout()
        self.service_input = QLineEdit()
        self.service_input.setPlaceholderText("Service")
        self.service_input.setFont(QFont("Arial", 14))
        self.service_input.setFixedWidth(200)
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setFont(QFont("Arial", 14))
        self.password_input.setFixedWidth(200)
        self.add_button = QPushButton("Add")
        self.add_button.setFont(QFont("Arial", 14, QFont.Bold))
        self.add_button.setStyleSheet("background-color: #1ec1a2; color: white; border-radius: 6px; padding: 8px 16px;")
        self.add_button.setEnabled(False)
        self.password_input.textChanged.connect(self.show_strength_feedback)
        self.add_button.clicked.connect(self.add_entry)
        form_layout.addWidget(self.service_input)
        form_layout.addWidget(self.password_input)
        form_layout.addWidget(self.add_button)
        layout.addLayout(form_layout)

        self.strength_label = QLabel("")
        self.strength_label.setFont(QFont("Arial", 12))
        self.strength_label.setStyleSheet("color: white; margin-left: 16px;")
        layout.addWidget(self.strength_label)

        self.criteria_label = QLabel("🔑 Strong = 12+ chars, uppercase, number, symbol<br>🟠 Medium = 8+ chars<br>🔴 Weak = anything else")
        self.criteria_label.setFont(QFont("Arial", 11))
        self.criteria_label.setStyleSheet("color: gray")
        layout.addWidget(self.criteria_label)

        self.refresh_table()

    def get_user_timezone(self):
        return get_user_timezone(self.username)
    
    def format_datetime_user_tz(self, dt_str):
        from datetime import datetime
        user_tz = self.get_user_timezone()
        abbr = TIMEZONE_ABBR.get(user_tz, user_tz)
        try:
            from zoneinfo import ZoneInfo
            tz = ZoneInfo(user_tz)
            dt = datetime.fromisoformat(dt_str)
            dt = dt.replace(tzinfo=ZoneInfo("UTC")).astimezone(tz)
            return dt.strftime("%b %d, %Y %I:%M %p ") + abbr
        except ImportError:
            from pytz import timezone, utc
            tz = timezone(user_tz)
            dt = datetime.fromisoformat(dt_str)
            dt = utc.localize(dt).astimezone(tz)
            return dt.strftime("%b %d, %Y %I:%M %p ") + abbr
        except Exception:
            return dt_str
        
    def refresh_table(self):
        self.table.setRowCount(0)
        self.entries = retrieve_passwords(self.username, self.encryption_key)
        self.view_states = {}

        # Set column widths for better visibility
        self.table.setColumnWidth(1, 250)  # Password column (index 1), adjust width as needed

        for row, (service, password, last_updated) in enumerate(self.entries):
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(service))
            self.table.setItem(row, 1, QTableWidgetItem("●●●●●●●●"))
            strength, color = evaluate_password_strength(password)
            strength_item = QTableWidgetItem(strength)
            strength_item.setForeground(QColor(color))
            self.table.setItem(row, 5, strength_item)
            # Format last_updated for user timezone display with abbreviation
            formatted_last_updated = self.format_datetime_user_tz(last_updated) if last_updated else ""
            self.table.setItem(row, 6, QTableWidgetItem(formatted_last_updated))

            # View Button
            view_btn = QPushButton("👁 View")
            view_btn.clicked.connect(lambda _, r=row: self.toggle_password_visibility(r))
            self.table.setCellWidget(row, 2, view_btn)

            # Update Button
            update_btn = QPushButton("📝 Update")
            update_btn.clicked.connect(lambda _, r=row: self.prompt_update_password(r))
            self.table.setCellWidget(row, 3, update_btn)

            # Delete Button
            delete_btn = QPushButton("🗑 Delete")
            delete_btn.clicked.connect(lambda _, r=row: self.confirm_delete_entry(r))
            self.table.setCellWidget(row, 4, delete_btn)

    def toggle_password_visibility(self, row):
        is_visible = self.view_states.get(row, False)
        if not is_visible:
            input_pw, ok = QInputDialog.getText(self, "Re-enter Vault Password", "Enter your login password:", QLineEdit.Password)
            if ok:
                success, _ = authenticate_user(self.username, input_pw)
                if success:
                    pw = self.entries[row][1]
                    self.table.setItem(row, 1, QTableWidgetItem(pw))
                    self.table.cellWidget(row, 2).setText("🙈 Hide")
                    self.view_states[row] = True
                else:
                    QMessageBox.critical(self, "Access Denied", "Incorrect vault password.")
        else:
            # FIX: Retrieve password for strength calculation
            password = self.entries[row][1]
            self.table.setItem(row, 1, QTableWidgetItem("●●●●●●●●"))
            strength, color = evaluate_password_strength(password)
            strength_item = QTableWidgetItem(strength)
            strength_item.setForeground(QColor(color))
            self.table.setItem(row, 5, strength_item)
            self.table.cellWidget(row, 2).setText("👁 View")
            self.view_states[row] = False

    def confirm_delete_entry(self, row):
        input_pw, ok = QInputDialog.getText(self, "Confirm Delete", "Enter your login password:", QLineEdit.Password)
        if ok and authenticate_user(self.username, input_pw)[0]:
            service = normalize_service(self.entries[row][0])
            if any(char in service for char in [";", "'", '"', "--", "\\"]):
                QMessageBox.warning(self, "Invalid Service", "Service name contains invalid characters.")
                return
            from vaultsecure_backend import delete_password
            success, message = delete_password(self.username, service, self.encryption_key)
            if success:
                self.refresh_table()
                QMessageBox.information(self, "Success", message)
            else:
                QMessageBox.critical(self, "Delete Failed", message)
        else:
            QMessageBox.critical(self, "Delete Failed", "Authentication failed or cancelled.")

    def prompt_update_password(self, row):
        # Disable the update and delete buttons while editing
        self.table.cellWidget(row, 3).setEnabled(False)
        self.table.cellWidget(row, 4).setEnabled(False)

        # Replace the password cell with a QLineEdit for inline editing
        pw_edit = QLineEdit()
        pw_edit.setPlaceholderText("New password")
        pw_edit.setFont(QFont("Arial", 16))  # Match displayed font
        self.table.setCellWidget(row, 1, pw_edit)

        # Strength feedback label
        strength_label = QLabel("")
        strength_label.setFont(QFont("Arial", 16))  # Match displayed font
        self.table.setCellWidget(row, 5, strength_label)

        def update_strength_label():
            pw = pw_edit.text()
            strength, color = evaluate_password_strength(pw)
            strength_label.setText(strength)
            strength_label.setStyleSheet(f"color: {color}")

        pw_edit.textChanged.connect(update_strength_label)
        update_strength_label()  # Initialize with empty or current value

        # Create Save and Cancel buttons
        save_btn = QPushButton("💾 Save")
        cancel_btn = QPushButton("✖ Cancel")

        def restore_row():
            self.refresh_table()

        from vaultsecure_backend import update_password

        def save_new_password():
            new_pw = pw_edit.text().strip()
            if not new_pw:
                QMessageBox.warning(self, "Cancelled", "No new password provided.")
                restore_row()
                return
            strength, _ = evaluate_password_strength(new_pw)
            if strength != "Strong":
                QMessageBox.warning(self, "Weak Password", "Only strong passwords can be set.")
                return
            # Authenticate user before saving
            input_pw, ok = QInputDialog.getText(self, "Authenticate Update", "Enter your login password:", QLineEdit.Password)
            if not (ok and authenticate_user(self.username, input_pw)[0]):
                QMessageBox.critical(self, "Update Failed", "Authentication failed or cancelled.")
                restore_row()
                return
            service = normalize_service(self.entries[row][0])
            from vaultsecure_backend import update_password
            success, message = update_password(self.username, service, new_pw, self.encryption_key)
            if success:
                QMessageBox.information(self, "Success", message)
                self.refresh_table()
            else:
                QMessageBox.critical(self, "Error", message)
                restore_row()

        save_btn.clicked.connect(save_new_password)
        cancel_btn.clicked.connect(restore_row)

        # Place Save and Cancel buttons in the update and delete columns
        self.table.setCellWidget(row, 3, save_btn)
        self.table.setCellWidget(row, 4, cancel_btn)

    def add_entry(self):
        service = normalize_service(self.service_input.text())
        password = self.password_input.text().strip()

        # Basic input sanitization
        if not service or not password:
            QMessageBox.warning(self, "Missing Info", "Both fields are required.")
            return
        if any(char in service for char in [";", "'", '"', "--", "\\"]):
            QMessageBox.warning(self, "Invalid Service", "Service name contains invalid characters.")
            return
        if len(service) > 100:
            QMessageBox.warning(self, "Invalid Service", "Service name is too long.")
            return

        strength, _ = evaluate_password_strength(password)
        if strength != "Strong":
            QMessageBox.warning(self, "Weak Password", "Only strong passwords can be added.")
            return

        # Expect (success, message) from store_password
        success, message = store_password(self.username, service, password, self.encryption_key)
        if success:
            self.service_input.clear()
            self.password_input.clear()
            self.refresh_table()
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.critical(self, "Error", message)

    def show_strength_feedback(self):
        pw = self.password_input.text()
        strength, color = evaluate_password_strength(pw)
        self.strength_label.setText(f"Password Strength: <span style='color:{color}'>{strength}</span>")
        if hasattr(self, 'add_button'):
            self.add_button.setEnabled(strength == "Strong")