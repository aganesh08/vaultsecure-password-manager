from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QListWidget, QPushButton, QMessageBox, QComboBox, QProgressBar, QLineEdit,
    QWidget, QLabel, QHBoxLayout, QFrame, QStackedLayout, QFormLayout, QTableWidget, QTableWidgetItem, QListWidgetItem
)
from PyQt5.QtGui import QFont, QColor, QPalette
from PyQt5.QtCore import Qt, pyqtSignal
import sqlite3

from vault_ui import VaultManager
from vaultsecure_backend import retrieve_passwords, get_user_timezone, get_recent_activity_log, get_last_backup_time_raw

# --- Timezone abbreviation mapping ---
TIMEZONE_ABBR = {
    "America/Los_Angeles": "PST",
    "America/Chicago": "CST",
    "America/New_York": "EST"
}

class RestoreBackupDialog(QDialog):
    def __init__(self, username, encryption_key, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Restore from Backup")
        self.resize(400, 300)
        from vaultsecure_backend import list_backups, restore_vault_from_backup
        self.username = username
        self.encryption_key = encryption_key
        self.backups = list_backups(username)
        layout = QVBoxLayout(self)
        self.list_widget = QListWidget()
        for backup_id, backup_time in self.backups:
            formatted_time = self.format_datetime_user_tz(backup_time)
            self.list_widget.addItem(f"ID: {backup_id} | {formatted_time}")
        layout.addWidget(self.list_widget)
        restore_btn = QPushButton("Restore Selected Backup")
        restore_btn.clicked.connect(self.restore_selected)
        layout.addWidget(restore_btn)
        self.setLayout(layout)
    
    def get_user_timezone(self):
        from vaultsecure_backend import get_user_timezone
        return get_user_timezone(self.username)
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
        
    def restore_selected(self):
        from vaultsecure_backend import restore_vault_from_backup
        idx = self.list_widget.currentRow()
        if idx == -1:
            QMessageBox.warning(self, "No Selection", "Please select a backup to restore.")
            return
        backup_id = self.backups[idx][0]
        ok, msg = restore_vault_from_backup(self.username, self.encryption_key, backup_id)
        if ok:
            QMessageBox.information(self, "Success", msg)
            self.accept()
        else:
            QMessageBox.critical(self, "Restore Failed", msg)

class DashboardWindow(QWidget):
    logout_requested = pyqtSignal()

    def __init__(self, username, encryption_key, main_window=None):
        super().__init__()
        self.username = username
        self.encryption_key = encryption_key
        self.main_window = main_window
        self.set_dark_theme()

        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(4, 4, 4, 4)
        main_layout.setSpacing(0)

        sidebar = self.build_sidebar()

        self.content_stack = QStackedLayout()
        content_wrapper = QFrame()
        content_wrapper.setStyleSheet("background-color: #2b2b3d; color: white; border-radius: 12px;")
        content_wrapper.setLayout(self.content_stack)
        content_wrapper.setContentsMargins(8, 8, 8, 8)

        main_layout.addWidget(sidebar)
        main_layout.addSpacing(8)
        main_layout.addWidget(content_wrapper)

        self.setLayout(main_layout)
        self.switch_section(self.build_dashboard)

    def set_dark_theme(self):
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(30, 30, 47))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(43, 43, 61))
        dark_palette.setColor(QPalette.AlternateBase, QColor(66, 66, 84))
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(30, 30, 47))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        self.setPalette(dark_palette)

    def build_sidebar(self):
        sidebar = QFrame()
        sidebar.setFixedWidth(200)
        sidebar.setStyleSheet("""
            QFrame {
                background-color: #181828;
                border-radius: 12px;
            }
        """)
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 24, 0, 24)
        layout.setSpacing(12)
        sidebar.setLayout(layout)

        nav_items = {
            "Dashboard": self.build_dashboard,
            "Password Management": self.build_passwords,
            "Settings": self.build_settings,
            "Logout": self.logout
        }

        for label, builder in nav_items.items():
            btn = QPushButton(label)
            if label == "Logout":
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #636e72;
                        color: #fff;
                        border: none;
                        border-radius: 8px;
                        padding: 12px 0;
                        font-size: 15px;
                        text-align: center;
                    }
                    QPushButton:hover {
                        background-color: #81ecec;
                        color: #181828;
                    }
                """)
            else:
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #181828;
                        color: #fff;
                        border: none;
                        border-radius: 8px;
                        padding: 12px 0;
                        font-size: 15px;
                        text-align: center;
                    }
                    QPushButton:hover {
                        background-color: #23233a;
                        color: #1ec1a2;
                    }
                    QPushButton:checked {
                        background-color: #1ec1a2;
                        color: #181828;
                    }
                """)
            btn.setFont(QFont("Arial", 13, QFont.Bold))
            btn.setCursor(Qt.PointingHandCursor)
            if label == "Logout":
                btn.clicked.connect(self.logout)
            else:
                btn.clicked.connect(lambda _, b=builder: self.switch_section(b))
            layout.addWidget(btn, alignment=Qt.AlignHCenter)

        layout.addStretch()
        return sidebar

    def switch_section(self, builder_func):
        while self.content_stack.count():
            widget = self.content_stack.widget(0)
            self.content_stack.removeWidget(widget)
            widget.setParent(None)
        self.content_stack.addWidget(builder_func())

    def build_dashboard(self):
        from vault_ui import evaluate_password_strength

        frame = QFrame()
        layout = QVBoxLayout(frame)
        layout.setAlignment(Qt.AlignTop)
        layout.setSpacing(10)
        layout.setContentsMargins(8, 8, 8, 8)

        title = QLabel("Security Dashboard")
        title.setFont(QFont("Arial", 28, QFont.Bold))
        title.setStyleSheet("margin-bottom: 4px;")
        title.setAlignment(Qt.AlignLeft)
        subtitle = QLabel(f"Welcome back, {self.username}")
        subtitle.setFont(QFont("Arial", 18))
        subtitle.setStyleSheet("margin-bottom: 12px;")
        subtitle.setAlignment(Qt.AlignLeft)
        layout.addWidget(title)
        layout.addWidget(subtitle)

        # --- Top Row: Security Score, Password Health, Encryption Status ---
        top_row = QHBoxLayout()
        top_row.setSpacing(16)

        # Security Score
        score_frame = QFrame()
        score_layout = QVBoxLayout(score_frame)
        score_label = QLabel("Security Score")
        score_label.setFont(QFont("Arial", 14, QFont.Bold))
        score_label.setAlignment(Qt.AlignCenter)
        score = self.calculate_security_score()
        score_bar = QProgressBar()
        score_bar.setValue(score)
        score_bar.setAlignment(Qt.AlignCenter)
        score_bar.setFormat(f"{score} %")
        score_bar.setStyleSheet("QProgressBar {font-size: 18px; border-radius: 8px;} QProgressBar::chunk {background-color: #1ec1a2;}")
        score_layout.addWidget(score_label)
        score_layout.addWidget(score_bar)
        top_row.addWidget(score_frame)

        # Password Health
        health_frame = QFrame()
        health_layout = QVBoxLayout(health_frame)
        health_label = QLabel("Password Health")
        health_label.setFont(QFont("Arial", 14, QFont.Bold))
        health_layout.addWidget(health_label)
        strong, medium, weak = self.count_password_strengths()
        health_layout.addWidget(QLabel(f"<span style='color:#1ec1a2;'>Strong</span>: {strong}%"))
        health_layout.addWidget(QLabel(f"<span style='color:#ffd600;'>Medium</span>: {medium}%"))
        health_layout.addWidget(QLabel(f"<span style='color:#ff4d4f;'>Weak</span>: {weak}%"))
        top_row.addWidget(health_frame)

        # Encryption Status
        enc_frame = QFrame()
        enc_layout = QVBoxLayout(enc_frame)
        enc_label = QLabel("Encryption Status")
        enc_label.setFont(QFont("Arial", 14, QFont.Bold))
        enc_layout.addWidget(enc_label)
        enc_layout.addWidget(QLabel("Algorithm: <b>AES-256</b>"))
        last_backup = self.get_last_backup_time()
        enc_layout.addWidget(QLabel(f"Last Backup: <span style='color:#1ec1a2;'>{last_backup}</span>"))
        sync_status = "Active" if last_backup != "Never" else "Not Synced"
        enc_layout.addWidget(QLabel(f"Sync Status: <span style='color:#1ec1a2;'>{sync_status}</span>"))
        top_row.addWidget(enc_frame)

        layout.addLayout(top_row)

        # --- Recent Activity ---
        activity_label = QLabel("Recent Activity")
        activity_label.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(activity_label)
        activity_list = QListWidget()
        for desc, time in self.get_recent_activity():
            activity_list.addItem(QListWidgetItem(f"{desc} - {time}"))
        activity_list.setStyleSheet("background-color: #23233a; color: white; font-size: 14px; border-radius: 8px;")
        activity_list.setMaximumHeight(60)
        layout.addWidget(activity_list)

        # --- Alerts (Weak Passwords, Password Age) ---
        alerts_row = QHBoxLayout()
        alerts_row.setSpacing(12)

        weak_pw_frame = QFrame()
        weak_pw_frame.setStyleSheet("background-color: #2b1e1e; border-radius: 8px;")
        weak_pw_layout = QVBoxLayout(weak_pw_frame)
        weak_pw_label = QLabel("⚠️ Weak Passwords")
        weak_pw_label.setStyleSheet("color: #ff4d4f; font-weight: bold;")
        weak_pw_layout.addWidget(weak_pw_label)
        weak_count = self.get_weak_password_count()
        weak_pw_layout.addWidget(QLabel(f"{weak_count} password{'s' if weak_count != 1 else ''} need attention"))
        review_btn = QPushButton("Review Now")
        review_btn.setStyleSheet("background-color: #ff4d4f; color: white; border-radius: 6px;")
        weak_pw_layout.addWidget(review_btn)
        alerts_row.addWidget(weak_pw_frame)

        age_pw_frame = QFrame()
        age_pw_frame.setStyleSheet("background-color: #2b241e; border-radius: 8px;")
        age_pw_layout = QVBoxLayout(age_pw_frame)
        age_pw_label = QLabel("⏰ Password Age")
        age_pw_label.setStyleSheet("color: #ffd600; font-weight: bold;")
        age_pw_layout.addWidget(age_pw_label)
        old_count = self.get_old_password_count()
        age_pw_layout.addWidget(QLabel(f"{old_count} password{'s' if old_count != 1 else ''} are over 90 days old"))
        update_btn = QPushButton("Update Now")
        update_btn.setStyleSheet("background-color: #ffd600; color: black; border-radius: 6px;")
        age_pw_layout.addWidget(update_btn)
        alerts_row.addWidget(age_pw_frame)

        layout.addLayout(alerts_row)

        # --- Password Table ---
        table_label = QLabel("Your Passwords")
        table_label.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(table_label)

        passwords = retrieve_passwords(self.username, self.encryption_key)
        table = QTableWidget(len(passwords), 2)
        table.setHorizontalHeaderLabels(["Service", "Strength"])
        table.setStyleSheet("""
            QTableWidget {
                font-size: 16px;
                background-color: #23233a;
                color: white;
                border-radius: 8px;
            }
            QHeaderView::section {
                font-size: 16px;
                background-color: #23233a;
                color: #b0b0b0;
                padding: 6px;
            }
        """)
        table.horizontalHeader().setStretchLastSection(True)
        table.setColumnWidth(0, 220)
        table.setColumnWidth(1, 120)
        table.setMinimumHeight(120)
        table.setShowGrid(False)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setSelectionMode(QTableWidget.NoSelection)

        for row, (service, password, last_updated) in enumerate(passwords):
            service_item = QTableWidgetItem(service)
            service_item.setFont(QFont("Arial", 14))
            table.setItem(row, 0, service_item)
            strength, color = evaluate_password_strength(password)
            strength_item = QTableWidgetItem(strength)
            strength_item.setFont(QFont("Arial", 14, QFont.Bold))
            strength_item.setForeground(QColor(color))
            table.setItem(row, 1, strength_item)
        layout.addWidget(table)

        return frame

    def calculate_security_score(self):
        passwords = retrieve_passwords(self.username, self.encryption_key)
        if not passwords:
            return 0
        from vault_ui import evaluate_password_strength
        strong = medium = weak = 0
        for _, pw, _ in passwords:
            strength, _ = evaluate_password_strength(pw)
            if strength == "Strong":
                strong += 1
            elif strength == "Medium":
                medium += 1
            else:
                weak += 1
        total = strong + medium + weak
        score = int((strong * 1.0 + medium * 0.5) / total * 100)
        return score

    def count_password_strengths(self):
        passwords = retrieve_passwords(self.username, self.encryption_key)
        if not passwords:
            return (0, 0, 0)
        from vault_ui import evaluate_password_strength
        strong = medium = weak = 0
        for _, pw, _ in passwords:
            strength, _ = evaluate_password_strength(pw)
            if strength == "Strong":
                strong += 1
            elif strength == "Medium":
                medium += 1
            else:
                weak += 1
        total = strong + medium + weak
        if total == 0:
            return (0, 0, 0)
        return (
            int(strong / total * 100),
            int(medium / total * 100),
            int(weak / total * 100)
        )
    
    def get_weak_password_count(self):
        passwords = retrieve_passwords(self.username, self.encryption_key)
        from vault_ui import evaluate_password_strength
        return sum(1 for _, pw, _ in passwords if evaluate_password_strength(pw)[0] == "Weak")

    def get_old_password_count(self, days=90):
        try:
            with sqlite3.connect('vaultsecure.db') as conn:
                c = conn.cursor()
                c.execute("SELECT id FROM users WHERE username = ?", (self.username,))
                user_id = c.fetchone()
                if not user_id:
                    return 0
                user_id = user_id[0]
                c.execute("SELECT last_updated FROM vault WHERE user_id = ?", (user_id,))
                rows = c.fetchall()
                from datetime import datetime, timedelta
                cutoff = datetime.now() - timedelta(days=days)
                old_count = 0
                for (last_updated,) in rows:
                    if last_updated and datetime.fromisoformat(last_updated) < cutoff:
                        old_count += 1
                return old_count
        except Exception:
            return 0

    def get_recent_activity(self, limit=5):
        activity = []
        for service, action, timestamp in get_recent_activity_log(self.username, limit):
            if action == "created":
                msg = f"New service entry for {service}"
            elif action == "updated":
                msg = f"Password changed for {service}"
            elif action == "deleted":
                msg = f"service entry {service} and its password entry deleted"
            elif action == "restored":
                msg = "Vault restored from backup"
            else:
                msg = f"{action.title()} for {service}"
            time_str = self.format_datetime_user_tz(timestamp)
            activity.append((msg, time_str))
        return activity

    def get_last_backup_time(self):
        raw = get_last_backup_time_raw(self.username)
        if raw:
            return self.format_datetime_user_tz(raw)
        return "Never"
    
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
        
    def build_passwords(self):
        return VaultManager(self.username, self.encryption_key)
    
    def build_settings(self):
        from vaultsecure_backend import change_master_password, authenticate_user

        frame = QFrame()
        frame.setStyleSheet("background-color: #23233a; border-radius: 16px;")
        layout = QVBoxLayout(frame)
        layout.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(32)

        # --- Centered Title & Subtitle ---
        header_widget = QWidget()
        header_layout = QVBoxLayout(header_widget)
        header_layout.setAlignment(Qt.AlignHCenter)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(0)

        title = QLabel("Settings & User Management")
        title.setFont(QFont("Arial", 28, QFont.Bold))
        title.setStyleSheet("color: white; margin-bottom: 8px;")
        title.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(title)

        layout.addWidget(header_widget, alignment=Qt.AlignHCenter)

        # --- Timezone Section ---
        tz_card = QFrame()
        tz_card.setStyleSheet("background-color: #292940; border-radius: 12px;")
        tz_card.setFixedWidth(600)
        tz_layout = QVBoxLayout(tz_card)
        tz_layout.setContentsMargins(32, 24, 32, 24)
        tz_layout.setSpacing(12)

        tz_title = QLabel("Timezone")
        tz_title.setFont(QFont("Arial", 16, QFont.Bold))
        tz_title.setStyleSheet("color: #fff; margin-bottom: 8px;")
        tz_layout.addWidget(tz_title, alignment=Qt.AlignLeft)

        tz_row = QHBoxLayout()
        timezone_label = QLabel("Display Timezone:")
        timezone_label.setFont(QFont("Arial", 14))
        timezone_combo = QComboBox()
        timezone_combo.setFixedWidth(250)
        timezone_combo.setStyleSheet("padding: 8px; border-radius: 6px; background-color: #181828; color: white;")
        timezone_map = {
            "Pacific (PST)": "America/Los_Angeles",
            "Central (CST)": "America/Chicago",
            "Eastern (EST)": "America/New_York"
        }
        timezone_combo.addItems(list(timezone_map.keys()))

        # Load user's current timezone via the backend to avoid bypassing
        # shared DB access logic and test patching.
        current_timezone = get_user_timezone(self.username)
        if current_timezone:
            for display, value in timezone_map.items():
                if value == current_timezone:
                    idx = timezone_combo.findText(display)
                    if idx >= 0:
                        timezone_combo.setCurrentIndex(idx)
                    break

        save_btn = QPushButton("Save Timezone")
        save_btn.setStyleSheet("background-color: #1ec1a2; color: white; border-radius: 6px; padding: 8px 16px;")
        tz_row.addWidget(timezone_label)
        tz_row.addWidget(timezone_combo)
        tz_row.addWidget(save_btn)
        tz_row.addStretch()
        tz_layout.addLayout(tz_row)
        layout.addWidget(tz_card)

        def save_timezone():
            display = timezone_combo.currentText()
            tz = timezone_map[display]
            conn = sqlite3.connect('vaultsecure.db')
            c = conn.cursor()
            c.execute("UPDATE users SET timezone = ? WHERE username = ?", (tz, self.username))
            conn.commit()
            conn.close()
            QMessageBox.information(self, "Timezone Updated", f"Timezone set to {display}.")

        save_btn.clicked.connect(save_timezone)

        # --- Password Section ---
        pw_card = QFrame()
        pw_card.setStyleSheet("background-color: #292940; border-radius: 12px;")
        pw_card.setFixedWidth(600)
        pw_layout = QVBoxLayout(pw_card)
        pw_layout.setContentsMargins(32, 24, 32, 24)
        pw_layout.setSpacing(12)

        pw_title = QLabel("Change Master Password")
        pw_title.setFont(QFont("Arial", 16, QFont.Bold))
        pw_title.setStyleSheet("color: #fff; margin-bottom: 8px;")
        pw_layout.addWidget(pw_title, alignment=Qt.AlignLeft)

        pw_form = QFormLayout()
        pw_form.setLabelAlignment(Qt.AlignRight)
        pw_form.setFormAlignment(Qt.AlignLeft)
        old_pw = QLineEdit()
        old_pw.setEchoMode(QLineEdit.Password)
        old_pw.setFont(QFont("Arial", 16))
        old_pw.setStyleSheet("padding: 12px; border-radius: 8px; background-color: #181828; color: white;")
        old_pw.setPlaceholderText("Current Password")
        new_pw = QLineEdit()
        new_pw.setEchoMode(QLineEdit.Password)
        new_pw.setFont(QFont("Arial", 16))
        new_pw.setStyleSheet("padding: 12px; border-radius: 8px; background-color: #181828; color: white;")
        new_pw.setPlaceholderText("At least 12 chars, strong")
        pw_form.addRow("Current Password:", old_pw)
        pw_form.addRow("New Password:", new_pw)
        pw_layout.addLayout(pw_form)

        pw_btn = QPushButton("Change Master Password")
        pw_btn.setFont(QFont("Arial", 16, QFont.Bold))
        pw_btn.setStyleSheet("background-color: #1ec1a2; color: white; border-radius: 8px; padding: 12px; min-width: 300px;")
        pw_layout.addWidget(pw_btn, alignment=Qt.AlignHCenter)
        layout.addWidget(pw_card)

        def handle_pw_change():
            old = old_pw.text()
            new = new_pw.text()
            if not old or not new:
                QMessageBox.warning(self, "Input Error", "Please fill both fields.")
                return
            auth_ok, _ = authenticate_user(self.username, old)
            if not auth_ok:
                QMessageBox.critical(self, "Auth Failed", "Current password incorrect.")
                return
            result, msg = change_master_password(self.username, old, new)
            if result:
                # Update the encryption key
                self.encryption_key = new
                
                # Clear any cached vault managers
                if hasattr(self, 'vault_manager'):
                    del self.vault_manager
                
                QMessageBox.information(self, "Success", "Password changed and vault re-encrypted.\nAll sections will refresh with the new key.")
                old_pw.clear()
                new_pw.clear()
                
                # Force refresh to dashboard
                self.switch_section(self.build_dashboard)
            else:
                QMessageBox.critical(self, "Error", msg)

        pw_btn.clicked.connect(handle_pw_change)

        # --- Restore Section ---
        restore_card = QFrame()
        restore_card.setStyleSheet("background-color: #292940; border-radius: 12px;")
        restore_card.setFixedWidth(600)
        restore_layout = QVBoxLayout(restore_card)
        restore_layout.setContentsMargins(32, 24, 32, 24)
        restore_layout.setSpacing(12)

        restore_title = QLabel("Backup & Restore")
        restore_title.setFont(QFont("Arial", 16, QFont.Bold))
        restore_title.setStyleSheet("color: #fff; margin-bottom: 8px;")
        restore_layout.addWidget(restore_title, alignment=Qt.AlignLeft)

        restore_btn = QPushButton("Restore from Backup")
        restore_btn.setFont(QFont("Arial", 16, QFont.Bold))
        restore_btn.setStyleSheet("background-color: #ff4d4f; color: white; border-radius: 8px; padding: 12px; min-width: 300px;")
        restore_btn.clicked.connect(self.open_restore_dialog)
        restore_layout.addWidget(restore_btn, alignment=Qt.AlignHCenter)
        layout.addWidget(restore_card)

        layout.addStretch()
        return frame
    
    def open_restore_dialog(self):
        dlg = RestoreBackupDialog(self.username, self.encryption_key, self)
        dlg.exec_()

    def logout(self):
        try:
            # Clear sensitive data from memory
            if hasattr(self, 'encryption_key'):
                # Overwrite encryption key with zeros before deletion
                if self.encryption_key:
                    self.encryption_key = '0' * len(self.encryption_key)
                self.encryption_key = None
            
            # Clear any cached password data
            if hasattr(self, 'cached_passwords'):
                self.cached_passwords = None
            
            # Clear system clipboard if it might contain sensitive data
            from PyQt5.QtWidgets import QApplication
            clipboard = QApplication.clipboard()
            clipboard.clear()
            
            # Emit logout signal to main window (this will clear login fields)
            self.logout_requested.emit()
            
            # Close the dashboard window
            self.close()
            
        except Exception as e:
            # Ensure logout happens even if cleanup fails
            print(f"Warning: Logout cleanup error: {e}")
            self.logout_requested.emit()
            self.close()