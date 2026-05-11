from PyQt5.QtWidgets import QApplication
from main_window import MainWindow
from vaultsecure_backend import create_tables
import sys

if __name__ == "__main__":
    create_tables()
    app = QApplication(sys.argv)
    window = MainWindow()

    # Get available geometry (excludes dock and menu bar)
    screen = app.primaryScreen().availableGeometry()
    window.setGeometry(screen.left(), screen.top(), screen.width(), screen.height())

    window.show()
    sys.exit(app.exec_())