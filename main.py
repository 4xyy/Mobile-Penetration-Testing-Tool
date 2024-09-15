from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QLabel, QFileDialog
from src.static_analysis import analyze_apk, analyze_ipa
from src.dynamic_analysis import run_dynamic_analysis
from src.api_testing import test_api_endpoint
from src.report_generator import generate_report
from utils.decompiler import decompile_apk, decompile_ipa
from utils.network_monitor import start_network_monitoring

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mobile Penetration Testing Tool")
        self.setGeometry(100, 100, 600, 400)
        self.file_path = ""
        self.package_name = ""
        self.initUI()

    def initUI(self):
        # Button to upload APK/IPA file
        self.upload_btn = QPushButton('Upload APK/IPA', self)
        self.upload_btn.clicked.connect(self.upload_file)
        self.upload_btn.resize(200, 40)
        self.upload_btn.move(200, 50)

        # Button to run static analysis
        self.static_analysis_btn = QPushButton('Run Static Analysis', self)
        self.static_analysis_btn.clicked.connect(self.run_static_analysis)
        self.static_analysis_btn.resize(200, 40)
        self.static_analysis_btn.move(200, 100)

        # Button to run dynamic analysis
        self.dynamic_analysis_btn = QPushButton('Run Dynamic Analysis', self)
        self.dynamic_analysis_btn.clicked.connect(self.run_dynamic_analysis)
        self.dynamic_analysis_btn.resize(200, 40)
        self.dynamic_analysis_btn.move(200, 150)

        # Button to run API testing
        self.api_testing_btn = QPushButton('Run API Testing', self)
        self.api_testing_btn.clicked.connect(self.run_api_testing)
        self.api_testing_btn.resize(200, 40)
        self.api_testing_btn.move(200, 200)

    def upload_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select APK or IPA File", "", "All Files (*);;APK Files (*.apk);;IPA Files (*.ipa)", options=options)
        if file_path:
            self.file_path = file_path
            print(f"Selected file: {self.file_path}")

    def run_static_analysis(self):
        if self.file_path.endswith('.apk'):
            decompile_apk(self.file_path)
            analyze_apk(self.file_path)
        elif self.file_path.endswith('.ipa'):
            decompile_ipa(self.file_path)
            analyze_ipa(self.file_path)
        else:
            print("Unsupported file type for static analysis.")

    def run_dynamic_analysis(self):
        if not self.package_name:
            self.package_name = input("Enter the package name of the app: ").strip()
        if self.package_name:
            start_network_monitoring(self.package_name)
            run_dynamic_analysis(self.package_name)
        else:
            print("Please enter a valid package name.")

    def run_api_testing(self):
        api_url = input("Enter the API endpoint URL to test: ").strip()
        if api_url:
            test_api_endpoint(api_url)
            generate_report(['API Testing Completed'])  # Example report generation
        else:
            print("Please enter a valid API URL.")

if __name__ == "__main__":
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec_()

