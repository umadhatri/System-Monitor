import sys
import time
import psutil
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QTableWidget, QTableWidgetItem, QPushButton, QLabel,
                            QHeaderView, QHBoxLayout, QMessageBox)
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QColor
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from advanced_anomaly_detector import AdvancedAnomalyDetector
import json

class ProcessMonitorUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("System Process Monitor - macOS")
        self.setGeometry(100, 100, 1200, 800)
        
        # Initialize anomaly detector
        self.anomaly_detector = AdvancedAnomalyDetector()
        
        # Define suspicious process names (customized for macOS environment)
        self.suspicious_patterns = [
            "netcat", "wireshark", "nmap", "john", "hashcat", "hydra",
            "tcpdump", "aircrack", "ettercap", "burpsuite"
        ]
        
        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Add header with system info
        header_layout = QHBoxLayout()
        self.system_info_label = QLabel()
        self.system_info_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        header_layout.addWidget(self.system_info_label)
        layout.addLayout(header_layout)
        
        # Create process table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(7)
        self.process_table.setHorizontalHeaderLabels([
            "PID", "Name", "Username", "CPU %", "Memory (MB)", "Status", "Created"
        ])
        
        # Set table properties
        self.process_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.process_table.setAlternatingRowColors(True)
        self.process_table.setSortingEnabled(True)
        self.process_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #d3d3d3;
                background-color: white;
                alternate-background-color: #f6f6f6;
            }
            QHeaderView::section {
                background-color: #f0f0f0;
                padding: 4px;
                border: 1px solid #d3d3d3;
                font-weight: bold;
            }
        """)
        
        # Create matplotlib figure for CPU usage graph
        plt.style.use('seaborn-v0_8')
        self.figure, (self.cpu_ax, self.mem_ax) = plt.subplots(2, 1, figsize=(8, 6))
        self.canvas = FigureCanvas(self.figure)
        
        # Control panel
        control_layout = QHBoxLayout()
        
        # Refresh button
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.update_data)
        self.refresh_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 5px 15px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        
        # Auto refresh button
        self.auto_refresh_button = QPushButton("Auto Refresh")
        self.auto_refresh_button.setCheckable(True)
        self.auto_refresh_button.toggled.connect(self.toggle_auto_refresh)
        self.auto_refresh_button.setStyleSheet("""
            QPushButton {
                background-color: #008CBA;
                color: white;
                padding: 5px 15px;
                border-radius: 4px;
            }
            QPushButton:checked {
                background-color: #007B9A;
            }
        """)
        
        # Anomaly detection button
        self.detect_anomalies_button = QPushButton("Detect Anomalies")
        self.detect_anomalies_button.clicked.connect(self.check_anomalies)
        self.detect_anomalies_button.setStyleSheet("""
            QPushButton {
                background-color: #FF5722;
                color: white;
                padding: 5px 15px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #F4511E;
            }
        """)
        
        # Add buttons to control layout
        control_layout.addWidget(self.refresh_button)
        control_layout.addWidget(self.auto_refresh_button)
        control_layout.addWidget(self.detect_anomalies_button)
        
        # Add widgets to layout
        layout.addLayout(control_layout)
        layout.addWidget(QLabel("<b>Running Processes</b>"))
        layout.addWidget(self.process_table)
        layout.addWidget(QLabel("<b>System Resource Usage</b>"))
        layout.addWidget(self.canvas)
        
        # Add status label
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #666; font-style: italic;")
        layout.addWidget(self.status_label)
        
        # Initialize data storage for graphs
        self.cpu_history = []
        self.mem_history = []
        self.time_points = []
        self.start_time = time.time()
        
        # Set up timer for automatic updates
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_data)
        
        # Initial update
        self.update_data()

    def check_anomalies(self):
        try:
            # Update anomaly detector history
            self.anomaly_detector.update_history()
            
            # Train model if needed
            if not self.anomaly_detector.is_trained:
                self.status_label.setText("Training anomaly detection model...")
                self.status_label.setStyleSheet("color: #2196F3;")
                if not self.anomaly_detector.train_model():
                    self.status_label.setText("Need more data to train model")
                    return
            
            # Get current process metrics
            current_metrics = self.anomaly_detector.collect_process_metrics()
            
            # Detect anomalies
            anomalies = self.anomaly_detector.detect_anomalies(current_metrics)
            
            # Generate report
            report = self.anomaly_detector.generate_report(anomalies)
            
            # Save report
            report_file = f'anomaly_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            # Update UI
            self.status_label.setText(
                f"Found {len(anomalies)} anomalous processes. Report saved to {report_file}"
            )
            self.status_label.setStyleSheet("color: #4CAF50;")
            
            # Highlight anomalous processes in the table
            self.highlight_anomalies(anomalies)
            
        except Exception as e:
            self.status_label.setText(f"Error detecting anomalies: {str(e)}")
            self.status_label.setStyleSheet("color: #F44336;")

    def highlight_anomalies(self, anomalies):
        anomaly_pids = {proc['pid'] for proc in anomalies}
        
        for row in range(self.process_table.rowCount()):
            pid_item = self.process_table.item(row, 0)  # Assuming PID is in first column
            if pid_item and int(pid_item.text()) in anomaly_pids:
                for col in range(self.process_table.columnCount()):
                    item = self.process_table.item(row, col)
                    if item:
                        item.setBackground(QColor(255, 87, 34, 100))  # Semi-transparent red
    
    def toggle_auto_refresh(self, checked):
        if checked:
            self.timer.start(2000)  # Update every 2 seconds
            self.refresh_button.setEnabled(False)
        else:
            self.timer.stop()
            self.refresh_button.setEnabled(True)
    
    def is_suspicious(self, name, cmdline):
        name = name.lower()
        if cmdline:
            cmdline = ' '.join(cmdline).lower()
        else:
            cmdline = ''
            
        return any(pattern in name or pattern in cmdline for pattern in self.suspicious_patterns)
    
    def update_data(self):
        try:
            # Update system info
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            self.system_info_label.setText(
                f"CPU Usage: {cpu_percent}% | "
                f"Memory: {memory.used/1024/1024/1024:.1f}GB used of {memory.total/1024/1024/1024:.1f}GB | "
                f"Memory Percent: {memory.percent}%"
            )
            
            # Update process table
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 
                                          'memory_percent', 'status', 'create_time', 'cmdline']):
                try:
                    pinfo = proc.info
                    created = datetime.fromtimestamp(pinfo['create_time']).strftime('%Y-%m-%d %H:%M:%S')
                    memory_mb = proc.memory_info().rss / 1024 / 1024  # Convert to MB
                    
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'username': pinfo['username'],
                        'cpu': pinfo['cpu_percent'],
                        'memory': memory_mb,
                        'status': pinfo['status'],
                        'created': created,
                        'suspicious': self.is_suspicious(pinfo['name'], pinfo.get('cmdline', []))
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            self.update_process_table(processes)
            self.update_resource_graphs(cpu_percent, memory.percent)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error updating data: {str(e)}")
    
    def update_process_table(self, processes):
        self.process_table.setSortingEnabled(False)
        self.process_table.setRowCount(len(processes))
        
        for row, process in enumerate(processes):
            items = [
                QTableWidgetItem(str(process['pid'])),
                QTableWidgetItem(process['name']),
                QTableWidgetItem(process['username']),
                QTableWidgetItem(f"{process['cpu']:.1f}"),
                QTableWidgetItem(f"{process['memory']:.1f}"),
                QTableWidgetItem(process['status']),
                QTableWidgetItem(process['created'])
            ]
            
            # Set items as non-editable
            for item in items:
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            
            # Apply color if process is suspicious
            if process['suspicious']:
                for item in items:
                    item.setBackground(QColor(255, 200, 200))
            
            # Add items to row
            for col, item in enumerate(items):
                self.process_table.setItem(row, col, item)
        
        self.process_table.setSortingEnabled(True)
    
    def update_resource_graphs(self, cpu_percent, mem_percent):
        current_time = time.time() - self.start_time
        
        self.time_points.append(current_time)
        self.cpu_history.append(cpu_percent)
        self.mem_history.append(mem_percent)
        
        # Keep only last 50 data points
        if len(self.time_points) > 50:
            self.time_points.pop(0)
            self.cpu_history.pop(0)
            self.mem_history.pop(0)
        
        # Update CPU graph
        self.cpu_ax.clear()
        self.cpu_ax.plot(self.time_points, self.cpu_history, 'b-', label='CPU Usage')
        self.cpu_ax.set_ylabel('CPU Usage (%)')
        self.cpu_ax.set_title('CPU Usage Over Time')
        self.cpu_ax.grid(True)
        self.cpu_ax.legend()
        
        # Update Memory graph
        self.mem_ax.clear()
        self.mem_ax.plot(self.time_points, self.mem_history, 'r-', label='Memory Usage')
        self.mem_ax.set_xlabel('Time (s)')
        self.mem_ax.set_ylabel('Memory Usage (%)')
        self.mem_ax.set_title('Memory Usage Over Time')
        self.mem_ax.grid(True)
        self.mem_ax.legend()
        
        self.figure.tight_layout()
        self.canvas.draw()

def check_anomalies(self):
    try:
        # Update anomaly detector history
        self.anomaly_detector.update_history()
        
        # Train model if needed
        if not self.anomaly_detector.is_trained:
            self.status_label.setText("Training anomaly detection model...")
            self.status_label.setStyleSheet("color: #2196F3;")
            if not self.anomaly_detector.train_model():
                self.status_label.setText("Need more data to train model")
                return
        
        # Get current process metrics
        current_metrics = self.anomaly_detector.collect_process_metrics()
        
        # Detect anomalies
        anomalies = self.anomaly_detector.detect_anomalies(current_metrics)
        
        # Generate report
        report = self.anomaly_detector.generate_report(anomalies)
        
        # Save report
        report_file = f'anomaly_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Update UI
        self.status_label.setText(
            f"Found {len(anomalies)} anomalous processes. Report saved to {report_file}"
        )
        self.status_label.setStyleSheet("color: #4CAF50;")
        
        # Highlight anomalous processes in the table
        self.highlight_anomalies(anomalies)
        
    except Exception as e:
        self.status_label.setText(f"Error detecting anomalies: {str(e)}")
        self.status_label.setStyleSheet("color: #F44336;")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    # Set fusion style for better macOS appearance
    app.setStyle('Fusion')
    
    window = ProcessMonitorUI()
    window.show()
    sys.exit(app.exec_())