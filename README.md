# System Process Monitor with Anomaly Detection
## 📜 Overview
This project is a **System Process Monitor** that utilizes advanced machine learning techniques to detect anomalies in real-time. Designed for cross-platform compatibility, it provides detailed process monitoring, anomaly detection, and customizable reporting features, making it suitable for cybersecurity and systems management applications.

## 🛠️ Features
- **Real-Time Process Monitoring**:
  - Collects and displays metrics such as CPU usage, memory usage, thread count, and more.
- **Anomaly Detection**:
  - Employs the **Isolation Forest** algorithm to identify suspicious processes based on behavior patterns.
- **Customizable Reports**:
  - Automatically generates detailed JSON reports for detected anomalies.
- **Interactive UI**:
  - A user-friendly interface built with PyQt5 for visualizing system metrics and anomalies.

## 🔧 Technical Details
- **Languages**: Python, C++
- **Libraries Used**:
  - `psutil`: For system process and resource monitoring.
  - `sklearn`: For implementing the Isolation Forest anomaly detection algorithm.
  - `PyQt5`: For building an interactive desktop application.
- **Platforms**: Supports macOS (for now)

## 🚀 How to run the project?
### Pre-requisites
- Python 3.7+
- Required Python libraries: `psutil`, `scikit-learn`, `PyQt5`, `numpy`
Install dependencies using : `pip install -r requirements.txt`

### Steps to run the project
1. Clone the repository
   ```bash
   git clone https://github.com/umadhatri/System-Monitor.git
   cd system-process-monitor
   ```
   
2. Start the UI application:
   ```bash
   python process_monitor_ui.py
   ```
   
3. Monitor processes and detect anomalies in real time!

## 🎥 Demo
Check out the video demonstration [here](https://youtu.be/Le7XCnft8mk) showcasing the real-time anomaly detection capabilities of the program!

## 📊 JSON Output of the system
Please check the JSON file in the repository to see how the detected anomalies are stored in a JSON file

## 🔒 Applications
- Cybersecurity: Detect malware-like behavior (e.g., excessive resource usage or unusual network activity)
- System Administration: Monitor system performance and identify rogue processes
- Research: Analyze real-world process behavior patterns for anomaly prediction

## 🤝🏻 Contributions
Contributions are welcome! Feel free to open issues or submit pull requests to enhance the project.

## 📝 License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## 📬 Contact
Please feel free to contact me at [umasatyanarayana35@gmail.com](mailto:umasatyanarayana35@gmail.com) for more queries and questions
