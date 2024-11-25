import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import psutil
import pandas as pd
from collections import deque
import logging
from datetime import datetime

class AdvancedAnomalyDetector:
    def __init__(self, history_size=100):
        self.history_size = history_size
        self.process_history = deque(maxlen=history_size)
        self.scaler = StandardScaler()
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.is_trained = False
        
        # Initialize logging
        logging.basicConfig(
            filename=f'process_monitor_{datetime.now().strftime("%Y%m%d")}.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def collect_process_metrics(self):
        """Collect detailed metrics for all running processes"""
        process_metrics = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 
                                       'num_threads', 'num_fds', 'connections']):
            try:
                # Get process info
                pinfo = proc.info
                
                # Get network connections count
                try:
                    num_connections = len(proc.connections())
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    num_connections = 0
                
                # Get number of open files
                try:
                    num_files = len(proc.open_files())
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    num_files = 0
                
                metrics = {
                    'pid': pinfo['pid'],
                    'name': pinfo['name'],
                    'cpu_percent': pinfo['cpu_percent'] or 0,
                    'memory_percent': pinfo['memory_percent'] or 0,
                    'num_threads': pinfo['num_threads'] or 0,
                    'num_fds': pinfo['num_fds'] or 0,
                    'num_connections': num_connections,
                    'num_files': num_files
                }
                
                process_metrics.append(metrics)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                logging.warning(f"Error collecting metrics for process: {e}")
                continue
        
        return process_metrics
    
    def update_history(self):
        """Update process history with current metrics"""
        current_metrics = self.collect_process_metrics()
        self.process_history.append(current_metrics)
        logging.info(f"Updated process history. Current size: {len(self.process_history)}")
    
    def prepare_training_data(self):
        """Prepare data for anomaly detection model"""
        if not self.process_history:
            return None
        
        # Aggregate metrics per process
        all_data = []
        for metrics in self.process_history:
            for proc in metrics:
                feature_vector = [
                    proc['cpu_percent'],
                    proc['memory_percent'],
                    proc['num_threads'],
                    proc['num_connections'],
                    proc['num_files']
                ]
                all_data.append(feature_vector)
        
        return np.array(all_data)
    
    def train_model(self):
        """Train the anomaly detection model"""
        data = self.prepare_training_data()
        if data is None or len(data) < self.history_size:
            logging.warning("Insufficient data for training")
            return False
        
        try:
            # Scale the data
            scaled_data = self.scaler.fit_transform(data)
            
            # Train the model
            self.model.fit(scaled_data)
            self.is_trained = True
            logging.info("Successfully trained anomaly detection model")
            return True
            
        except Exception as e:
            logging.error(f"Error training model: {e}")
            return False
    
    def detect_anomalies(self, processes):
        """Detect anomalies in current processes"""
        if not self.is_trained:
            logging.warning("Model not trained yet")
            return []
        
        try:
            # Prepare current process data
            current_data = []
            for proc in processes:
                feature_vector = [
                    proc['cpu_percent'],
                    proc['memory_percent'],
                    proc['num_threads'],
                    proc['num_connections'],
                    proc['num_files']
                ]
                current_data.append(feature_vector)
            
            # Scale and predict
            scaled_data = self.scaler.transform(current_data)
            predictions = self.model.predict(scaled_data)
            
            # Find anomalous processes (where prediction == -1)
            anomalies = []
            for i, pred in enumerate(predictions):
                if pred == -1:
                    processes[i]['anomaly_reason'] = self.get_anomaly_reason(processes[i])
                    anomalies.append(processes[i])
            
            logging.info(f"Detected {len(anomalies)} anomalous processes")
            return anomalies
            
        except Exception as e:
            logging.error(f"Error detecting anomalies: {e}")
            return []
    
    def get_anomaly_reason(self, process):
        """Determine the reason for anomaly"""
        reasons = []
        
        if process['cpu_percent'] > 80:
            reasons.append("High CPU usage")
        if process['memory_percent'] > 80:
            reasons.append("High memory usage")
        if process['num_connections'] > 50:
            reasons.append("Unusual network activity")
        if process['num_threads'] > 100:
            reasons.append("High thread count")
        if process['num_files'] > 100:
            reasons.append("Many open files")
        
        return ", ".join(reasons) if reasons else "Unusual behavior pattern"
    
    def generate_report(self, anomalies):
        """Generate a detailed report of anomalies"""
        report = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_processes': len(self.process_history[-1]) if self.process_history else 0,
            'anomaly_count': len(anomalies),
            'anomalies': []
        }
        
        for proc in anomalies:
            report['anomalies'].append({
                'pid': proc['pid'],
                'name': proc['name'],
                'reason': proc['anomaly_reason'],
                'cpu_percent': proc['cpu_percent'],
                'memory_percent': proc['memory_percent'],
                'connections': proc['num_connections']
            })
        
        return report