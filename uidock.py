#!/usr/bin/env python3
import sys
import os
import json
import importlib.util
import inspect
import subprocess
import threading
import time
import traceback
import logging
import psutil
from datetime import datetime
from pathlib import Path
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QTabWidget, QLabel, 
                            QStackedWidget, QLineEdit, QTextEdit, QComboBox,
                            QListWidget, QListWidgetItem, QMessageBox, QFrame,
                            QScrollArea, QGridLayout, QSizePolicy, QGroupBox,
                            QCheckBox, QSlider, QProgressBar, QSplitter, QDialog,
                            QDialogButtonBox, QTreeWidget, QTreeWidgetItem, QHeaderView,
                            QInputDialog, QMenu, QAction, QFileDialog)
from PyQt5.QtCore import Qt, QSize, QTimer, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon, QFontDatabase, QTextCursor

# ========================================
# MANAGER
# ========================================
class EnhancedCyberThemeManager:
    """Manager with advanced customization"""
    
    def __init__(self):
        self.themes = {
            "cyber_dark": {
                "primary": "#0a0f1a",
                "secondary": "#1a1f2a", 
                "tertiary": "#2a2f3a",
                "accent": "#00ff88",
                "accent_secondary": "#00cc66",
                "text": "#e0e0e0",
                "text_secondary": "#a0a0a0",
                "border": "#334455",
                "border_light": "#445566",
                "border_dark": "#223344",
                "highlight": "#2a3344",
                "success": "#00ff88",
                "warning": "#ffaa00",
                "error": "#ff4444",
                "terminal": "#00ff88",
                "matrix": "#00ff44",
                "shadow": "rgba(0, 255, 136, 0.1)"
            },
            "matrix": {
                "primary": "#001100",
                "secondary": "#002200", 
                "tertiary": "#003300",
                "accent": "#00ff00",
                "accent_secondary": "#00cc00",
                "text": "#00ff00",
                "text_secondary": "#00aa00",
                "border": "#004400",
                "border_light": "#005500",
                "border_dark": "#001100",
                "highlight": "#003300",
                "success": "#00ff00",
                "warning": "#ffff00",
                "error": "#ff0000",
                "terminal": "#00ff00",
                "matrix": "#00ff00",
                "shadow": "rgba(0, 255, 0, 0.2)"
            },
            "midnight": {
                "primary": "#0a0a2a",
                "secondary": "#1a1a3a", 
                "tertiary": "#2a2a4a",
                "accent": "#0088ff",
                "accent_secondary": "#0066cc",
                "text": "#e0e0ff",
                "text_secondary": "#a0a0cc",
                "border": "#334466",
                "border_light": "#445577",
                "border_dark": "#223355",
                "highlight": "#2a2a66",
                "success": "#00ff88",
                "warning": "#ffaa00",
                "error": "#ff4444",
                "terminal": "#0088ff",
                "matrix": "#0088ff",
                "shadow": "rgba(0, 136, 255, 0.2)"
            },
            "stealth": {
                "primary": "#1a1a1a",
                "secondary": "#2a2a2a", 
                "tertiary": "#3a3a3a",
                "accent": "#ff4444",
                "accent_secondary": "#cc3333",
                "text": "#cccccc",
                "text_secondary": "#999999",
                "border": "#444444",
                "border_light": "#555555",
                "border_dark": "#333333",
                "highlight": "#3a2a2a",
                "success": "#00aa00",
                "warning": "#ffaa00",
                "error": "#ff4444",
                "terminal": "#ff4444",
                "matrix": "#ff4444",
                "shadow": "rgba(255, 68, 68, 0.2)"
            },
            "purple_haze": {
                "primary": "#1a0a2a",
                "secondary": "#2a1a3a", 
                "tertiary": "#3a2a4a",
                "accent": "#aa00ff",
                "accent_secondary": "#8800cc",
                "text": "#e0d0ff",
                "text_secondary": "#a090cc",
                "border": "#443366",
                "border_light": "#554477",
                "border_dark": "#332255",
                "highlight": "#3a2a55",
                "success": "#00ff88",
                "warning": "#ffaa00",
                "error": "#ff4444",
                "terminal": "#aa00ff",
                "matrix": "#aa00ff",
                "shadow": "rgba(170, 0, 255, 0.2)"
            },
            "amber_alert": {
                "primary": "#2a1a0a",
                "secondary": "#3a2a1a", 
                "tertiary": "#4a3a2a",
                "accent": "#ffaa00",
                "accent_secondary": "#cc8800",
                "text": "#ffeed0",
                "text_secondary": "#ccaa90",
                "border": "#665533",
                "border_light": "#776644",
                "border_dark": "#554422",
                "highlight": "#554422",
                "success": "#00ff88",
                "warning": "#ffaa00",
                "error": "#ff4444",
                "terminal": "#ffaa00",
                "matrix": "#ffaa00",
                "shadow": "rgba(255, 170, 0, 0.2)"
            }
        }
        
        self.current_theme = "cyber_dark"
        self.apply_theme(self.current_theme)
        
        self.custom_settings = {
            "border_radius": 6,
            "button_radius": 4,
            "shadow_intensity": 5,
            "animation_speed": 0
        }
        
    def apply_theme(self, theme_name):
        """Apply a theme"""
        if theme_name in self.themes:
            self.current_theme = theme_name
            theme = self.themes[theme_name]
            for key, value in theme.items():
                setattr(self, f"current_{key}", value)
            return True
        return False
    
    def get_css_variables(self):
        """Get CSS variables for styling"""
        return {
            'primary': self.current_primary,
            'secondary': self.current_secondary,
            'tertiary': self.current_tertiary,
            'accent': self.current_accent,
            'accent_secondary': self.current_accent_secondary,
            'text': self.current_text,
            'text_secondary': self.current_text_secondary,
            'border': self.current_border,
            'border_light': self.current_border_light,
            'border_dark': self.current_border_dark,
            'highlight': self.current_highlight,
            'success': self.current_success,
            'warning': self.current_warning,
            'error': self.current_error,
            'terminal': self.current_terminal,
            'matrix': self.current_matrix,
            'shadow': self.current_shadow,
            'border_radius': f"{self.custom_settings['border_radius']}px",
            'button_radius': f"{self.custom_settings['button_radius']}px"
        }

# ========================================
# SECURITY SETTINGS MANAGER
# ========================================
class EnhancedSecuritySettings:
    """Security and customization settings"""
    
    def __init__(self):
        self.settings = {
            "auto_scan": True,
            "process_monitoring": True,
            "detailed_logging": True,
            "security_level": "high",
            "auto_terminate_failed": True,
            "max_processes": 10,
            "log_retention_days": 30,
            "ui_theme": "cyber_dark",
            "border_radius": 6,
            "button_radius": 4,
            "enable_shadows": True,
            "compact_mode": False,
            "font_size": 9,
            "show_performance": True,
            "enable_sound": False,
            "startup_scan": True,
            "notifications": True
        }
        self.load_settings()
    
    def load_settings(self):
        """Load settings from file"""
        try:
            if os.path.exists("enhanced_security_settings.json"):
                with open("enhanced_security_settings.json", "r") as f:
                    loaded = json.load(f)
                    self.settings.update(loaded)
        except Exception as e:
            print(f"Settings load error: {e}")
    
    def save_settings(self):
        """Save settings to file"""
        try:
            with open("enhanced_security_settings.json", "w") as f:
                json.dump(self.settings, f, indent=2)
        except Exception as e:
            print(f"Settings save error: {e}")
    
    def get(self, key, default=None):
        """Get a setting"""
        return self.settings.get(key, default)
    
    def set(self, key, value):
        """Set a setting"""
        self.settings[key] = value
        self.save_settings()

# ========================================
# LOGGING & DEBUGGING SYSTEM
# ========================================
class EnhancedDebugLogger:
    """Advanced logging and debugging system"""
    
    def __init__(self):
        self.logs = []
        self.debug_logs = []
        self.error_logs = []
        self.performance_logs = []
        self.security_logs = []
        self.application_logs = []
        self.max_logs = 5000
        
        # Initialize file logging
        self.setup_file_logging()
        
        self.health_metrics = {
            "system_health": "optimal",
            "last_check": datetime.now().isoformat(),
            "errors_last_hour": 0,
            "performance_issues": [],
            "resource_usage": {},
            "application_stats": {}
        }
        
    def setup_file_logging(self):
        """Setup file-based logging"""
        try:
            if not os.path.exists("logs"):
                os.makedirs("logs")
            
            # Main application log
            self.file_logger = logging.getLogger('UIDock')
            self.file_logger.setLevel(logging.DEBUG)
            
            # File handler for all logs
            file_handler = logging.FileHandler('logs/uidock.log')
            file_handler.setLevel(logging.DEBUG)
            
            # Error log handler
            error_handler = logging.FileHandler('logs/error.log')
            error_handler.setLevel(logging.ERROR)
            
            # Security log handler
            security_handler = logging.FileHandler('logs/security.log')
            security_handler.setLevel(logging.WARNING)
            
            # Formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(formatter)
            error_handler.setFormatter(formatter)
            security_handler.setFormatter(formatter)
            
            self.file_logger.addHandler(file_handler)
            self.file_logger.addHandler(error_handler)
            self.file_logger.addHandler(security_handler)
            
        except Exception as e:
            print(f"File logging setup failed: {e}")
        
    def log(self, level, message, category="system", details=None, stack_trace=None, app_name=None):
        """Enhanced logging with stack traces and categorization"""
        timestamp = datetime.now()
        log_entry = {
            "timestamp": timestamp.isoformat(),
            "level": level,
            "category": category,
            "message": message,
            "details": details,
            "stack_trace": stack_trace,
            "app_name": app_name
        }
        
        self.logs.append(log_entry)
        
        # Categorize logs
        if level == "error":
            self.error_logs.append(log_entry)
            self.file_logger.error(f"{category}: {message} - {details}")
        elif level == "debug":
            self.debug_logs.append(log_entry)
            self.file_logger.debug(f"{category}: {message}")
        elif level == "performance":
            self.performance_logs.append(log_entry)
        elif level == "security":
            self.security_logs.append(log_entry)
            self.file_logger.warning(f"SECURITY - {category}: {message}")
        elif category == "application":
            self.application_logs.append(log_entry)
            self.file_logger.info(f"APP {app_name}: {message}")
        else:
            self.file_logger.info(f"{category}: {message}")
        
        # Trim logs to prevent memory issues
        for log_list in [self.logs, self.error_logs, self.debug_logs, 
                        self.performance_logs, self.security_logs, self.application_logs]:
            if len(log_list) > self.max_logs:
                del log_list[:len(log_list) - self.max_logs]
        
        return log_entry

    def log_error(self, message, details=None, exc_info=None, app_name=None):
        """Log error with automatic stack trace"""
        stack_trace = traceback.format_exc() if exc_info else None
        return self.log("error", message, "error", details, stack_trace, app_name)

    def log_debug(self, message, details=None, app_name=None):
        """Debug logging"""
        return self.log("debug", message, "debug", details, None, app_name)

    def log_security(self, message, details=None, app_name=None):
        """Security-related logging"""
        return self.log("warning", message, "security", details, None, app_name)

    def log_application(self, message, app_name, details=None):
        """Application-specific logging"""
        return self.log("info", message, "application", details, None, app_name)

    def log_performance(self, message, details=None):
        """Performance logging"""
        return self.log("info", message, "performance", details)

    def get_health_report(self):
        """Generate comprehensive system health report"""
        current_time = datetime.now()
        self.health_metrics["last_check"] = current_time.isoformat()
        
        hour_ago = current_time.timestamp() - 3600
        
        # Count errors in last hour
        self.health_metrics["errors_last_hour"] = len([
            log for log in self.error_logs 
            if datetime.fromisoformat(log["timestamp"]).timestamp() > hour_ago
        ])
        
        # Count security events
        security_events = len([
            log for log in self.security_logs 
            if datetime.fromisoformat(log["timestamp"]).timestamp() > hour_ago
        ])
        
        # Determine system health
        if self.health_metrics["errors_last_hour"] > 10 or security_events > 5:
            self.health_metrics["system_health"] = "critical"
        elif self.health_metrics["errors_last_hour"] > 5 or security_events > 2:
            self.health_metrics["system_health"] = "degraded"
        elif self.health_metrics["errors_last_hour"] > 2:
            self.health_metrics["system_health"] = "warning"
        else:
            self.health_metrics["system_health"] = "optimal"
        
        # Application statistics
        app_stats = {}
        for log in self.application_logs[-1000:]:  # Last 1000 app logs
            app_name = log.get('app_name', 'unknown')
            if app_name not in app_stats:
                app_stats[app_name] = {'launches': 0, 'errors': 0, 'last_activity': log['timestamp']}
            
            if log['level'] == 'error':
                app_stats[app_name]['errors'] += 1
            elif 'launch' in log['message'].lower():
                app_stats[app_name]['launches'] += 1
        
        self.health_metrics["application_stats"] = app_stats
        
        return self.health_metrics

    def get_log_summary(self):
        """Get comprehensive log summary for diagnostics"""
        return {
            "total_logs": len(self.logs),
            "errors": len(self.error_logs),
            "debug_entries": len(self.debug_logs),
            "performance_entries": len(self.performance_logs),
            "security_entries": len(self.security_logs),
            "application_entries": len(self.application_logs),
            "last_error": self.error_logs[-1] if self.error_logs else None,
            "last_security_event": self.security_logs[-1] if self.security_logs else None,
            "health_status": self.get_health_report()
        }

    def get_logs_by_category(self, category, limit=100):
        """Get logs filtered by category"""
        if category == "all":
            return self.logs[-limit:]
        elif category == "error":
            return self.error_logs[-limit:]
        elif category == "debug":
            return self.debug_logs[-limit:]
        elif category == "security":
            return self.security_logs[-limit:]
        elif category == "application":
            return self.application_logs[-limit:]
        elif category == "performance":
            return self.performance_logs[-limit:]
        else:
            return [log for log in self.logs if log.get('category') == category][-limit:]

    def clear_logs(self, log_type="all"):
        """Clear specific log types"""
        if log_type == "all":
            self.logs.clear()
            self.error_logs.clear()
            self.debug_logs.clear()
            self.performance_logs.clear()
            self.security_logs.clear()
            self.application_logs.clear()
        elif log_type == "error":
            self.error_logs.clear()
        elif log_type == "debug":
            self.debug_logs.clear()
        elif log_type == "security":
            self.security_logs.clear()
        elif log_type == "application":
            self.application_logs.clear()

    def export_logs(self, filename=None):
        """Export logs to file"""
        if not filename:
            filename = f"logs/uidock_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            export_data = {
                "export_timestamp": datetime.now().isoformat(),
                "log_summary": self.get_log_summary(),
                "recent_logs": self.logs[-1000:],  # Last 1000 logs
                "error_logs": self.error_logs[-500:],  # Last 500 errors
                "security_logs": self.security_logs[-200:],  # Last 200 security events
            }
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            return True, filename
        except Exception as e:
            return False, str(e)

# ========================================
# TRUST & SECURITY ANALYSIS SYSTEM
# ========================================
class TrustAnalysisSystem:
    """Advanced trust analysis for detected applications"""
    
    def __init__(self, logger):
        self.logger = logger
        self.trust_database = self.load_trust_database()
        self.analysis_history = []
        self.user_trust_overrides = self.load_user_trust_overrides()
        
    def load_trust_database(self):
        """Load trust analysis rules and patterns"""
        return {
            "suspicious_patterns": [
                "exec(", "eval(", "compile(", "open(", "os.system", "subprocess.call",
                "__import__", "getattr", "setattr", "input(", "file("
            ],
            "trusted_patterns": [
                "class ", "def ", "import ", "from ", "print(", "return "
            ],
            "risk_factors": {
                "network_operations": 3,
                "file_operations": 2,
                "system_commands": 5,
                "dynamic_code": 4,
                "gui_operations": 1
            }
        }
    
    def load_user_trust_overrides(self):
        """Load user-defined trust overrides"""
        try:
            if os.path.exists("user_trust_overrides.json"):
                with open("user_trust_overrides.json", "r") as f:
                    return json.load(f)
        except Exception as e:
            print(f"Trust overrides load error: {e}")
        return {}
    
    def save_user_trust_overrides(self):
        """Save user trust overrides to file"""
        try:
            with open("user_trust_overrides.json", "w") as f:
                json.dump(self.user_trust_overrides, f, indent=2)
        except Exception as e:
            print(f"Trust overrides save error: {e}")
    
    def set_user_trust_level(self, app_name, trust_level):
        """Allow user to manually set trust level for an app"""
        self.user_trust_overrides[app_name] = {
            "trust_level": trust_level,
            "set_by_user": True,
            "timestamp": datetime.now().isoformat()
        }
        self.save_user_trust_overrides()
        self.logger.log("info", f"User set trust level for {app_name} to {trust_level}", "trust_analysis")
    
    def get_user_trust_level(self, app_name):
        """Get user-defined trust level for an app"""
        return self.user_trust_overrides.get(app_name, {}).get("trust_level")
    
    def analyze_trust_level(self, file_path, source_code=None):
        """Comprehensive trust analysis of application code"""
        try:
            app_name = Path(file_path).stem
            
            # Check if user has manually set trust level
            user_trust_level = self.get_user_trust_level(app_name)
            if user_trust_level:
                return {
                    "file_path": file_path,
                    "timestamp": datetime.now().isoformat(),
                    "risk_score": 0,
                    "risk_factors": [],
                    "trust_level": user_trust_level,
                    "user_override": True,
                    "recommendations": ["Trust level set by user"],
                    "detected_patterns": []
                }
            
            if source_code is None:
                with open(file_path, 'r') as f:
                    source_code = f.read()
            
            analysis_result = {
                "file_path": file_path,
                "timestamp": datetime.now().isoformat(),
                "risk_score": 0,
                "risk_factors": [],
                "trust_level": "unknown",
                "user_override": False,
                "recommendations": [],
                "detected_patterns": []
            }
            
            # Analyze for suspicious patterns
            risk_factors = self.analyze_risk_factors(source_code)
            analysis_result["risk_factors"] = risk_factors
            analysis_result["risk_score"] = sum(factor["score"] for factor in risk_factors)
            
            # IMPROVED TRUST LOGIC: If app passes all checks and can run, it should be trusted
            # Only mark as untrusted if there are actual security risks
            if analysis_result["risk_score"] >= 10:
                analysis_result["trust_level"] = "untrusted"
            elif analysis_result["risk_score"] >= 5:
                analysis_result["trust_level"] = "moderate"
            else:
                # If no significant risks found, trust the application
                analysis_result["trust_level"] = "trusted"
            
            # Generate recommendations
            analysis_result["recommendations"] = self.generate_recommendations(analysis_result)
            
            self.analysis_history.append(analysis_result)
            self.logger.log("info", f"Trust analysis completed: {analysis_result['trust_level']}", 
                          "trust_analysis", analysis_result)
            
            return analysis_result
            
        except Exception as e:
            self.logger.log_error("Trust analysis failed", {"file_path": file_path}, e)
            return {
                "file_path": file_path,
                "trust_level": "unknown",
                "error": str(e),
                "risk_score": 0,
                "risk_factors": []
            }
    
    def analyze_risk_factors(self, source_code):
        """Analyze source code for risk factors"""
        risk_factors = []
        code_lower = source_code.lower()
        
        # Check for suspicious patterns
        for pattern in self.trust_database["suspicious_patterns"]:
            if pattern in source_code:
                risk_factors.append({
                    "factor": f"Suspicious pattern: {pattern}",
                    "score": self.trust_database["risk_factors"].get("dynamic_code", 2),
                    "pattern": pattern
                })
        
        # Check for network operations
        if any(network_keyword in code_lower for network_keyword in ["requests", "socket", "urllib", "http"]):
            risk_factors.append({
                "factor": "Network operations detected",
                "score": self.trust_database["risk_factors"]["network_operations"],
                "pattern": "network_operations"
            })
        
        # Check for file operations
        if any(file_keyword in code_lower for file_keyword in ["open(", "file(", "os.open", "write("]):
            risk_factors.append({
                "factor": "File operations detected",
                "score": self.trust_database["risk_factors"]["file_operations"],
                "pattern": "file_operations"
            })
        
        # Check for system commands
        if any(cmd_keyword in code_lower for cmd_keyword in ["os.system", "subprocess", "executable"]):
            risk_factors.append({
                "factor": "System command execution",
                "score": self.trust_database["risk_factors"]["system_commands"],
                "pattern": "system_commands"
            })
        
        return risk_factors
    
    def generate_recommendations(self, analysis_result):
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        if analysis_result["risk_score"] >= 10:
            recommendations.extend([
                "Run in isolated environment",
                "Review code manually before execution",
                "Monitor system resources during execution"
            ])
        elif analysis_result["risk_score"] >= 5:
            recommendations.extend([
                "Monitor application behavior",
                "Check network activity",
                "Verify file operations"
            ])
        else:
            recommendations.append("Application appears safe for normal use")
        
        return recommendations

# ========================================
# DEFAULT APPS MANAGER
# ========================================
class DefaultAppsManager:
    """Manage default applications that are outlined and shown at the top"""
    
    def __init__(self):
        self.default_apps_file = "default_apps.json"
        self.default_apps = self.load_default_apps()
    
    def load_default_apps(self):
        """Load default apps from file"""
        try:
            if os.path.exists(self.default_apps_file):
                with open(self.default_apps_file, 'r') as f:
                    data = json.load(f)
                    return data.get("default_apps", [])
        except Exception as e:
            print(f"Error loading default apps: {e}")
        return []
    
    def save_default_apps(self):
        """Save default apps to file"""
        try:
            data = {
                "default_apps": self.default_apps,
                "last_updated": datetime.now().isoformat()
            }
            with open(self.default_apps_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving default apps: {e}")
    
    def add_default_app(self, app_name):
        """Add an app to default apps"""
        if app_name not in self.default_apps:
            self.default_apps.append(app_name)
            self.save_default_apps()
            return True
        return False
    
    def remove_default_app(self, app_name):
        """Remove an app from default apps"""
        if app_name in self.default_apps:
            self.default_apps.remove(app_name)
            self.save_default_apps()
            return True
        return False
    
    def is_default_app(self, app_name):
        """Check if an app is a default app"""
        return app_name in self.default_apps
    
    def get_default_apps(self):
        """Get list of default apps"""
        return self.default_apps.copy()

# ========================================
# LOADING BRIDGE WINDOW
# ========================================
class LoadingBridgeWindow(QWidget):
    """Temporary loading bridge for multi-file applications"""
    
    def __init__(self, app_name, folder_name, executable_path, parent=None):
        super().__init__(parent)
        self.app_name = app_name
        self.folder_name = folder_name
        self.executable_path = executable_path
        self.process = None
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle(f"LOADING[{self.app_name}]-from:[{self.folder_name}]")
        self.setFixedSize(300, 100)
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.Dialog)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Loading label
        loading_label = QLabel(f"🚀 Launching: {self.app_name}")
        loading_label.setAlignment(Qt.AlignCenter)
        loading_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        layout.addWidget(loading_label)
        
        # From folder label
        folder_label = QLabel(f"📁 From: {self.folder_name}")
        folder_label.setAlignment(Qt.AlignCenter)
        folder_label.setStyleSheet("font-size: 10px; color: #888;")
        layout.addWidget(folder_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("Initializing application...")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("font-size: 9px;")
        layout.addWidget(self.status_label)
        
        # Start the application
        self.start_application()
        
    def start_application(self):
        """Start the application process"""
        try:
            self.status_label.setText("Starting process...")
            
            # Determine how to launch based on file type
            if self.executable_path.endswith('.py'):
                # Python file
                self.process = subprocess.Popen([sys.executable, self.executable_path])
                launch_method = "Python"
            elif self.executable_path.endswith(('.sh', '.bash')):
                # Shell script
                self.process = subprocess.Popen(['bash', self.executable_path])
                launch_method = "Bash"
            elif self.executable_path.endswith('.exe'):
                # Windows executable
                self.process = subprocess.Popen([self.executable_path])
                launch_method = "Executable"
            else:
                # Try to execute directly
                self.process = subprocess.Popen([self.executable_path])
                launch_method = "Direct"
                
            self.status_label.setText(f"Launched with {launch_method} - PID: {self.process.pid}")
            
            # Monitor the process
            self.monitor_timer = QTimer()
            self.monitor_timer.timeout.connect(self.check_process)
            self.monitor_timer.start(500)  # Check every 500ms
            
        except Exception as e:
            self.status_label.setText(f"Error: {str(e)}")
            QTimer.singleShot(3000, self.close)  # Close after 3 seconds on error
            
    def check_process(self):
        """Check if the process is still running"""
        if self.process and self.process.poll() is not None:
            # Process has ended, close the loading window
            self.status_label.setText("Application started successfully")
            QTimer.singleShot(1000, self.close)  # Close after 1 second

# ========================================
# FOLDER CONFIGURATION DIALOG
# ========================================
class FolderConfigurationDialog(QDialog):
    """Dialog to configure multi-file application folders"""
    
    def __init__(self, folder_path, parent=None):
        super().__init__(parent)
        self.folder_path = Path(folder_path)
        self.selected_executable = None
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle(f"Configure: {self.folder_path.name}")
        self.setFixedSize(500, 400)
        
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel(f"📁 Configure Application: {self.folder_path.name}")
        header.setStyleSheet("font-weight: bold; font-size: 14px; margin-bottom: 10px;")
        layout.addWidget(header)
        
        # Description
        desc = QLabel("Select the main executable file for this application:")
        layout.addWidget(desc)
        
        # Supported file types
        file_types = QLabel("Supported: .py, .sh, .bash, .exe, and other executables")
        file_types.setStyleSheet("font-size: 10px; color: #888; font-style: italic;")
        layout.addWidget(file_types)
        
        # File list
        layout.addWidget(QLabel("Files in folder:"))
        
        self.file_list = QListWidget()
        self.file_list.itemDoubleClicked.connect(self.select_file)
        layout.addWidget(self.file_list)
        
        # Selected file display
        selected_layout = QHBoxLayout()
        selected_layout.addWidget(QLabel("Selected:"))
        self.selected_label = QLabel("No file selected")
        self.selected_label.setStyleSheet("font-weight: bold; color: #00ff88;")
        selected_layout.addWidget(self.selected_label)
        selected_layout.addStretch()
        layout.addLayout(selected_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_file)
        button_layout.addWidget(browse_btn)
        
        button_layout.addStretch()
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        ok_btn = QPushButton("Configure")
        ok_btn.setDefault(True)
        ok_btn.clicked.connect(self.accept_configuration)
        button_layout.addWidget(ok_btn)
        
        layout.addLayout(button_layout)
        
        self.load_files()
        
    def load_files(self):
        """Load all files from the folder"""
        self.file_list.clear()
        
        # Supported executable patterns
        executable_patterns = ['*.py', '*.sh', '*.bash', '*.exe', '*.bat', '*.cmd']
        
        all_files = []
        for pattern in executable_patterns:
            all_files.extend(self.folder_path.glob(pattern))
            
        # Also look for files without extensions that might be executables
        for item in self.folder_path.iterdir():
            if item.is_file() and not item.suffix and os.access(item, os.X_OK):
                all_files.append(item)
        
        # Add files to list
        for file_path in sorted(all_files):
            item = QListWidgetItem(f"{file_path.name} ({file_path.suffix or 'executable'})")
            item.setData(Qt.UserRole, file_path)
            self.file_list.addItem(item)
            
    def browse_file(self):
        """Browse for a file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "Select Application Executable",
            str(self.folder_path),
            "Executable Files (*.py *.sh *.bash *.exe *.bat *.cmd);;All Files (*)"
        )
        
        if file_path:
            self.selected_executable = Path(file_path)
            self.selected_label.setText(self.selected_executable.name)
            
    def select_file(self, item):
        """Select a file from the list"""
        self.selected_executable = item.data(Qt.UserRole)
        self.selected_label.setText(self.selected_executable.name)
        
    def accept_configuration(self):
        """Accept the configuration"""
        if not self.selected_executable:
            QMessageBox.warning(self, "No File Selected", "Please select an executable file.")
            return
            
        if not self.selected_executable.exists():
            QMessageBox.warning(self, "File Not Found", "The selected file does not exist.")
            return
            
        self.accept()
        
    def get_configuration(self):
        """Get the configuration result"""
        return {
            'folder_path': str(self.folder_path),
            'executable_path': str(self.selected_executable),
            'app_name': self.folder_path.name,
            'configured_at': datetime.now().isoformat()
        }

# ========================================
# WINDOW SCANNER WITH FOLDER SUPPORT
# ========================================
class EnhancedWindowScanner(QThread):
    """thread for scanning and detecting GUI window files and folders"""
    scan_complete = pyqtSignal(dict)
    scan_progress = pyqtSignal(int, str)
    
    def __init__(self, windows_dir):
        super().__init__()
        self.windows_dir = Path(windows_dir)
        self.windows_dir.mkdir(exist_ok=True)
        self.folder_configs = self.load_folder_configurations()
    
    def load_folder_configurations(self):
        """Load folder configurations from file"""
        try:
            if os.path.exists("folder_configurations.json"):
                with open("folder_configurations.json", "r") as f:
                    return json.load(f)
        except Exception as e:
            print(f"Folder configs load error: {e}")
        return {}
    
    def save_folder_configurations(self):
        """Save folder configurations to file"""
        try:
            with open("folder_configurations.json", "w") as f:
                json.dump(self.folder_configs, f, indent=2)
        except Exception as e:
            print(f"Folder configs save error: {e}")
    
    def run(self):
        """Scan for Python files and application folders in windows directory"""
        detected_windows = {}
        
        if self.windows_dir.exists():
            # Scan for single Python files
            py_files = list(self.windows_dir.glob("*.py"))
            # Scan for application folders
            folders = [f for f in self.windows_dir.iterdir() if f.is_dir() and not f.name.startswith('.')]
            
            total_items = len(py_files) + len(folders)
            
            current_item = 0
            # Process single Python files
            for py_file in py_files:
                if py_file.name == "__init__.py":
                    continue
                    
                current_item += 1
                progress = int((current_item) / total_items * 100) if total_items > 0 else 100
                self.scan_progress.emit(progress, f"Analyzing {py_file.name}...")
                
                window_info = self.analyze_window_file(py_file)
                if window_info:
                    detected_windows[py_file.stem] = window_info
                
                time.sleep(0.05)
            
            # Process application folders
            for folder in folders:
                current_item += 1
                progress = int((current_item) / total_items * 100) if total_items > 0 else 100
                self.scan_progress.emit(progress, f"Scanning folder {folder.name}...")
                
                folder_info = self.analyze_application_folder(folder)
                if folder_info:
                    detected_windows[folder.name] = folder_info
                
                time.sleep(0.05)
        
        self.scan_complete.emit(detected_windows)
    
    def analyze_application_folder(self, folder_path):
        """Analyze application folder for executable files"""
        try:
            folder_info = {
                "type": "folder",
                "folder_path": str(folder_path),
                "files": [],
                "executables": [],
                "main_file": None,
                "status": "unconfigured",
                "display_name": folder_path.stem.replace('_', ' ').title(),
                "description": f"Multi-file application in {folder_path.name}",
                "detected_at": datetime.now().isoformat(),
                "security_level": "unknown",
                "file_size": 0,
                "last_modified": datetime.fromtimestamp(os.path.getmtime(folder_path)).isoformat()
            }
            
            # Check if folder has existing configuration
            if folder_path.name in self.folder_configs:
                config = self.folder_configs[folder_path.name]
                folder_info.update({
                    "status": "configured",
                    "main_file": config['executable_path'],
                    "security_level": self.analyze_security_file(config['executable_path']),
                    "display_name": config.get('custom_name', folder_info['display_name'])
                })
            
            # Scan for executable files
            executable_patterns = ['*.py', '*.sh', '*.bash', '*.exe', '*.bat', '*.cmd']
            
            for pattern in executable_patterns:
                for file_path in folder_path.glob(pattern):
                    file_info = {
                        'name': file_path.name,
                        'path': str(file_path),
                        'size': os.path.getsize(file_path),
                        'executable': os.access(file_path, os.X_OK)
                    }
                    folder_info['files'].append(file_info)
                    folder_info['executables'].append(file_info)
            
            # Also look for files without extensions that might be executables
            for item in folder_path.iterdir():
                if item.is_file() and not item.suffix and os.access(item, os.X_OK):
                    file_info = {
                        'name': item.name,
                        'path': str(item),
                        'size': os.path.getsize(item),
                        'executable': True
                    }
                    folder_info['files'].append(file_info)
                    folder_info['executables'].append(file_info)
            
            return folder_info
                
        except Exception as e:
            return {
                "type": "folder",
                "folder_path": str(folder_path),
                "status": "error",
                "error": str(e),
                "display_name": folder_path.stem,
                "security_level": "untrusted",
                "detected_at": datetime.now().isoformat()
            }
    
    def analyze_window_file(self, file_path):
        """Analyze a Python file to detect GUI frameworks and main classes"""
        try:
            # Read the file content first for analysis
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_code = f.read()
            
            # Security analysis
            security_level = self.analyze_security(source_code)
            
            # Framework detection
            framework = "unknown"
            gui_classes = []
            main_functions = []
            root_creation = False
            
            # Check for PyQt imports and classes
            if any(qt_import in source_code for qt_import in ['PyQt5', 'from PyQt5', 'import PyQt5']):
                framework = "pyqt"
                # Look for class definitions that might be GUI classes
                lines = source_code.split('\n')
                for line in lines:
                    line_clean = line.strip()
                    if line_clean.startswith('class ') and ('QMainWindow' in line_clean or 'QWidget' in line_clean):
                        class_name = line_clean.split('class ')[1].split('(')[0].strip()
                        if class_name:
                            gui_classes.append(class_name)
            
            # Check for tkinter
            elif any(tk_import in source_code for tk_import in ['import tkinter', 'from tkinter', 'import Tk', 'import Toplevel']):
                framework = "tkinter"
                if 'Tk()' in source_code or 'Toplevel()' in source_code:
                    root_creation = True
            
            # Look for main functions
            if 'def main()' in source_code or 'if __name__' in source_code:
                main_functions.append('main')
            
            # Determine status
            status = "ready" if (gui_classes or main_functions or root_creation or self.has_gui_creation(source_code)) else "no_gui_class"
            
            result = {
                "file_path": str(file_path),
                "type": "file",
                "status": status,
                "class_name": gui_classes[0] if gui_classes else main_functions[0] if main_functions else "DirectExecution",
                "classes": gui_classes,
                "main_functions": main_functions,
                "root_creation": root_creation,
                "framework": framework,
                "display_name": file_path.stem.replace('_', ' ').title(),
                "description": f"Auto-detected {framework} GUI from {file_path.name}",
                "detected_at": datetime.now().isoformat(),
                "security_level": security_level,
                "file_size": os.path.getsize(file_path),
                "last_modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
            }
            
            return result
                
        except Exception as e:
            return {
                "file_path": str(file_path),
                "type": "file",
                "status": "error",
                "error": str(e),
                "display_name": file_path.stem,
                "framework": "unknown",
                "security_level": "untrusted",
                "detected_at": datetime.now().isoformat()
            }
    
    def analyze_security_file(self, file_path):
        """Analyze security of a specific file"""
        try:
            if file_path.endswith('.py'):
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    source_code = f.read()
                return self.analyze_security(source_code)
            else:
                # For non-Python files, use basic trust
                return "trusted"
        except:
            return "unknown"
    
    def has_gui_creation(self, source_code):
        """Check if source code contains GUI creation patterns"""
        gui_patterns = [
            'Tk()', 'Toplevel()', 'QApplication', 'QMainWindow', 'QWidget', 
            'show()', 'mainloop()', 'exec_()'
        ]
        return any(pattern in source_code for pattern in gui_patterns)
    
    def analyze_security(self, source_code):
        """Analyze source code for potential security issues"""
        security_issues = []
        
        dangerous_imports = ['os.system', 'subprocess.call', 'eval', 'exec', 'pickle.loads']
        for imp in dangerous_imports:
            if imp in source_code:
                security_issues.append(imp)
        
        network_keywords = ['requests.get', 'socket.socket', 'urllib.request']
        for keyword in network_keywords:
            if keyword in source_code:
                security_issues.append(keyword)
        
        if not security_issues:
            return "trusted"
        elif len(security_issues) <= 2:
            return "moderate"
        else:
            return "untrusted"
    
    def save_folder_configuration(self, folder_name, configuration):
        """Save folder configuration"""
        self.folder_configs[folder_name] = configuration
        self.save_folder_configurations()

# ========================================
# PROCESS TRACKING
# ========================================
class EnhancedProcessTracker:
    """process tracking with better resource monitoring"""
    
    def __init__(self, logger):
        self.active_windows = {}
        self.process_history = []
        self.performance_stats = {
            "total_launches": 0,
            "successful_launches": 0,
            "failed_launches": 0,
            "total_runtime": 0,
            "average_runtime": 0
        }
        self.logger = logger
        
    def add_window(self, window_name, process_info):
        """Add a window to active tracking"""
        self.active_windows[window_name] = {
            **process_info,
            'status': 'running',
            'start_time': datetime.now().isoformat(),
            'last_check': datetime.now().isoformat(),
            'security_status': 'monitoring',
            'resource_usage': {
                'cpu_percent': 0,
                'memory_mb': 0,
                'threads': 0
            }
        }
        
        history_entry = {
            **process_info,
            'start_time': datetime.now().isoformat(),
            'status': 'launched'
        }
        self.process_history.append(history_entry)
        
        self.performance_stats["total_launches"] += 1
        self.performance_stats["successful_launches"] += 1
        
        self.logger.log_application(f"Application launched: {window_name}", window_name, process_info)
        
        return True
    
    def remove_window(self, window_name, reason="closed"):
        """Remove a window from tracking"""
        if window_name in self.active_windows:
            window_info = self.active_windows[window_name]
            window_info['end_time'] = datetime.now().isoformat()
            window_info['status'] = reason
            
            start_time = datetime.fromisoformat(window_info['start_time'])
            end_time = datetime.now()
            runtime = (end_time - start_time).total_seconds()
            
            self.performance_stats["total_runtime"] += runtime
            
            for entry in reversed(self.process_history):
                if entry.get('name') == window_name and entry.get('status') == 'launched':
                    entry['end_time'] = datetime.now().isoformat()
                    entry['status'] = reason
                    entry['runtime'] = runtime
                    break
            
            self.logger.log_application(f"Application {reason}: {window_name}", window_name, {
                'runtime': runtime,
                'start_time': window_info['start_time'],
                'end_time': window_info['end_time']
            })
            
            del self.active_windows[window_name]
            return True
        return False
    
    def check_process_status(self):
        """Check if tracked processes are still running"""
        windows_to_remove = []
        
        for window_name, window_info in self.active_windows.items():
            try:
                process = window_info.get('process')
                if process and process.poll() is not None:
                    windows_to_remove.append((window_name, "terminated"))
                else:
                    try:
                        if process and process.poll() is None:
                            ps_process = psutil.Process(process.pid)
                            window_info['resource_usage'] = {
                                'cpu_percent': ps_process.cpu_percent(),
                                'memory_mb': ps_process.memory_info().rss / 1024 / 1024,
                                'threads': ps_process.num_threads()
                            }
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    
                    window_info['last_check'] = datetime.now().isoformat()
            except Exception as e:
                windows_to_remove.append((window_name, f"error: {str(e)}"))
        
        for window_name, reason in windows_to_remove:
            self.remove_window(window_name, reason)
        
        return len(windows_to_remove) > 0
    
    def get_running_count(self):
        """Get count of running processes"""
        return len(self.active_windows)
    
    def get_active_windows(self):
        """Get active windows info"""
        return self.active_windows
    
    def get_performance_stats(self):
        """Get performance statistics"""
        if self.performance_stats["successful_launches"] > 0:
            self.performance_stats["average_runtime"] = (
                self.performance_stats["total_runtime"] / self.performance_stats["successful_launches"]
            )
        return self.performance_stats
    
    def force_terminate(self, window_name):
        """Force terminate a process"""
        if window_name in self.active_windows:
            try:
                process = self.active_windows[window_name].get('process')
                if process:
                    process.terminate()
                    time.sleep(0.5)
                    if process.poll() is None:
                        process.kill()
                self.remove_window(window_name, "force_terminated")
                self.logger.log_security(f"Application force terminated: {window_name}", window_name)
                return True
            except Exception as e:
                self.logger.log_error(f"Termination failed: {e}", None, window_name)
        return False

# ========================================
# EXTERNAL WINDOW MANAGER
# ========================================
class EnhancedExternalWindowManager:
    """window manager with security tracking"""
    
    def __init__(self, logger):
        self.process_tracker = EnhancedProcessTracker(logger)
        self.logger = logger
    
    def launch_python_app(self, file_path, window_name):
        """Launch Python app with security tracking"""
        try:
            process = subprocess.Popen([sys.executable, file_path])
            process_info = {
                "name": window_name,
                "file_path": file_path,
                "process": process,
                "framework": "python",
                "type": "external",
                "pid": process.pid
            }
            
            self.process_tracker.add_window(window_name, process_info)
            self.logger.log_application(f"Successfully launched: {window_name}", window_name, {
                'file_path': file_path,
                'pid': process.pid
            })
            return True, f"Launched application: {window_name}"
        except Exception as e:
            self.process_tracker.performance_stats["failed_launches"] += 1
            self.logger.log_error(f"Failed to launch: {window_name}", {
                'file_path': file_path,
                'error': str(e)
            }, window_name)
            return False, f"Error launching app: {str(e)}"
    
    def launch_folder_app(self, folder_name, executable_path, window_name):
        """Launch folder-based application with loading bridge"""
        try:
            # Create and show loading bridge
            loading_window = LoadingBridgeWindow(
                window_name, 
                folder_name, 
                executable_path
            )
            loading_window.show()
            
            # The loading window handles the actual process launch
            # We track it as launched immediately since the loading window is managing it
            process_info = {
                "name": window_name,
                "file_path": executable_path,
                "process": loading_window.process,  # This might be None initially
                "framework": "folder",
                "type": "external",
                "folder_name": folder_name,
                "loading_window": loading_window
            }
            
            self.process_tracker.add_window(window_name, process_info)
            self.logger.log_application(f"Started folder application: {window_name}", window_name, {
                'folder_name': folder_name,
                'executable_path': executable_path
            })
            return True, f"Launching folder application: {window_name}"
            
        except Exception as e:
            self.process_tracker.performance_stats["failed_launches"] += 1
            self.logger.log_error(f"Failed to launch folder app: {window_name}", {
                'folder_name': folder_name,
                'executable_path': executable_path,
                'error': str(e)
            }, window_name)
            return False, f"Error launching folder app: {str(e)}"
    
    def terminate_process(self, window_name):
        """Terminate a process with security tracking"""
        return self.process_tracker.force_terminate(window_name)
    
    def get_running_count(self):
        """Get running process count"""
        return self.process_tracker.get_running_count()
    
    def get_active_windows(self):
        """Get active windows"""
        return self.process_tracker.get_active_windows()
    
    def get_performance_stats(self):
        """Get performance statistics"""
        return self.process_tracker.get_performance_stats()

# ========================================
# APP GROUPING SYSTEM
# ========================================
class AppGroupManager:
    """Manage custom application groups for organization"""
    
    def __init__(self):
        self.groups_file = "app_groups.json"
        self.groups = self.load_groups()
    
    def load_groups(self):
        """Load groups from file"""
        try:
            if os.path.exists(self.groups_file):
                with open(self.groups_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading groups: {e}")
        return {"default": {"name": "Default", "apps": []}}
    
    def save_groups(self):
        """Save groups to file"""
        try:
            with open(self.groups_file, 'w') as f:
                json.dump(self.groups, f, indent=2)
        except Exception as e:
            print(f"Error saving groups: {e}")
    
    def create_group(self, group_id, group_name):
        """Create a new group"""
        self.groups[group_id] = {"name": group_name, "apps": []}
        self.save_groups()
    
    def delete_group(self, group_id):
        """Delete a group"""
        if group_id in self.groups and group_id != "default":
            # Move all apps from deleted group to default group
            for app in self.groups[group_id]["apps"]:
                if app not in self.groups["default"]["apps"]:
                    self.groups["default"]["apps"].append(app)
            del self.groups[group_id]
            self.save_groups()
            return True
        return False
    
    def rename_group(self, group_id, new_name):
        """Rename a group"""
        if group_id in self.groups and group_id != "default":
            self.groups[group_id]["name"] = new_name
            self.save_groups()
            return True
        return False
    
    def add_app_to_group(self, app_name, group_id):
        """Add app to group"""
        if group_id in self.groups:
            if app_name not in self.groups[group_id]["apps"]:
                self.groups[group_id]["apps"].append(app_name)
                self.save_groups()
                return True
        return False
    
    def remove_app_from_group(self, app_name, group_id):
        """Remove app from group"""
        if group_id in self.groups and app_name in self.groups[group_id]["apps"]:
            self.groups[group_id]["apps"].remove(app_name)
            self.save_groups()
            return True
        return False
    
    def get_app_groups(self, app_name):
        """Get groups for an app"""
        return [group_id for group_id, group_data in self.groups.items() 
                if app_name in group_data["apps"]]
    
    def get_group_apps(self, group_id):
        """Get apps in a group"""
        return self.groups.get(group_id, {}).get("apps", [])
    
    def get_all_groups(self):
        """Get all groups except default"""
        return {k: v for k, v in self.groups.items() if k != "default"}

# ========================================
# GUI WINDOW MANAGER
# ========================================
class EnhancedGUIWindowManager:
    
    def __init__(self, logger):
        self.windows_dir = "windows"
        Path(self.windows_dir).mkdir(exist_ok=True)
        self.available_windows = {}
        self.window_manager = EnhancedExternalWindowManager(logger)
        self.embedded_windows = {}
        self.security_settings = EnhancedSecuritySettings()
        self.logger = logger
        
        # Start scanning for windows
        self.start_window_scan()
    
    def start_window_scan(self):
        """Start scanning for windows in the windows directory"""
        self.scanner = EnhancedWindowScanner(self.windows_dir)
        self.scanner.scan_complete.connect(self.update_available_windows)
        self.scanner.start()
        self.logger.log("info", "Started window scanner", "scanner")
    
    def update_available_windows(self, detected_windows):
        """Update available windows from scanner results"""
        self.available_windows = detected_windows
        
        ready_count = len([w for w in detected_windows.values() if w.get('status') == 'ready'])
        folder_count = len([w for w in detected_windows.values() if w.get('type') == 'folder'])
        total_count = len(detected_windows)
        trusted_count = len([w for w in detected_windows.values() if w.get('security_level') == 'trusted'])
        
        self.logger.log("info", f"Window scan completed: {ready_count}/{total_count} ready, {folder_count} folders, {trusted_count} trusted", "scanner", {
            'ready_count': ready_count,
            'folder_count': folder_count,
            'total_count': total_count,
            'trusted_count': trusted_count
        })

# ========================================
# LAUNCHER INTERFACE
# ========================================
class CompactLauncherWidget(QWidget):
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.group_manager = AppGroupManager()
        self.default_apps_manager = DefaultAppsManager()
        self.init_ui()
        
        # Refresh apps periodically
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_apps)
        self.refresh_timer.start(5000)  # Refresh every 5 seconds
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        
        # Header with refresh button
        header_layout = QHBoxLayout()
        header = QLabel("🚀 APPLICATION LAUNCHER")
        header.setFont(QFont("Courier New", 14, QFont.Bold))
        header.setStyleSheet(self.get_header_style())
        header_layout.addWidget(header)
        
        refresh_btn = QPushButton("🔄 Scan")
        refresh_btn.setFixedSize(60, 30)
        refresh_btn.setStyleSheet(self.get_small_button_style())
        refresh_btn.clicked.connect(self.force_rescan)
        header_layout.addWidget(refresh_btn)
        
        header_layout.addStretch()
        layout.addLayout(header_layout)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        
        # Group filter
        filter_layout.addWidget(QLabel("Group:"))
        self.group_combo = QComboBox()
        self.group_combo.setStyleSheet(self.get_combo_style())
        self.group_combo.currentTextChanged.connect(self.filter_apps)
        filter_layout.addWidget(self.group_combo)
        
        # Trust level filter
        filter_layout.addWidget(QLabel("Trust:"))
        self.trust_combo = QComboBox()
        self.trust_combo.addItems(["All", "Trusted", "Moderate", "Untrusted", "User Trusted"])
        self.trust_combo.setStyleSheet(self.get_combo_style())
        self.trust_combo.currentTextChanged.connect(self.filter_apps)
        filter_layout.addWidget(self.trust_combo)
        
        # Type filter
        filter_layout.addWidget(QLabel("Type:"))
        self.type_combo = QComboBox()
        self.type_combo.addItems(["All", "Single File", "Folder"])
        self.type_combo.setStyleSheet(self.get_combo_style())
        self.type_combo.currentTextChanged.connect(self.filter_apps)
        filter_layout.addWidget(self.type_combo)
        
        # Default Apps filter
        filter_layout.addWidget(QLabel("Show:"))
        self.default_filter_combo = QComboBox()
        self.default_filter_combo.addItems(["All Apps", "Default Apps Only"])
        self.default_filter_combo.setStyleSheet(self.get_combo_style())
        self.default_filter_combo.currentTextChanged.connect(self.filter_apps)
        filter_layout.addWidget(self.default_filter_combo)
        
        filter_layout.addStretch()
        
        # Group management buttons
        new_group_btn = QPushButton("+")
        new_group_btn.setFixedSize(30, 25)
        new_group_btn.setStyleSheet(self.get_small_button_style())
        new_group_btn.clicked.connect(self.create_new_group)
        filter_layout.addWidget(new_group_btn)
        
        manage_groups_btn = QPushButton("📁")
        manage_groups_btn.setFixedSize(30, 25)
        manage_groups_btn.setStyleSheet(self.get_small_button_style())
        manage_groups_btn.clicked.connect(self.manage_groups)
        filter_layout.addWidget(manage_groups_btn)
        
        layout.addLayout(filter_layout)
        
        # Search
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search applications...")
        self.search_input.setStyleSheet(self.get_input_style())
        self.search_input.textChanged.connect(self.filter_apps)
        search_layout.addWidget(self.search_input)
        layout.addLayout(search_layout)
        
        # Apps scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setStyleSheet("QScrollArea { border: none; }")
        
        # Apps container
        self.apps_container = QWidget()
        self.apps_layout = QVBoxLayout(self.apps_container)
        self.apps_layout.setContentsMargins(5, 5, 5, 5)
        self.apps_layout.setSpacing(6)
        self.apps_layout.addStretch()
        
        scroll.setWidget(self.apps_container)
        layout.addWidget(scroll)
        
        # Update groups and apps
        self.update_groups_display()
        self.update_apps_display()
    
    def force_rescan(self):
        """Force rescan of windows directory"""
        self.main_window.window_manager.start_window_scan()
        self.main_window.debug_logger.log("info", "Manual rescan triggered", "launcher")
        QMessageBox.information(self, "Rescan", "Scanning windows directory for applications...")
    
    def refresh_apps(self):
        """Refresh apps display"""
        self.update_apps_display()
    
    def update_groups_display(self):
        """Update groups combo box"""
        current_group = self.group_combo.currentData() if self.group_combo.currentData() else "all"
        self.group_combo.clear()
        
        self.group_combo.addItem("All Groups", "all")
        for group_id, group_data in self.group_manager.groups.items():
            self.group_combo.addItem(group_data["name"], group_id)
        
        # Restore selection if possible
        index = self.group_combo.findData(current_group)
        if index >= 0:
            self.group_combo.setCurrentIndex(index)
        else:
            self.group_combo.setCurrentIndex(0)  # All Groups
    
    def filter_apps(self):
        """Filter apps based on all criteria"""
        self.update_apps_display()
    
    def update_apps_display(self):
        """Update apps display with filtering - FIXED VERSION"""
        # Clear existing apps
        for i in reversed(range(self.apps_layout.count())):
            widget = self.apps_layout.itemAt(i).widget()
            if widget and hasattr(widget, 'is_app_widget'):
                widget.deleteLater()
        
        # Get current filters
        current_group = self.group_combo.currentData()
        current_trust = self.trust_combo.currentText()
        current_type = self.type_combo.currentText()
        current_default_filter = self.default_filter_combo.currentText()
        search_text = self.search_input.text().lower()
        
        # Separate default and non-default apps
        default_apps = []
        regular_apps = []
        
        for app_name, app_info in self.main_window.window_manager.available_windows.items():
            # Apply type filter
            if current_type != "All":
                app_type = app_info.get('type', 'file')
                if current_type == "Single File" and app_type != "file":
                    continue
                elif current_type == "Folder" and app_type != "folder":
                    continue
            
            # Apply group filter
            if current_group and current_group != "all":
                group_apps = self.group_manager.get_group_apps(current_group)
                if app_name not in group_apps:
                    continue
            
            # Apply trust filter - FIXED LOGIC
            if current_trust != "All":
                # Get the actual trust level to display (user override or auto-detected)
                display_trust_level = self.get_app_display_trust_level(app_name, app_info)
                
                if current_trust == "User Trusted":
                    # Only show apps with user overrides
                    user_trust = self.main_window.trust_system.get_user_trust_level(app_name)
                    if not user_trust:
                        continue
                elif current_trust.lower() != display_trust_level:
                    continue
            
            # Apply search filter
            if search_text and search_text not in app_name.lower():
                continue
            
            # Check if app is a default app
            if self.default_apps_manager.is_default_app(app_name):
                default_apps.append((app_name, app_info))
            else:
                regular_apps.append((app_name, app_info))
        
        # Apply default apps filter
        if current_default_filter == "Default Apps Only":
            apps_to_display = default_apps
        else:
            # Show default apps first, then regular apps
            apps_to_display = default_apps + regular_apps
        
        # Create app widgets
        displayed_count = 0
        for app_name, app_info in apps_to_display:
            app_widget = self.create_app_widget(app_name, app_info)
            self.apps_layout.insertWidget(self.apps_layout.count() - 1, app_widget)
            displayed_count += 1
        
        # Show message if no apps found
        if displayed_count == 0:
            no_apps_label = QLabel("No applications found matching current filters.")
            no_apps_label.setAlignment(Qt.AlignCenter)
            no_apps_label.setStyleSheet("color: #888; font-style: italic; padding: 20px;")
            no_apps_label.is_app_widget = True
            self.apps_layout.insertWidget(0, no_apps_label)
    
    def get_app_display_trust_level(self, app_name, app_info):
        """Get the trust level to display for an app (user override or auto-detected)"""
        user_trust = self.main_window.trust_system.get_user_trust_level(app_name)
        if user_trust:
            return user_trust
        else:
            return app_info.get('security_level', 'unknown')
    
    def create_app_widget(self, app_name, app_info):
        """Create a compact app widget with trust management and default app highlighting"""
        widget = QFrame()
        widget.setFixedHeight(70)
        
        # Check if this is a default app and apply special styling
        is_default_app = self.default_apps_manager.is_default_app(app_name)
        if is_default_app:
            widget.setStyleSheet(self.get_default_app_widget_style())
        else:
            widget.setStyleSheet(self.get_app_widget_style())
        
        widget.is_app_widget = True
        
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(10)
        
        # App info
        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)
        
        # Add default app indicator
        name_text = app_info.get('display_name', app_name)
        if is_default_app:
            name_text = "⭐ " + name_text
            
        name_label = QLabel(name_text)
        name_label.setStyleSheet(f"color: {self.main_window.theme_manager.current_accent}; font-weight: bold; font-size: 11px;")
        info_layout.addWidget(name_label)
        
        # Type and trust status
        app_type = app_info.get('type', 'file')
        type_icon = "📁" if app_type == "folder" else "📄"
        
        trust_level = app_info.get('security_level', 'unknown')
        user_trust = self.main_window.trust_system.get_user_trust_level(app_name)
        
        if user_trust:
            trust_text = f"🔒 {user_trust.title()} (User Set)"
            trust_color = self.main_window.theme_manager.current_success
        else:
            trust_text = f"🛡️ {trust_level.title()}"
            if trust_level == "trusted":
                trust_color = self.main_window.theme_manager.current_success
            elif trust_level == "moderate":
                trust_color = self.main_window.theme_manager.current_warning
            else:
                trust_color = self.main_window.theme_manager.current_error
        
        trust_label = QLabel(f"{type_icon} {trust_text}")
        trust_label.setStyleSheet(f"color: {trust_color}; font-size: 9px;")
        info_layout.addWidget(trust_label)
        
        # Description based on type
        if app_type == "folder":
            status = app_info.get('status', 'unconfigured')
            if status == "configured":
                desc = f"📦 Folder • {len(app_info.get('files', []))} files • Configured"
            else:
                desc = f"📦 Folder • {len(app_info.get('files', []))} files • Needs Configuration"
        else:
            desc = f"{app_info.get('framework', 'unknown')} • {app_info.get('status', 'unknown')}"
        
        desc_label = QLabel(desc)
        desc_label.setStyleSheet(f"color: {self.main_window.theme_manager.current_text_secondary}; font-size: 9px;")
        desc_label.setWordWrap(True)
        info_layout.addWidget(desc_label)
        
        layout.addLayout(info_layout)
        layout.addStretch()
        
        # Status and actions
        status_layout = QVBoxLayout()
        status_layout.setSpacing(2)
        
        status = app_info.get('status', 'unknown')
        if status == 'ready' or (app_info.get('type') == 'folder' and status == 'configured'):
            status_color = self.main_window.theme_manager.current_success
            status_text = "READY"
        elif status == 'error':
            status_color = self.main_window.theme_manager.current_error
            status_text = "ERROR"
        elif app_info.get('type') == 'folder' and status == 'unconfigured':
            status_color = self.main_window.theme_manager.current_warning
            status_text = "CONFIG"
        else:
            status_color = self.main_window.theme_manager.current_warning
            status_text = status.upper()
        
        status_label = QLabel(status_text)
        status_label.setStyleSheet(f"color: {status_color}; font-size: 9px; font-weight: bold;")
        status_layout.addWidget(status_label)
        
        # Action buttons
        action_layout = QHBoxLayout()
        
        if status == 'ready' or (app_info.get('type') == 'folder' and status == 'configured'):
            launch_btn = QPushButton("Launch")
            launch_btn.setFixedSize(50, 20)
            launch_btn.setStyleSheet(self.get_small_button_style())
            launch_btn.clicked.connect(lambda checked, name=app_name: self.launch_app(name))
            action_layout.addWidget(launch_btn)
        
        if app_info.get('type') == 'folder' and status == 'unconfigured':
            config_btn = QPushButton("Config")
            config_btn.setFixedSize(50, 20)
            config_btn.setStyleSheet(self.get_small_button_style())
            config_btn.clicked.connect(lambda checked, name=app_name: self.configure_folder(name))
            action_layout.addWidget(config_btn)
        
        trust_btn = QPushButton("Trust")
        trust_btn.setFixedSize(45, 20)
        trust_btn.setStyleSheet(self.get_small_button_style())
        trust_btn.clicked.connect(lambda checked, name=app_name: self.manage_app_trust(name))
        action_layout.addWidget(trust_btn)
        
        group_btn = QPushButton("Group")
        group_btn.setFixedSize(50, 20)
        group_btn.setStyleSheet(self.get_small_button_style())
        group_btn.clicked.connect(lambda checked, name=app_name: self.manage_app_groups(name))
        action_layout.addWidget(group_btn)
        
        # Default app toggle button
        default_btn_text = "⭐" if is_default_app else "☆"
        default_btn = QPushButton(default_btn_text)
        default_btn.setFixedSize(30, 20)
        default_btn.setStyleSheet(self.get_small_button_style())
        default_btn.clicked.connect(lambda checked, name=app_name: self.toggle_default_app(name))
        action_layout.addWidget(default_btn)
        
        status_layout.addLayout(action_layout)
        layout.addLayout(status_layout)
        
        return widget
    
    def toggle_default_app(self, app_name):
        """Toggle an app as default/non-default"""
        if self.default_apps_manager.is_default_app(app_name):
            # Remove from default apps with confirmation
            reply = QMessageBox.question(
                self, 
                "Remove Default App", 
                f"Are you sure you want to remove '{app_name}' from default apps?\n\n"
                f"This app may be important to the system or may have been added during an update.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No  # Default to No for safety
            )
            
            if reply == QMessageBox.Yes:
                if self.default_apps_manager.remove_default_app(app_name):
                    self.main_window.debug_logger.log("info", f"Removed {app_name} from default apps", "default_apps")
                    self.update_apps_display()
        else:
            # Add to default apps
            if self.default_apps_manager.add_default_app(app_name):
                self.main_window.debug_logger.log("info", f"Added {app_name} to default apps", "default_apps")
                self.update_apps_display()
    
    def configure_folder(self, app_name):
        """Configure a folder application"""
        try:
            app_info = self.main_window.window_manager.available_windows.get(app_name)
            if app_info and app_info.get('type') == 'folder':
                folder_path = app_info.get('folder_path')
                if folder_path and os.path.exists(folder_path):
                    dialog = FolderConfigurationDialog(folder_path, self)
                    if dialog.exec_() == QDialog.Accepted:
                        config = dialog.get_configuration()
                        # Save the configuration
                        self.main_window.window_manager.scanner.save_folder_configuration(app_name, config)
                        # Update the app info
                        app_info.update({
                            "status": "configured",
                            "main_file": config['executable_path'],
                            "security_level": self.main_window.window_manager.scanner.analyze_security_file(config['executable_path'])
                        })
                        self.update_apps_display()
                        self.main_window.debug_logger.log("info", f"Configured folder application: {app_name}", "launcher", config)
                        QMessageBox.information(self, "Configuration Saved", f"Folder '{app_name}' has been configured successfully.")
                else:
                    QMessageBox.warning(self, "Error", f"Folder not found: {folder_path}")
            else:
                QMessageBox.warning(self, "Error", f"Application not found or not a folder: {app_name}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to configure folder: {str(e)}")
            self.main_window.debug_logger.log_error(f"Failed to configure folder {app_name}", {"error": str(e)}, app_name)
    
    def manage_app_trust(self, app_name):
        """Manage trust level for an app"""
        dialog = AppTrustDialog(self, app_name, self.main_window.trust_system)
        dialog.trust_level_changed.connect(self.update_apps_display)
        dialog.exec_()
    
    def create_new_group(self):
        """Create a new app group"""
        name, ok = QInputDialog.getText(self, "New Group", "Enter group name:")
        if ok and name:
            group_id = f"group_{int(time.time())}"
            self.group_manager.create_group(group_id, name)
            self.update_groups_display()
            self.main_window.debug_logger.log("info", f"Created new app group: {name}", "groups")
    
    def manage_groups(self):
        """Open group management dialog"""
        dialog = GroupManagementDialog(self, self.group_manager)
        dialog.groups_updated.connect(self.update_groups_display)
        dialog.exec_()
    
    def manage_app_groups(self, app_name):
        """Manage groups for an app"""
        dialog = AppGroupDialog(self, app_name, self.group_manager)
        dialog.exec_()
        self.update_apps_display()
    
    def launch_app(self, app_name):
        """Launch an application"""
        try:
            app_info = self.main_window.window_manager.available_windows.get(app_name)
            if app_info:
                app_type = app_info.get('type', 'file')
                
                if app_type == 'file':
                    # Single file application
                    file_path = app_info.get('file_path')
                    if file_path and os.path.exists(file_path):
                        success, message = self.main_window.window_manager.window_manager.launch_python_app(file_path, app_name)
                        if success:
                            QMessageBox.information(self, "Success", f"Launched {app_name}")
                            self.main_window.debug_logger.log("info", f"Launched application: {app_name}", "launcher")
                        else:
                            QMessageBox.warning(self, "Launch Failed", message)
                    else:
                        QMessageBox.warning(self, "Error", f"Application file not found: {file_path}")
                
                elif app_type == 'folder':
                    # Folder-based application
                    if app_info.get('status') == 'configured':
                        executable_path = app_info.get('main_file')
                        folder_name = app_info.get('folder_path', app_name)
                        if executable_path and os.path.exists(executable_path):
                            success, message = self.main_window.window_manager.window_manager.launch_folder_app(
                                os.path.basename(folder_name), 
                                executable_path, 
                                app_name
                            )
                            if success:
                                # Don't show message for folder apps - loading window handles it
                                self.main_window.debug_logger.log("info", f"Launched folder application: {app_name}", "launcher")
                            else:
                                QMessageBox.warning(self, "Launch Failed", message)
                        else:
                            QMessageBox.warning(self, "Error", f"Executable file not found: {executable_path}")
                    else:
                        QMessageBox.warning(self, "Not Configured", f"Please configure the folder '{app_name}' before launching.")
            else:
                QMessageBox.warning(self, "Error", f"Application not found: {app_name}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to launch {app_name}: {str(e)}")
            self.main_window.debug_logger.log_error(f"Failed to launch {app_name}", {"error": str(e)}, app_name)
    
    def get_header_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            color: {css_vars['accent']};
            background-color: {css_vars['secondary']};
            padding: 8px;
            border: 1px solid {css_vars['border']};
            border-radius: {css_vars['border_radius']};
            font-size: 12px;
        """
    
    def get_combo_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            QComboBox {{
                background-color: {css_vars['tertiary']};
                color: {css_vars['text']};
                border: 1px solid {css_vars['border']};
                border-radius: {css_vars['button_radius']};
                padding: 2px 5px;
                font-size: 10px;
            }}
        """
    
    def get_input_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            QLineEdit {{
                background-color: {css_vars['tertiary']};
                color: {css_vars['text']};
                border: 1px solid {css_vars['border']};
                border-radius: {css_vars['button_radius']};
                padding: 3px 5px;
                font-size: 10px;
            }}
        """
    
    def get_small_button_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            QPushButton {{
                background-color: {css_vars['tertiary']};
                color: {css_vars['text']};
                border: 1px solid {css_vars['border']};
                border-radius: {css_vars['button_radius']};
                padding: 1px 3px;
                font-size: 9px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {css_vars['accent']};
                color: {css_vars['primary']};
            }}
        """
    
    def get_app_widget_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            QFrame {{
                background-color: {css_vars['secondary']};
                border: 1px solid {css_vars['border']};
                border-radius: {css_vars['border_radius']};
            }}
            QFrame:hover {{
                border: 1px solid {css_vars['accent']};
                background-color: {css_vars['highlight']};
            }}
        """
    
    def get_default_app_widget_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            QFrame {{
                background-color: {css_vars['secondary']};
                border: 2px solid {css_vars['accent']};
                border-radius: {css_vars['border_radius']};
            }}
            QFrame:hover {{
                border: 2px solid {css_vars['accent_secondary']};
                background-color: {css_vars['highlight']};
            }}
        """

# ========================================
# DIALOG CLASSES (AppTrustDialog, GroupManagementDialog, AppGroupDialog)
# ========================================
class AppTrustDialog(QDialog):
    """Dialog for managing app trust levels"""
    
    trust_level_changed = pyqtSignal()
    
    def __init__(self, parent, app_name, trust_system):
        super().__init__(parent)
        self.app_name = app_name
        self.trust_system = trust_system
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle(f"Manage Trust Level - {self.app_name}")
        self.setFixedSize(350, 200)
        
        layout = QVBoxLayout(self)
        
        # Current trust status
        current_trust = self.trust_system.get_user_trust_level(self.app_name)
        if current_trust:
            status_text = f"Current Trust Level: {current_trust.title()} (User Set)"
            status_color = self.parent().main_window.theme_manager.current_success
        else:
            # Get auto-detected trust level
            wm = self.parent().main_window.window_manager
            app_info = wm.available_windows.get(self.app_name, {})
            auto_trust = app_info.get('security_level', 'unknown')
            status_text = f"Current Trust Level: {auto_trust.title()} (Auto-detected)"
            if auto_trust == "trusted":
                status_color = self.parent().main_window.theme_manager.current_success
            elif auto_trust == "moderate":
                status_color = self.parent().main_window.theme_manager.current_warning
            else:
                status_color = self.parent().main_window.theme_manager.current_error
        
        status_label = QLabel(status_text)
        status_label.setStyleSheet(f"color: {status_color}; font-weight: bold; padding: 10px;")
        layout.addWidget(status_label)
        
        # Trust level selection
        layout.addWidget(QLabel("Set Trust Level:"))
        
        self.trust_combo = QComboBox()
        self.trust_combo.addItems(["Trusted", "Moderate", "Untrusted", "Auto (Use System Detection)"])
        if current_trust:
            self.trust_combo.setCurrentText(current_trust.title())
        else:
            self.trust_combo.setCurrentText("Auto (Use System Detection)")
        layout.addWidget(self.trust_combo)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        set_btn = QPushButton("Set Trust Level")
        set_btn.clicked.connect(self.set_trust_level)
        button_layout.addWidget(set_btn)
        
        clear_btn = QPushButton("Clear User Setting")
        clear_btn.clicked.connect(self.clear_trust_level)
        button_layout.addWidget(clear_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
    
    def set_trust_level(self):
        """Set user-defined trust level"""
        trust_level = self.trust_combo.currentText()
        if trust_level == "Auto (Use System Detection)":
            # Clear user override
            if self.app_name in self.trust_system.user_trust_overrides:
                del self.trust_system.user_trust_overrides[self.app_name]
                self.trust_system.save_user_trust_overrides()
        else:
            # Set user override
            self.trust_system.set_user_trust_level(self.app_name, trust_level.lower())
        
        self.trust_level_changed.emit()
        self.accept()
    
    def clear_trust_level(self):
        """Clear user-defined trust level"""
        if self.app_name in self.trust_system.user_trust_overrides:
            del self.trust_system.user_trust_overrides[self.app_name]
            self.trust_system.save_user_trust_overrides()
            self.trust_level_changed.emit()
        
        self.accept()

class GroupManagementDialog(QDialog):
    """Dialog for managing groups (rename, delete, etc.)"""
    
    groups_updated = pyqtSignal()
    
    def __init__(self, parent, group_manager):
        super().__init__(parent)
        self.group_manager = group_manager
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("📁 Manage Groups")
        self.setFixedSize(400, 500)
        
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("Application Groups")
        header.setStyleSheet("font-weight: bold; font-size: 14px; margin-bottom: 10px;")
        layout.addWidget(header)
        
        # Groups list
        self.groups_list = QListWidget()
        self.groups_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.groups_list.customContextMenuRequested.connect(self.show_context_menu)
        layout.addWidget(self.groups_list)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        new_btn = QPushButton("New Group")
        new_btn.clicked.connect(self.create_group)
        button_layout.addWidget(new_btn)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        
        self.update_groups_list()
    
    def update_groups_list(self):
        """Update the groups list display"""
        self.groups_list.clear()
        for group_id, group_data in self.group_manager.get_all_groups().items():
            app_count = len(group_data["apps"])
            item_text = f"{group_data['name']} ({app_count} apps)"
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, group_id)
            self.groups_list.addItem(item)
    
    def show_context_menu(self, position):
        """Show context menu for group operations"""
        item = self.groups_list.itemAt(position)
        if not item:
            return
        
        group_id = item.data(Qt.UserRole)
        group_name = self.group_manager.groups[group_id]["name"]
        
        menu = QMenu(self)
        
        rename_action = QAction("Rename Group", self)
        rename_action.triggered.connect(lambda: self.rename_group(group_id, group_name))
        menu.addAction(rename_action)
        
        delete_action = QAction("Delete Group", self)
        delete_action.triggered.connect(lambda: self.delete_group(group_id, group_name))
        menu.addAction(delete_action)
        
        menu.exec_(self.groups_list.mapToGlobal(position))
    
    def create_group(self):
        """Create a new group"""
        name, ok = QInputDialog.getText(self, "New Group", "Enter group name:")
        if ok and name:
            group_id = f"group_{int(time.time())}"
            self.group_manager.create_group(group_id, name)
            self.update_groups_list()
            self.groups_updated.emit()
    
    def rename_group(self, group_id, current_name):
        """Rename a group"""
        new_name, ok = QInputDialog.getText(self, "Rename Group", "Enter new name:", text=current_name)
        if ok and new_name and new_name != current_name:
            if self.group_manager.rename_group(group_id, new_name):
                self.update_groups_list()
                self.groups_updated.emit()
    
    def delete_group(self, group_id, group_name):
        """Delete a group with confirmation"""
        reply = QMessageBox.question(
            self, 
            "Delete Group", 
            f"Are you sure you want to delete the group '{group_name}'? All apps in this group will be moved to the Default group.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            if self.group_manager.delete_group(group_id):
                self.update_groups_list()
                self.groups_updated.emit()
                QMessageBox.information(self, "Group Deleted", f"Group '{group_name}' has been deleted.")

class AppGroupDialog(QDialog):
    """Dialog for managing app groups"""
    
    def __init__(self, parent, app_name, group_manager):
        super().__init__(parent)
        self.app_name = app_name
        self.group_manager = group_manager
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle(f"Manage Groups for {self.app_name}")
        self.setFixedSize(300, 400)
        
        layout = QVBoxLayout(self)
        
        # Current groups
        layout.addWidget(QLabel("Current Groups:"))
        
        self.groups_list = QListWidget()
        layout.addWidget(self.groups_list)
        
        # Add to group
        add_layout = QHBoxLayout()
        self.add_combo = QComboBox()
        self.update_add_combo()
        add_layout.addWidget(self.add_combo)
        
        add_btn = QPushButton("Add")
        add_btn.clicked.connect(self.add_to_group)
        add_layout.addWidget(add_btn)
        
        layout.addLayout(add_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        remove_btn = QPushButton("Remove Selected")
        remove_btn.clicked.connect(self.remove_from_group)
        btn_layout.addWidget(remove_btn)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)
        
        self.update_groups_list()
    
    def update_add_combo(self):
        """Update add group combo"""
        self.add_combo.clear()
        for group_id, group_data in self.group_manager.groups.items():
            if self.app_name not in group_data["apps"]:
                self.add_combo.addItem(group_data["name"], group_id)
    
    def update_groups_list(self):
        """Update groups list"""
        self.groups_list.clear()
        for group_id, group_data in self.group_manager.groups.items():
            if self.app_name in group_data["apps"]:
                self.groups_list.addItem(f"{group_data['name']} ({group_id})")
    
    def add_to_group(self):
        """Add app to selected group"""
        group_id = self.add_combo.currentData()
        if group_id:
            self.group_manager.add_app_to_group(self.app_name, group_id)
            self.update_groups_list()
            self.update_add_combo()
    
    def remove_from_group(self):
        """Remove app from selected group"""
        current_item = self.groups_list.currentItem()
        if current_item:
            text = current_item.text()
            group_id = text.split('(')[-1].rstrip(')')
            self.group_manager.remove_app_from_group(self.app_name, group_id)
            self.update_groups_list()
            self.update_add_combo()

# ========================================
# DASHBOARD
# ========================================
class EnhancedCyberDashboardWidget(QWidget):
    """Optimized dashboard"""
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.init_ui()
        
        self.monitor_timer = QTimer()
        self.monitor_timer.timeout.connect(self.update_system_stats)
        self.monitor_timer.start(4000)
        
        self.update_system_stats()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        
        # Header
        header = QLabel("🔒 UIDOCK DASHBOARD")
        header.setFont(QFont("Courier New", 14, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet(self.get_header_style())
        layout.addWidget(header)
        
        # System Status Grid
        status_grid = QGridLayout()
        status_grid.setSpacing(6)
        status_grid.setContentsMargins(2, 2, 2, 2)
        
        metrics = [
            ("🖥️ Running", "running_apps", "0", self.main_window.theme_manager.current_accent),
            ("📊 Scanned", "total_scanned", "0", self.main_window.theme_manager.current_success),
            ("📁 Folders", "folder_apps", "0", self.main_window.theme_manager.current_warning),
            ("🛡️ Trusted", "trusted_apps", "0", self.main_window.theme_manager.current_success),
        ]
        
        row, col = 0, 0
        for label, key, value, color in metrics:
            metric_card = self.create_compact_metric_card(label, key, value, color)
            status_grid.addWidget(metric_card, row, col)
            col += 1
            if col > 1:
                col = 0
                row += 1
        
        layout.addLayout(status_grid)
        
        # Quick Actions
        actions_group = QGroupBox("🚀 Quick Actions")
        actions_group.setStyleSheet(self.get_group_style())
        actions_layout = QHBoxLayout(actions_group)
        actions_layout.setSpacing(6)
        
        actions = [
            ("📱 Apps", lambda: self.main_window.show_launcher_interface()),
            ("🐛 Debug", lambda: self.main_window.show_debugging_interface()),
            ("🛡️ Trust", lambda: self.main_window.show_trust_interface()),
            ("⚙️ Settings", lambda: self.main_window.show_security_interface()),
        ]
        
        for label, callback in actions:
            btn = QPushButton(label)
            btn.setFixedHeight(30)
            btn.setStyleSheet(self.get_action_button_style())
            btn.clicked.connect(callback)
            actions_layout.addWidget(btn)
        
        layout.addWidget(actions_group)
        
        # Security Status
        security_group = QGroupBox("🛡️ System Status")
        security_group.setStyleSheet(self.get_group_style())
        security_layout = QVBoxLayout(security_group)
        
        self.security_status = QLabel("System operational. All services running.")
        self.security_status.setStyleSheet(f"""
            color: {self.main_window.theme_manager.current_success}; 
            font-weight: bold; 
            font-family: 'Courier New';
            padding: 6px;
            background-color: {self.main_window.theme_manager.current_secondary};
            border-radius: 4px;
            border: 1px solid {self.main_window.theme_manager.current_border_light};
            font-size: 10px;
        """)
        security_layout.addWidget(self.security_status)
        
        layout.addWidget(security_group)
        
        layout.addStretch()
    
    def create_compact_metric_card(self, label, key, value, color):
        """Create a compact metric card"""
        css_vars = self.main_window.theme_manager.get_css_variables()
        card = QFrame()
        card.setFixedSize(110, 60)
        card.setStyleSheet(f"""
            QFrame {{
                background-color: {css_vars['secondary']};
                border: 1px solid {css_vars['border']};
                border-radius: {css_vars['border_radius']};
                padding: 5px;
            }}
        """)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(3, 3, 3, 3)
        card_layout.setSpacing(1)
        
        label_widget = QLabel(label)
        label_widget.setStyleSheet(f"color: {css_vars['text_secondary']}; font-size: 9px; font-family: 'Courier New';")
        label_widget.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(label_widget)
        
        value_widget = QLabel(value)
        value_widget.setFont(QFont("Courier New", 12, QFont.Bold))
        value_widget.setStyleSheet(f"color: {color};")
        value_widget.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(value_widget)
        
        setattr(self, f"{key}_label", value_widget)
        
        return card
    
    def update_system_stats(self):
        """Update system statistics based on actual application data"""
        try:
            wm = self.main_window.window_manager
            
            # Running applications
            running_count = wm.window_manager.get_running_count()
            self.running_apps_label.setText(str(running_count))
            
            # Application statistics
            total_scanned = len(wm.available_windows)
            self.total_scanned_label.setText(str(total_scanned))
            
            # Count folder applications
            folder_count = len([w for w in wm.available_windows.values() if w.get('type') == 'folder'])
            self.folder_apps_label.setText(str(folder_count))
            
            # Count trusted apps (including user-trusted)
            trusted_count = 0
            for app_name, app_info in wm.available_windows.items():
                user_trust = self.main_window.trust_system.get_user_trust_level(app_name)
                if user_trust == "trusted":
                    trusted_count += 1
                elif not user_trust and app_info.get('security_level') == 'trusted':
                    trusted_count += 1
                    
            self.trusted_apps_label.setText(str(trusted_count))
            
            # Update security status
            if running_count == 0:
                security_text = "System idle. No applications running."
                security_color = self.main_window.theme_manager.current_text_secondary
            else:
                security_text = "System operational. Services running normally."
                security_color = self.main_window.theme_manager.current_success
            
            self.security_status.setText(security_text)
            self.security_status.setStyleSheet(f"""
                color: {security_color}; 
                font-weight: bold; 
                font-family: 'Courier New';
                padding: 6px;
                background-color: {self.main_window.theme_manager.current_secondary};
                border-radius: 4px;
                border: 1px solid {security_color};
                font-size: 10px;
            """)
            
        except Exception as e:
            print(f"Error updating system stats: {e}")
    
    def get_header_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            color: {css_vars['accent']};
            background-color: {css_vars['secondary']};
            padding: 8px;
            border: 1px solid {css_vars['border']};
            border-radius: {css_vars['border_radius']};
            margin-bottom: 8px;
            font-size: 12px;
        """
    
    def get_group_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            QGroupBox {{
                color: {css_vars['accent']};
                font-weight: bold;
                border: 1px solid {css_vars['border']};
                border-radius: {css_vars['border_radius']};
                margin-top: 1ex;
                padding-top: 1ex;
                font-family: 'Courier New';
                background-color: {css_vars['secondary']};
                font-size: 10px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 8px;
                padding: 0 3px 0 3px;
                background-color: {css_vars['secondary']};
            }}
        """
    
    def get_action_button_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            QPushButton {{
                background-color: {css_vars['tertiary']};
                color: {css_vars['text']};
                border: 1px solid {css_vars['border']};
                border-radius: {css_vars['button_radius']};
                padding: 3px;
                font-weight: bold;
                font-family: 'Courier New';
                font-size: 10px;
            }}
            QPushButton:hover {{
                background-color: {css_vars['accent']};
                color: {css_vars['primary']};
                border: 1px solid {css_vars['accent']};
            }}
        """

# ========================================
# DEBUGGING INTERFACE
# ========================================
class EnhancedDebuggingWidget(QWidget):
    """Enhanced debugging and logging interface for UIDock"""
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.init_ui()
        
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_debug_info)
        self.update_timer.start(2000)
        
        self.update_debug_info()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        
        header = QLabel("🐛 UIDOCK DEBUG CONSOLE")
        header.setFont(QFont("Courier New", 14, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet(self.get_header_style())
        layout.addWidget(header)
        
        debug_tabs = QTabWidget()
        debug_tabs.setStyleSheet("""
            QTabBar::tab { 
                height: 22px; 
                font-size: 10px; 
                font-family: 'Courier New';
                font-weight: bold;
            }
            QTabWidget::pane {
                border: 1px solid #334455;
                border-radius: 4px;
            }
        """)
        
        # Create all tabs
        self.logs_tab = self.create_logs_tab()
        self.errors_tab = self.create_errors_tab()
        self.security_tab = self.create_security_tab()
        self.application_tab = self.create_application_tab()
        self.performance_tab = self.create_performance_tab()
        self.health_tab = self.create_health_tab()
        
        debug_tabs.addTab(self.logs_tab, "📝 All Logs")
        debug_tabs.addTab(self.errors_tab, "❌ Error Center")
        debug_tabs.addTab(self.security_tab, "🛡️ Security Hub")
        debug_tabs.addTab(self.application_tab, "📱 App Monitor")
        debug_tabs.addTab(self.performance_tab, "⚡ Performance")
        debug_tabs.addTab(self.health_tab, "❤️ Health")
        
        layout.addWidget(debug_tabs)
        
        # Actions
        actions_layout = QHBoxLayout()
        
        clear_logs_btn = QPushButton("🗑️ Clear All Logs")
        clear_logs_btn.setStyleSheet(self.get_button_style())
        clear_logs_btn.clicked.connect(self.clear_all_logs)
        actions_layout.addWidget(clear_logs_btn)
        
        export_btn = QPushButton("📤 Export Logs")
        export_btn.setStyleSheet(self.get_button_style())
        export_btn.clicked.connect(self.export_logs)
        actions_layout.addWidget(export_btn)
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.setStyleSheet(self.get_button_style())
        refresh_btn.clicked.connect(self.update_debug_info)
        actions_layout.addWidget(refresh_btn)
        
        layout.addLayout(actions_layout)
    
    def create_logs_tab(self):
        """Create comprehensive logs tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(3, 3, 3, 3)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Level:"))
        
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["All", "Error", "Warning", "Info", "Debug"])
        self.log_level_combo.currentTextChanged.connect(self.update_logs_display)
        filter_layout.addWidget(self.log_level_combo)
        
        filter_layout.addWidget(QLabel("Category:"))
        self.log_category_combo = QComboBox()
        self.log_category_combo.addItems(["All", "system", "scanner", "launcher", "trust_analysis", "security", "application", "performance"])
        self.log_category_combo.currentTextChanged.connect(self.update_logs_display)
        filter_layout.addWidget(self.log_category_combo)
        
        filter_layout.addStretch()
        
        self.log_limit_combo = QComboBox()
        self.log_limit_combo.addItems(["Last 50", "Last 100", "Last 500", "Last 1000"])
        self.log_limit_combo.currentTextChanged.connect(self.update_logs_display)
        filter_layout.addWidget(self.log_limit_combo)
        
        layout.addLayout(filter_layout)
        
        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        self.logs_text.setStyleSheet(self.get_text_edit_style())
        self.logs_text.setFont(QFont("Courier New", 8))
        layout.addWidget(self.logs_text)
        
        return widget
    
    def create_errors_tab(self):
        """Create enhanced error center tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(3, 3, 3, 3)
        
        # Error statistics
        stats_layout = QHBoxLayout()
        
        self.error_count_label = QLabel("Errors: 0")
        self.error_count_label.setStyleSheet(f"color: {self.main_window.theme_manager.current_error}; font-weight: bold;")
        stats_layout.addWidget(self.error_count_label)
        
        self.critical_count_label = QLabel("Critical: 0")
        self.critical_count_label.setStyleSheet("color: #ff4444; font-weight: bold;")
        stats_layout.addWidget(self.critical_count_label)
        
        self.last_error_label = QLabel("Last: Never")
        self.last_error_label.setStyleSheet(f"color: {self.main_window.theme_manager.current_text_secondary};")
        stats_layout.addWidget(self.last_error_label)
        
        stats_layout.addStretch()
        
        clear_errors_btn = QPushButton("Clear Errors")
        clear_errors_btn.setStyleSheet(self.get_small_button_style())
        clear_errors_btn.clicked.connect(lambda: self.main_window.debug_logger.clear_logs("error"))
        stats_layout.addWidget(clear_errors_btn)
        
        layout.addLayout(stats_layout)
        
        # Error details
        error_splitter = QSplitter(Qt.Vertical)
        
        # Error list
        self.error_list = QListWidget()
        self.error_list.itemClicked.connect(self.show_error_details)
        error_splitter.addWidget(self.error_list)
        
        # Error details
        self.error_details = QTextEdit()
        self.error_details.setReadOnly(True)
        self.error_details.setStyleSheet(self.get_text_edit_style())
        self.error_details.setFont(QFont("Courier New", 8))
        error_splitter.addWidget(self.error_details)
        
        error_splitter.setSizes([200, 300])
        layout.addWidget(error_splitter)
        
        return widget
    
    def create_security_tab(self):
        """Create enhanced security hub tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(3, 3, 3, 3)
        
        # Security overview
        overview_layout = QHBoxLayout()
        
        self.security_count_label = QLabel("Security Events: 0")
        self.security_count_label.setStyleSheet(f"color: {self.main_window.theme_manager.current_warning}; font-weight: bold;")
        overview_layout.addWidget(self.security_count_label)
        
        self.threat_level_label = QLabel("Threat Level: Low")
        self.threat_level_label.setStyleSheet("color: #00ff88; font-weight: bold;")
        overview_layout.addWidget(self.threat_level_label)
        
        self.last_security_label = QLabel("Last Event: Never")
        self.last_security_label.setStyleSheet(f"color: {self.main_window.theme_manager.current_text_secondary};")
        overview_layout.addWidget(self.last_security_label)
        
        overview_layout.addStretch()
        
        layout.addLayout(overview_layout)
        
        # Security events with categories
        security_splitter = QSplitter(Qt.Vertical)
        
        # Security event list
        self.security_list = QListWidget()
        self.security_list.itemClicked.connect(self.show_security_details)
        security_splitter.addWidget(self.security_list)
        
        # Security details
        self.security_details = QTextEdit()
        self.security_details.setReadOnly(True)
        self.security_details.setStyleSheet(self.get_text_edit_style())
        self.security_details.setFont(QFont("Courier New", 8))
        security_splitter.addWidget(self.security_details)
        
        security_splitter.setSizes([200, 300])
        layout.addWidget(security_splitter)
        
        return widget
    
    def create_application_tab(self):
        """Create enhanced application monitor tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(3, 3, 3, 3)
        
        # Application filter and stats
        app_header_layout = QHBoxLayout()
        
        app_header_layout.addWidget(QLabel("Application:"))
        self.app_filter_combo = QComboBox()
        self.app_filter_combo.addItems(["All Applications"])
        self.app_filter_combo.currentTextChanged.connect(self.update_application_logs)
        app_header_layout.addWidget(self.app_filter_combo)
        
        self.app_launch_count = QLabel("Launches: 0")
        self.app_launch_count.setStyleSheet(f"color: {self.main_window.theme_manager.current_success};")
        app_header_layout.addWidget(self.app_launch_count)
        
        self.app_error_count = QLabel("Errors: 0")
        self.app_error_count.setStyleSheet(f"color: {self.main_window.theme_manager.current_error};")
        app_header_layout.addWidget(self.app_error_count)
        
        app_header_layout.addStretch()
        
        layout.addLayout(app_header_layout)
        
        # Application logs with filtering
        app_filter_layout = QHBoxLayout()
        
        app_filter_layout.addWidget(QLabel("Log Level:"))
        self.app_log_level_combo = QComboBox()
        self.app_log_level_combo.addItems(["All", "Error", "Warning", "Info"])
        self.app_log_level_combo.currentTextChanged.connect(self.update_application_logs)
        app_filter_layout.addWidget(self.app_log_level_combo)
        
        app_filter_layout.addStretch()
        
        self.app_log_limit_combo = QComboBox()
        self.app_log_limit_combo.addItems(["Last 50", "Last 100", "Last 200"])
        self.app_log_limit_combo.currentTextChanged.connect(self.update_application_logs)
        app_filter_layout.addWidget(self.app_log_limit_combo)
        
        layout.addLayout(app_filter_layout)
        
        self.application_text = QTextEdit()
        self.application_text.setReadOnly(True)
        self.application_text.setStyleSheet(self.get_text_edit_style())
        self.application_text.setFont(QFont("Courier New", 8))
        layout.addWidget(self.application_text)
        
        return widget
    
    def create_performance_tab(self):
        """Create performance monitoring tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(3, 3, 3, 3)
        
        self.performance_text = QTextEdit()
        self.performance_text.setReadOnly(True)
        self.performance_text.setStyleSheet(self.get_text_edit_style())
        self.performance_text.setFont(QFont("Courier New", 9))
        layout.addWidget(self.performance_text)
        
        return widget
    
    def create_health_tab(self):
        """Create system health monitoring tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(3, 3, 3, 3)
        
        self.health_text = QTextEdit()
        self.health_text.setReadOnly(True)
        self.health_text.setStyleSheet(self.get_text_edit_style())
        self.health_text.setFont(QFont("Courier New", 9))
        layout.addWidget(self.health_text)
        
        return widget
    
    def update_debug_info(self):
        """Update all debugging information"""
        self.update_logs_display()
        self.update_errors_display()
        self.update_security_display()
        self.update_application_logs()
        self.update_performance_display()
        self.update_health_display()
        self.update_app_filter()
    
    def update_app_filter(self):
        """Update application filter combo"""
        current = self.app_filter_combo.currentText()
        self.app_filter_combo.clear()
        self.app_filter_combo.addItem("All Applications")
        
        # Get unique application names from logs
        app_names = set()
        for log in self.main_window.debug_logger.application_logs:
            app_name = log.get('app_name')
            if app_name:
                app_names.add(app_name)
        
        for app_name in sorted(app_names):
            self.app_filter_combo.addItem(app_name)
        
        # Restore selection if possible
        index = self.app_filter_combo.findText(current)
        if index >= 0:
            self.app_filter_combo.setCurrentIndex(index)
    
    def update_logs_display(self):
        """Update comprehensive logs display"""
        try:
            level_filter = self.log_level_combo.currentText().lower()
            category_filter = self.log_category_combo.currentText().lower()
            limit_text = self.log_limit_combo.currentText()
            limit = int(limit_text.split()[1])  # Extract number from "Last X"
            
            logs = self.main_window.debug_logger.logs
            
            # Apply filters
            if level_filter != "all":
                logs = [log for log in logs if log["level"] == level_filter]
            
            if category_filter != "all":
                logs = [log for log in logs if log.get("category") == category_filter]
            
            recent_logs = logs[-limit:]
            
            self.logs_text.clear()
            for log in recent_logs:
                timestamp = datetime.fromisoformat(log["timestamp"]).strftime("%H:%M:%S")
                level = log["level"].upper()
                category = log.get("category", "unknown")
                message = log["message"]
                app_name = log.get("app_name", "")
                
                if app_name:
                    app_info = f" [{app_name}]"
                else:
                    app_info = ""
                
                if level == "ERROR":
                    color = self.main_window.theme_manager.current_error
                elif level == "WARNING":
                    color = self.main_window.theme_manager.current_warning
                elif level == "DEBUG":
                    color = self.main_window.theme_manager.current_text_secondary
                else:
                    color = self.main_window.theme_manager.current_text
                
                log_line = f"[{timestamp}] {level}:{app_info} [{category}] {message}"
                
                self.logs_text.setTextColor(QColor(color))
                self.logs_text.append(log_line)
            
            self.scroll_to_bottom(self.logs_text)
            
        except Exception as e:
            self.logs_text.setPlainText(f"Error updating logs: {e}")
    
    def update_errors_display(self):
        """Update enhanced error center display"""
        try:
            errors = self.main_window.debug_logger.error_logs
            
            # Update error statistics
            total_errors = len(errors)
            critical_errors = len([e for e in errors if "critical" in e.get('message', '').lower()])
            
            self.error_count_label.setText(f"Errors: {total_errors}")
            self.critical_count_label.setText(f"Critical: {critical_errors}")
            
            if errors:
                last_error = errors[-1]
                last_time = datetime.fromisoformat(last_error["timestamp"]).strftime("%H:%M:%S")
                self.last_error_label.setText(f"Last: {last_time}")
            else:
                self.last_error_label.setText("Last: Never")
            
            # Update error list
            self.error_list.clear()
            for error in errors[-100:]:  # Last 100 errors
                timestamp = datetime.fromisoformat(error["timestamp"]).strftime("%H:%M:%S")
                message = error["message"][:100] + "..." if len(error["message"]) > 100 else error["message"]
                app_name = error.get("app_name", "System")
                
                item_text = f"[{timestamp}] {app_name}: {message}"
                item = QListWidgetItem(item_text)
                
                # Color code based on severity
                if "critical" in error.get('message', '').lower():
                    item.setBackground(QColor("#ff4444"))
                    item.setForeground(QColor("#ffffff"))
                elif "warning" in error.get('message', '').lower():
                    item.setBackground(QColor(self.main_window.theme_manager.current_warning))
                else:
                    item.setBackground(QColor(self.main_window.theme_manager.current_error))
                    item.setForeground(QColor("#ffffff"))
                
                item.setData(Qt.UserRole, error)
                self.error_list.addItem(item)
            
            self.error_list.scrollToBottom()
            
        except Exception as e:
            self.error_details.setPlainText(f"Error updating error display: {e}")
    
    def show_error_details(self, item):
        """Show detailed error information"""
        error_data = item.data(Qt.UserRole)
        if error_data:
            details_text = f"""
ERROR DETAILS
=============

Time: {datetime.fromisoformat(error_data['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}
Application: {error_data.get('app_name', 'System')}
Category: {error_data.get('category', 'unknown')}

Message:
{error_data['message']}

Details:
{error_data.get('details', 'No additional details')}

Stack Trace:
{error_data.get('stack_trace', 'No stack trace available')}
            """.strip()
            
            self.error_details.setPlainText(details_text)
    
    def update_security_display(self):
        """Update enhanced security hub display"""
        try:
            security_logs = self.main_window.debug_logger.security_logs
            
            # Update security statistics
            total_events = len(security_logs)
            
            # Calculate threat level
            recent_events = [log for log in security_logs 
                           if datetime.fromisoformat(log["timestamp"]).timestamp() > time.time() - 3600]  # Last hour
            
            threat_level = "Low"
            if len(recent_events) > 10:
                threat_level = "Critical"
            elif len(recent_events) > 5:
                threat_level = "High"
            elif len(recent_events) > 2:
                threat_level = "Medium"
            
            self.security_count_label.setText(f"Security Events: {total_events}")
            self.threat_level_label.setText(f"Threat Level: {threat_level}")
            
            # Color code threat level
            if threat_level == "Critical":
                self.threat_level_label.setStyleSheet("color: #ff4444; font-weight: bold;")
            elif threat_level == "High":
                self.threat_level_label.setStyleSheet("color: #ffaa00; font-weight: bold;")
            elif threat_level == "Medium":
                self.threat_level_label.setStyleSheet("color: #ffff00; font-weight: bold;")
            else:
                self.threat_level_label.setStyleSheet("color: #00ff88; font-weight: bold;")
            
            if security_logs:
                last_event = security_logs[-1]
                last_time = datetime.fromisoformat(last_event["timestamp"]).strftime("%H:%M:%S")
                self.last_security_label.setText(f"Last Event: {last_time}")
            else:
                self.last_security_label.setText("Last Event: Never")
            
            # Update security event list
            self.security_list.clear()
            for log in security_logs[-50:]:  # Last 50 security events
                timestamp = datetime.fromisoformat(log["timestamp"]).strftime("%H:%M:%S")
                message = log["message"][:80] + "..." if len(log["message"]) > 80 else log["message"]
                app_name = log.get("app_name", "System")
                
                item_text = f"[{timestamp}] {app_name}: {message}"
                item = QListWidgetItem(item_text)
                
                # Color code based on event type
                if "terminat" in log.get('message', '').lower() or "force" in log.get('message', '').lower():
                    item.setBackground(QColor("#ff4444"))
                    item.setForeground(QColor("#ffffff"))
                elif "warning" in log.get('message', '').lower():
                    item.setBackground(QColor(self.main_window.theme_manager.current_warning))
                else:
                    item.setBackground(QColor("#ffaa00"))
                
                item.setData(Qt.UserRole, log)
                self.security_list.addItem(item)
            
            self.security_list.scrollToBottom()
            
        except Exception as e:
            self.security_details.setPlainText(f"Error updating security display: {e}")
    
    def show_security_details(self, item):
        """Show detailed security event information"""
        security_data = item.data(Qt.UserRole)
        if security_data:
            details_text = f"""
SECURITY EVENT DETAILS
======================

Time: {datetime.fromisoformat(security_data['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}
Application: {security_data.get('app_name', 'System')}
Level: {security_data.get('level', 'warning').upper()}

Event:
{security_data['message']}

Details:
{security_data.get('details', 'No additional details')}
            """.strip()
            
            self.security_details.setPlainText(details_text)
    
    def update_application_logs(self):
        """Update enhanced application monitor display"""
        try:
            app_filter = self.app_filter_combo.currentText()
            level_filter = self.app_log_level_combo.currentText().lower()
            limit_text = self.app_log_limit_combo.currentText()
            limit = int(limit_text.split()[1])
            
            app_logs = self.main_window.debug_logger.application_logs
            
            # Apply filters
            if app_filter != "All Applications":
                app_logs = [log for log in app_logs if log.get('app_name') == app_filter]
            
            if level_filter != "all":
                app_logs = [log for log in app_logs if log['level'] == level_filter]
            
            recent_logs = app_logs[-limit:]
            
            # Update application statistics
            if app_filter != "All Applications":
                app_specific_logs = [log for log in self.main_window.debug_logger.application_logs 
                                   if log.get('app_name') == app_filter]
                launches = len([log for log in app_specific_logs if 'launch' in log.get('message', '').lower()])
                errors = len([log for log in app_specific_logs if log['level'] == 'error'])
                
                self.app_launch_count.setText(f"Launches: {launches}")
                self.app_error_count.setText(f"Errors: {errors}")
            else:
                self.app_launch_count.setText("Launches: -")
                self.app_error_count.setText("Errors: -")
            
            # Display logs
            self.application_text.clear()
            for log in recent_logs:
                timestamp = datetime.fromisoformat(log["timestamp"]).strftime("%H:%M:%S")
                level = log["level"].upper()
                message = log["message"]
                details = log.get("details", "")
                
                log_text = f"[{timestamp}] {level}: {message}"
                if details:
                    log_text += f"\n   Details: {details}"
                
                if level == "ERROR":
                    color = self.main_window.theme_manager.current_error
                elif level == "WARNING":
                    color = self.main_window.theme_manager.current_warning
                else:
                    color = self.main_window.theme_manager.current_success
                
                self.application_text.setTextColor(QColor(color))
                self.application_text.append(log_text + "\n")
            
            self.scroll_to_bottom(self.application_text)
            
        except Exception as e:
            self.application_text.setPlainText(f"Error updating application logs: {e}")
    
    def update_performance_display(self):
        """Update performance monitoring display"""
        try:
            wm = self.main_window.window_manager
            perf_stats = wm.window_manager.get_performance_stats()
            active_windows = wm.window_manager.get_active_windows()
            
            performance_text = f"""
UIDock Performance Statistics
=============================

Application Launches:
  Total: {perf_stats['total_launches']}
  Successful: {perf_stats['successful_launches']}
  Failed: {perf_stats['failed_launches']}
  Success Rate: {(perf_stats['successful_launches']/perf_stats['total_launches']*100) if perf_stats['total_launches'] > 0 else 100:.1f}%
  Average Runtime: {perf_stats['average_runtime']:.2f}s

System Resources:
  CPU Usage: {psutil.cpu_percent()}%
  Memory Usage: {psutil.virtual_memory().percent}%
  Available Memory: {psutil.virtual_memory().available / 1024 / 1024:.0f} MB

Currently Running Applications:
""".strip()
            
            if active_windows:
                for app_name, app_info in active_windows.items():
                    start_time = datetime.fromisoformat(app_info['start_time'])
                    runtime = (datetime.now() - start_time).total_seconds()
                    resource_usage = app_info.get('resource_usage', {})
                    
                    performance_text += f"\n  📱 {app_name}:"
                    performance_text += f"\n    Runtime: {runtime:.1f}s"
                    performance_text += f"\n    CPU: {resource_usage.get('cpu_percent', 0):.1f}%"
                    performance_text += f"\n    Memory: {resource_usage.get('memory_mb', 0):.1f} MB"
                    performance_text += f"\n    Threads: {resource_usage.get('threads', 0)}"
                    performance_text += f"\n    PID: {app_info.get('pid', 'N/A')}"
            else:
                performance_text += "\n\n  No applications currently running"
            
            self.performance_text.setPlainText(performance_text)
            
        except Exception as e:
            self.performance_text.setPlainText(f"Error updating performance: {e}")
    
    def update_health_display(self):
        """Update comprehensive system health display"""
        try:
            health_report = self.main_window.debug_logger.get_health_report()
            log_summary = self.main_window.debug_logger.get_log_summary()
            
            health_text = f"""
UIDock System Health Report
===========================

Overall Status: {health_report['system_health'].upper()}
Last Check: {health_report['last_check'][11:19]}
Errors (Last Hour): {health_report['errors_last_hour']}

System Metrics:
---------------
Total Logs: {log_summary['total_logs']}
Errors: {log_summary['errors']}
Security Events: {log_summary['security_entries']}
Debug Entries: {log_summary['debug_entries']}
Application Logs: {log_summary['application_entries']}

Application Health:
-------------------
""".strip()
            
            if health_report['application_stats']:
                for app_name, stats in health_report['application_stats'].items():
                    health_status = "✅ Healthy" if stats['errors'] == 0 else "⚠️ Issues" if stats['errors'] < 3 else "❌ Unhealthy"
                    health_text += f"\n{app_name}:"
                    health_text += f"\n  Status: {health_status}"
                    health_text += f"\n  Launches: {stats['launches']}"
                    health_text += f"\n  Errors: {stats['errors']}"
                    health_text += f"\n  Last Activity: {stats['last_activity'][11:19]}"
            else:
                health_text += "\nNo application activity recorded"
            
            # Add recommendations
            health_text += "\n\nRecommendations:"
            if health_report['errors_last_hour'] > 5:
                health_text += "\n⚠️  High error rate detected - review error logs"
            if log_summary['security_entries'] > 0:
                health_text += f"\n🛡️  {log_summary['security_entries']} security events need attention"
            if health_report['system_health'] == 'optimal':
                health_text += "\n✅ System operating normally"
            
            self.health_text.setPlainText(health_text)
            
        except Exception as e:
            self.health_text.setPlainText(f"Error updating health display: {e}")
    
    def scroll_to_bottom(self, text_widget):
        """Scroll text widget to bottom"""
        cursor = text_widget.textCursor()
        cursor.movePosition(QTextCursor.End)
        text_widget.setTextCursor(cursor)
    
    def clear_all_logs(self):
        """Clear all logs with confirmation"""
        reply = QMessageBox.question(self, "Clear Logs", 
                                   "Are you sure you want to clear ALL logs? This action cannot be undone.",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.main_window.debug_logger.clear_logs("all")
            self.update_debug_info()
            QMessageBox.information(self, "Logs Cleared", "All logs have been cleared.")
    
    def export_logs(self):
        """Export logs to file"""
        success, result = self.main_window.debug_logger.export_logs()
        if success:
            QMessageBox.information(self, "Export Successful", f"Logs exported to: {result}")
        else:
            QMessageBox.critical(self, "Export Failed", f"Failed to export logs: {result}")
    
    def get_header_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            color: {css_vars['accent']};
            background-color: {css_vars['secondary']};
            padding: 8px;
            border: 1px solid {css_vars['border']};
            border-radius: {css_vars['border_radius']};
            margin-bottom: 8px;
            font-size: 12px;
        """
    
    def get_button_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            QPushButton {{
                background-color: {css_vars['tertiary']};
                color: {css_vars['text']};
                border: 1px solid {css_vars['border']};
                border-radius: {css_vars['button_radius']};
                padding: 4px 8px;
                font-weight: bold;
                font-family: 'Courier New';
                font-size: 10px;
            }}
            QPushButton:hover {{
                background-color: {css_vars['accent']};
                color: {css_vars['primary']};
                border: 1px solid {css_vars['accent']};
            }}
        """
    
    def get_small_button_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            QPushButton {{
                background-color: {css_vars['tertiary']};
                color: {css_vars['text']};
                border: 1px solid {css_vars['border']};
                border-radius: {css_vars['button_radius']};
                padding: 2px 6px;
                font-weight: bold;
                font-family: 'Courier New';
                font-size: 9px;
            }}
            QPushButton:hover {{
                background-color: {css_vars['accent']};
                color: {css_vars['primary']};
            }}
        """
    
    def get_text_edit_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            QTextEdit {{
                background-color: {css_vars['secondary']};
                color: {css_vars['text']};
                border: 1px solid {css_vars['border']};
                border-radius: {css_vars['border_radius']};
                font-family: 'Courier New';
                font-size: 9px;
            }}
        """

# ========================================
# OPTIMIZED TRUST ANALYSIS INTERFACE
# ========================================
class EnhancedTrustAnalysisWidget(QWidget):
    """Optimized trust analysis interface with consistent trust levels"""
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.init_ui()
        
        self.update_trust_display()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        
        # Header
        header = QLabel("🛡️ TRUST ANALYSIS")
        header.setFont(QFont("Courier New", 14, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet(self.get_header_style())
        layout.addWidget(header)
        
        # Application Trust Overview
        overview_group = QGroupBox("📊 Trust Overview")
        overview_group.setStyleSheet(self.get_group_style())
        overview_layout = QVBoxLayout(overview_group)
        
        self.overview_text = QTextEdit()
        self.overview_text.setMaximumHeight(80)
        self.overview_text.setReadOnly(True)
        self.overview_text.setStyleSheet(self.get_text_edit_style())
        overview_layout.addWidget(self.overview_text)
        
        layout.addWidget(overview_group)
        
        # Detailed Trust Analysis
        analysis_group = QGroupBox("🔍 Application Analysis")
        analysis_group.setStyleSheet(self.get_group_style())
        analysis_layout = QVBoxLayout(analysis_group)
        
        self.analysis_tree = QTreeWidget()
        self.analysis_tree.setHeaderLabels(["Application", "Type", "Trust", "Score", "User Set", "Status"])
        self.analysis_tree.setStyleSheet(self.get_tree_style())
        self.analysis_tree.setMaximumHeight(150)
        self.analysis_tree.itemDoubleClicked.connect(self.on_app_double_click)
        analysis_layout.addWidget(self.analysis_tree)
        
        layout.addWidget(analysis_group)
        
        # Analysis Actions
        actions_layout = QHBoxLayout()
        
        analyze_btn = QPushButton("🔍 Analyze All")
        analyze_btn.setStyleSheet(self.get_button_style())
        analyze_btn.clicked.connect(self.analyze_all_applications)
        actions_layout.addWidget(analyze_btn)
        
        set_trust_btn = QPushButton("🔒 Set Trust Level")
        set_trust_btn.setStyleSheet(self.get_button_style())
        set_trust_btn.clicked.connect(self.set_app_trust_level)
        actions_layout.addWidget(set_trust_btn)
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.setStyleSheet(self.get_button_style())
        refresh_btn.clicked.connect(self.update_trust_display)
        actions_layout.addWidget(refresh_btn)
        
        layout.addLayout(actions_layout)
        
        layout.addStretch()
    
    def update_trust_display(self):
        """Update trust analysis display with consistent trust levels"""
        self.update_overview()
        self.update_analysis_tree()
    
    def update_overview(self):
        """Update trust overview with consistent counting"""
        try:
            wm = self.main_window.window_manager
            apps = wm.available_windows
            
            # Count different trust levels - USE THE SAME LOGIC AS LAUNCHER
            trusted_count = 0
            moderate_count = 0
            untrusted_count = 0
            user_trusted_count = 0
            folder_count = 0
            file_count = 0
            
            for app_name, app_info in apps.items():
                app_type = app_info.get('type', 'file')
                if app_type == 'folder':
                    folder_count += 1
                else:
                    file_count += 1
                    
                # Use the SAME trust level determination as the launcher
                display_trust_level = self.get_app_display_trust_level(app_name, app_info)
                
                if display_trust_level == "trusted":
                    trusted_count += 1
                elif display_trust_level == "moderate":
                    moderate_count += 1
                elif display_trust_level == "untrusted":
                    untrusted_count += 1
                
                # Count user overrides separately
                if self.main_window.trust_system.get_user_trust_level(app_name):
                    user_trusted_count += 1
            
            total_apps = len(apps)
            
            overview_text = f"""
Applications: {total_apps} ({file_count} files, {folder_count} folders)
Trusted: {trusted_count} ({trusted_count/total_apps*100 if total_apps > 0 else 0:.1f}%)
Moderate: {moderate_count} ({moderate_count/total_apps*100 if total_apps > 0 else 0:.1f}%)
Untrusted: {untrusted_count} ({untrusted_count/total_apps*100 if total_apps > 0 else 0:.1f}%)
User Overrides: {user_trusted_count}
            """.strip()
            
            self.overview_text.setPlainText(overview_text)
            
        except Exception as e:
            self.overview_text.setPlainText(f"Error: {e}")
    
    def get_app_display_trust_level(self, app_name, app_info):
        """Get the trust level to display for an app (user override or auto-detected) - SAME AS LAUNCHER"""
        user_trust = self.main_window.trust_system.get_user_trust_level(app_name)
        if user_trust:
            return user_trust
        else:
            # Use the ACTUAL security level from the app info (not re-analyzing)
            return app_info.get('security_level', 'unknown')
    
    def update_analysis_tree(self):
        """Update the analysis tree with consistent trust levels"""
        try:
            self.analysis_tree.clear()
            wm = self.main_window.window_manager
            
            for app_name, app_info in wm.available_windows.items():
                # Use the SAME trust level determination as everywhere else
                display_trust_level = self.get_app_display_trust_level(app_name, app_info)
                risk_score = app_info.get('risk_score', 0)
                user_trust = self.main_window.trust_system.get_user_trust_level(app_name)
                status = app_info.get('status', 'unknown')
                app_type = app_info.get('type', 'file')
                
                user_set = "Yes" if user_trust else "No"
                type_icon = "📁" if app_type == "folder" else "📄"
                
                # Create tree item with consistent trust level
                item = QTreeWidgetItem([
                    app_name, 
                    type_icon,
                    display_trust_level.title(), 
                    str(risk_score), 
                    user_set,
                    status.title()
                ])
                
                # Color code based on trust level - SAME AS LAUNCHER
                if user_trust:
                    # User-set trust levels get special coloring
                    item.setBackground(2, QColor("#aa00ff"))  # Purple for user override
                    item.setForeground(2, QColor("#ffffff"))
                elif display_trust_level == "trusted":
                    item.setBackground(2, QColor(self.main_window.theme_manager.current_success))
                elif display_trust_level == "moderate":
                    item.setBackground(2, QColor(self.main_window.theme_manager.current_warning))
                elif display_trust_level == "untrusted":
                    item.setBackground(2, QColor(self.main_window.theme_manager.current_error))
                    item.setForeground(2, QColor("#ffffff"))
                
                # Color status column
                if status == "ready" or (app_type == "folder" and status == "configured"):
                    item.setBackground(5, QColor(self.main_window.theme_manager.current_success))
                elif status == "error":
                    item.setBackground(5, QColor(self.main_window.theme_manager.current_error))
                    item.setForeground(5, QColor("#ffffff"))
                elif app_type == "folder" and status == "unconfigured":
                    item.setBackground(5, QColor(self.main_window.theme_manager.current_warning))
                else:
                    item.setBackground(5, QColor(self.main_window.theme_manager.current_warning))
                
                # Store app name for later use
                item.setData(0, Qt.UserRole, app_name)
                
                self.analysis_tree.addTopLevelItem(item)
            
            # Resize columns to content
            for i in range(self.analysis_tree.columnCount()):
                self.analysis_tree.resizeColumnToContents(i)
                
        except Exception as e:
            print(f"Error updating analysis tree: {e}")
    
    def on_app_double_click(self, item, column):
        """Handle app double-click to set trust level"""
        app_name = item.data(0, Qt.UserRole)
        if app_name:
            self.show_trust_dialog(app_name)
    
    def set_app_trust_level(self):
        """Set trust level for selected app"""
        current_item = self.analysis_tree.currentItem()
        if current_item:
            app_name = current_item.data(0, Qt.UserRole)
            if app_name:
                self.show_trust_dialog(app_name)
        else:
            QMessageBox.warning(self, "No Selection", "Please select an application first.")
    
    def show_trust_dialog(self, app_name):
        """Show dialog to set trust level for an app"""
        dialog = AppTrustDialog(self, app_name, self.main_window.trust_system)
        dialog.trust_level_changed.connect(self.update_trust_display)
        dialog.exec_()
    
    def analyze_all_applications(self):
        """Re-analyze all applications for trust - USING SAME LOGIC AS SCANNER"""
        try:
            wm = self.main_window.window_manager
            trust_system = self.main_window.trust_system
            
            for app_name, app_info in wm.available_windows.items():
                # Skip apps with user overrides - respect user decisions
                if trust_system.get_user_trust_level(app_name):
                    continue
                    
                app_type = app_info.get('type', 'file')
                
                if app_type == 'file':
                    file_path = app_info.get('file_path')
                    if file_path and os.path.exists(file_path):
                        # Use the EXACT SAME analysis method as the EnhancedWindowScanner
                        security_level = self.analyze_security_consistent(file_path)
                        
                        # Use the SAME trust logic as the scanner
                        if security_level == "trusted":
                            trust_level = "trusted"
                            risk_score = 0
                        elif security_level == "moderate":
                            trust_level = "moderate" 
                            risk_score = 5
                        else:
                            trust_level = "untrusted"
                            risk_score = 10
                        
                        # Update app info with consistent analysis results
                        app_info['security_level'] = trust_level
                        app_info['risk_score'] = risk_score
                        app_info['last_trust_analysis'] = datetime.now().isoformat()
                        
                        self.main_window.debug_logger.log("info", 
                            f"Re-analyzed {app_name}: {trust_level}", 
                            "trust_analysis", 
                            {"file_path": file_path, "security_level": security_level}
                        )
                
                elif app_type == 'folder' and app_info.get('status') == 'configured':
                    executable_path = app_info.get('main_file')
                    if executable_path and os.path.exists(executable_path):
                        security_level = self.analyze_security_consistent(executable_path)
                        
                        if security_level == "trusted":
                            trust_level = "trusted"
                            risk_score = 0
                        elif security_level == "moderate":
                            trust_level = "moderate" 
                            risk_score = 5
                        else:
                            trust_level = "untrusted"
                            risk_score = 10
                        
                        app_info['security_level'] = trust_level
                        app_info['risk_score'] = risk_score
                        app_info['last_trust_analysis'] = datetime.now().isoformat()
                        
                        self.main_window.debug_logger.log("info", 
                            f"Re-analyzed folder {app_name}: {trust_level}", 
                            "trust_analysis", 
                            {"executable_path": executable_path, "security_level": security_level}
                        )
            
            self.update_trust_display()
            self.main_window.debug_logger.log("info", "Completed consistent trust analysis for all applications", "trust_analysis")
            QMessageBox.information(self, "Analysis Complete", 
                "All applications analyzed.\n\n"
                "Apps are now consistently marked as trusted unless they have significant security risks.")
            
        except Exception as e:
            self.main_window.debug_logger.log_error("Trust analysis failed", {"error": str(e)}, "trust_analysis")
            QMessageBox.critical(self, "Analysis Failed", f"Failed to analyze applications: {e}")
    
    def analyze_security_consistent(self, file_path):
        """
        Analyze source code for security issues - EXACT SAME LOGIC AS ENHANCEDWINDOWSCANNER
        """
        try:
            # Only analyze Python files for security
            if not file_path.endswith('.py'):
                return "trusted"  # Non-Python files are trusted by default
                
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_code = f.read()
            
            security_issues = []
            
            # EXACT SAME checks as EnhancedWindowScanner.analyze_security()
            dangerous_imports = ['os.system', 'subprocess.call', 'eval', 'exec', 'pickle.loads']
            for imp in dangerous_imports:
                if imp in source_code:
                    security_issues.append(imp)
            
            network_keywords = ['requests.get', 'socket.socket', 'urllib.request']
            for keyword in network_keywords:
                if keyword in source_code:
                    security_issues.append(keyword)
            
            # EXACT SAME logic as the scanner
            if not security_issues:
                return "trusted"
            elif len(security_issues) <= 2:
                return "moderate"
            else:
                return "untrusted"
                
        except Exception as e:
            print(f"Security analysis error for {file_path}: {e}")
            return "untrusted"
    
    def get_header_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            color: {css_vars['accent']};
            background-color: {css_vars['secondary']};
            padding: 8px;
            border: 1px solid {css_vars['border']};
            border-radius: {css_vars['border_radius']};
            margin-bottom: 8px;
            font-size: 12px;
        """
    
    def get_group_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            QGroupBox {{
                color: {css_vars['accent']};
                font-weight: bold;
                border: 1px solid {css_vars['border']};
                border-radius: {css_vars['border_radius']};
                margin-top: 1ex;
                padding-top: 1ex;
                font-family: 'Courier New';
                background-color: {css_vars['secondary']};
                font-size: 10px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 8px;
                padding: 0 3px 0 3px;
                background-color: {css_vars['secondary']};
            }}
        """
    
    def get_button_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            QPushButton {{
                background-color: {css_vars['tertiary']};
                color: {css_vars['text']};
                border: 1px solid {css_vars['border']};
                border-radius: {css_vars['border_radius']};
                padding: 4px 8px;
                font-weight: bold;
                font-family: 'Courier New';
                font-size: 10px;
            }}
            QPushButton:hover {{
                background-color: {css_vars['accent']};
                color: {css_vars['primary']};
                border: 1px solid {css_vars['accent']};
            }}
        """
    
    def get_text_edit_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            QTextEdit {{
                background-color: {css_vars['secondary']};
                color: {css_vars['text']};
                border: 1px solid {css_vars['border']};
                border-radius: {css_vars['border_radius']};
                font-family: 'Courier New';
                font-size: 9px;
            }}
        """
    
    def get_tree_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            QTreeWidget {{
                background-color: {css_vars['secondary']};
                color: {css_vars['text']};
                border: 1px solid {css_vars['border']};
                border-radius: {css_vars['border_radius']};
                font-family: 'Courier New';
                font-size: 9px;
            }}
            QTreeWidget::item {{
                padding: 2px;
            }}
        """

# ========================================
# COMPLETE SECURITY SETTINGS WIDGET
# ========================================
class EnhancedSecuritySettingsWidget(QWidget):
    """Complete security settings and configuration"""
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        
        # Header
        header = QLabel("⚙️ UIDOCK CONFIGURATION")
        header.setFont(QFont("Courier New", 14, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet(self.get_header_style())
        layout.addWidget(header)
        
        # Create scroll area for better space management
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        
        # Content widget
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(3, 3, 3, 3)
        content_layout.setSpacing(8)
        
        # Security Level
        security_group = QGroupBox("🛡️ Security Level")
        security_group.setStyleSheet(self.get_group_style())
        security_layout = QVBoxLayout(security_group)
        
        self.security_combo = QComboBox()
        self.security_combo.addItems(["Low", "Medium", "High", "Maximum"])
        current_security = self.main_window.window_manager.security_settings.get("security_level", "high").title()
        self.security_combo.setCurrentText(current_security)
        self.security_combo.currentTextChanged.connect(self.change_security_level)
        security_layout.addWidget(QLabel("Security Level:"))
        security_layout.addWidget(self.security_combo)
        
        content_layout.addWidget(security_group)
        
        # Process Monitoring
        process_group = QGroupBox("🔍 Process Monitoring")
        process_group.setStyleSheet(self.get_group_style())
        process_layout = QVBoxLayout(process_group)
        
        self.monitoring_check = QCheckBox("Enable Process Monitoring")
        self.monitoring_check.setChecked(self.main_window.window_manager.security_settings.get("process_monitoring", True))
        self.monitoring_check.stateChanged.connect(self.toggle_process_monitoring)
        process_layout.addWidget(self.monitoring_check)
        
        self.auto_terminate_check = QCheckBox("Auto-terminate Failed Processes")
        self.auto_terminate_check.setChecked(self.main_window.window_manager.security_settings.get("auto_terminate_failed", True))
        self.auto_terminate_check.stateChanged.connect(self.toggle_auto_terminate)
        process_layout.addWidget(self.auto_terminate_check)
        
        self.auto_scan_check = QCheckBox("Auto-scan on Startup")
        self.auto_scan_check.setChecked(self.main_window.window_manager.security_settings.get("startup_scan", True))
        self.auto_scan_check.stateChanged.connect(self.toggle_auto_scan)
        process_layout.addWidget(self.auto_scan_check)
        
        content_layout.addWidget(process_group)
        
        # Theme Settings
        theme_group = QGroupBox("🎨 Interface Theme")
        theme_group.setStyleSheet(self.get_group_style())
        theme_layout = QVBoxLayout(theme_group)
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Cyber Dark", "Matrix", "Midnight", "Stealth", "Purple Haze", "Amber Alert"])
        current_theme = self.main_window.window_manager.security_settings.get("ui_theme", "cyber_dark").replace("_", " ").title()
        self.theme_combo.setCurrentText(current_theme)
        self.theme_combo.currentTextChanged.connect(self.change_theme)
        theme_layout.addWidget(QLabel("Theme:"))
        theme_layout.addWidget(self.theme_combo)
        
        content_layout.addWidget(theme_group)
        
        # UI Settings
        ui_group = QGroupBox("🖥️ UI Preferences")
        ui_group.setStyleSheet(self.get_group_style())
        ui_layout = QVBoxLayout(ui_group)
        
        self.compact_check = QCheckBox("Compact Mode")
        self.compact_check.setChecked(self.main_window.window_manager.security_settings.get("compact_mode", False))
        self.compact_check.stateChanged.connect(self.toggle_compact_mode)
        ui_layout.addWidget(self.compact_check)
        
        self.performance_check = QCheckBox("Show Performance Stats")
        self.performance_check.setChecked(self.main_window.window_manager.security_settings.get("show_performance", True))
        self.performance_check.stateChanged.connect(self.toggle_performance_stats)
        ui_layout.addWidget(self.performance_check)
        
        self.notifications_check = QCheckBox("Enable Notifications")
        self.notifications_check.setChecked(self.main_window.window_manager.security_settings.get("notifications", True))
        self.notifications_check.stateChanged.connect(self.toggle_notifications)
        ui_layout.addWidget(self.notifications_check)
        
        content_layout.addWidget(ui_group)
        
        # Logging Settings
        logging_group = QGroupBox("📝 Logging Settings")
        logging_group.setStyleSheet(self.get_group_style())
        logging_layout = QVBoxLayout(logging_group)
        
        self.detailed_logging_check = QCheckBox("Detailed Logging")
        self.detailed_logging_check.setChecked(self.main_window.window_manager.security_settings.get("detailed_logging", True))
        self.detailed_logging_check.stateChanged.connect(self.toggle_detailed_logging)
        logging_layout.addWidget(self.detailed_logging_check)
        
        content_layout.addWidget(logging_group)
        
        content_layout.addStretch()
        
        # Set up scroll area
        scroll.setWidget(content_widget)
        layout.addWidget(scroll)
        
        # Save Button
        save_btn = QPushButton("💾 Save Configuration")
        save_btn.setStyleSheet(self.get_button_style())
        save_btn.clicked.connect(self.save_configuration)
        layout.addWidget(save_btn)
    
    def change_security_level(self, level):
        """Change security level"""
        self.main_window.window_manager.security_settings.set("security_level", level.lower())
        self.main_window.debug_logger.log("info", f"Security level changed to: {level}", "settings")
    
    def toggle_process_monitoring(self, state):
        """Toggle process monitoring"""
        enabled = bool(state)
        self.main_window.window_manager.security_settings.set("process_monitoring", enabled)
        status = "enabled" if enabled else "disabled"
        self.main_window.debug_logger.log("info", f"Process monitoring {status}", "settings")
    
    def toggle_auto_terminate(self, state):
        """Toggle auto-terminate"""
        enabled = bool(state)
        self.main_window.window_manager.security_settings.set("auto_terminate_failed", enabled)
        status = "enabled" if enabled else "disabled"
        self.main_window.debug_logger.log("info", f"Auto-terminate {status}", "settings")
    
    def toggle_auto_scan(self, state):
        """Toggle auto-scan"""
        enabled = bool(state)
        self.main_window.window_manager.security_settings.set("startup_scan", enabled)
        status = "enabled" if enabled else "disabled"
        self.main_window.debug_logger.log("info", f"Startup scan {status}", "settings")
    
    def change_theme(self, theme_name):
        """Change application theme"""
        theme_key = theme_name.lower().replace(" ", "_")
        if self.main_window.theme_manager.apply_theme(theme_key):
            self.main_window.window_manager.security_settings.set("ui_theme", theme_key)
            self.main_window.apply_theme()
            self.main_window.debug_logger.log("info", f"Theme changed to: {theme_name}", "settings")
    
    def toggle_compact_mode(self, state):
        """Toggle compact mode"""
        enabled = bool(state)
        self.main_window.window_manager.security_settings.set("compact_mode", enabled)
        
        # Apply compact mode changes
        if enabled:
            self.main_window.setFixedSize(800, 500)  # Compact size
        else:
            self.main_window.setFixedSize(900, 600)  # Normal size
            
        self.main_window.debug_logger.log("info", f"Compact mode {'enabled' if enabled else 'disabled'}", "settings")
    
    def toggle_performance_stats(self, state):
        """Toggle performance stats display"""
        enabled = bool(state)
        self.main_window.window_manager.security_settings.set("show_performance", enabled)
        self.main_window.debug_logger.log("info", f"Performance stats {'enabled' if enabled else 'disabled'}", "settings")
    
    def toggle_notifications(self, state):
        """Toggle notifications"""
        enabled = bool(state)
        self.main_window.window_manager.security_settings.set("notifications", enabled)
        self.main_window.debug_logger.log("info", f"Notifications {'enabled' if enabled else 'disabled'}", "settings")
    
    def toggle_detailed_logging(self, state):
        """Toggle detailed logging"""
        enabled = bool(state)
        self.main_window.window_manager.security_settings.set("detailed_logging", enabled)
        self.main_window.debug_logger.log("info", f"Detailed logging {'enabled' if enabled else 'disabled'}", "settings")
    
    def save_configuration(self):
        """Save all configuration"""
        self.main_window.window_manager.security_settings.save_settings()
        self.main_window.debug_logger.log("info", "All settings saved", "settings")
        QMessageBox.information(self, "Configuration Saved", "All settings have been saved successfully.")
    
    def get_header_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            color: {css_vars['accent']};
            background-color: {css_vars['secondary']};
            padding: 8px;
            border: 1px solid {css_vars['border']};
            border-radius: {css_vars['border_radius']};
            margin-bottom: 8px;
            font-size: 12px;
        """
    
    def get_group_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            QGroupBox {{
                color: {css_vars['accent']};
                font-weight: bold;
                border: 1px solid {css_vars['border']};
                border-radius: {css_vars['border_radius']};
                margin-top: 1ex;
                padding-top: 1ex;
                font-family: 'Courier New';
                background-color: {css_vars['secondary']};
                font-size: 10px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 8px;
                padding: 0 3px 0 3px;
                background-color: {css_vars['secondary']};
            }}
        """
    
    def get_button_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            QPushButton {{
                background-color: {css_vars['tertiary']};
                color: {css_vars['text']};
                border: 1px solid {css_vars['accent']};
                border-radius: {css_vars['button_radius']};
                padding: 6px 10px;
                font-weight: bold;
                font-family: 'Courier New';
                font-size: 10px;
            }}
            QPushButton:hover {{
                background-color: {css_vars['accent']};
                color: {css_vars['primary']};
            }}
        """

# ========================================
# OPTIMIZED SYSTEM INFO WIDGET
# ========================================
class EnhancedSystemInfoWidget(QWidget):
    """Optimized system information and diagnostics"""
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.init_ui()
        
        self.update_system_info()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        
        # Header
        header = QLabel("🖥️ UIDOCK SYSTEM INFO")
        header.setFont(QFont("Courier New", 14, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet(self.get_header_style())
        layout.addWidget(header)
        
        # System Info
        system_group = QGroupBox("📊 System Information")
        system_group.setStyleSheet(self.get_group_style())
        system_layout = QVBoxLayout(system_group)
        
        self.system_info_text = QTextEdit()
        self.system_info_text.setMaximumHeight(120)
        self.system_info_text.setReadOnly(True)
        self.system_info_text.setStyleSheet(self.get_text_edit_style())
        system_layout.addWidget(self.system_info_text)
        
        layout.addWidget(system_group)
        
        # Application Statistics
        stats_group = QGroupBox("📈 Application Statistics")
        stats_group.setStyleSheet(self.get_group_style())
        stats_layout = QVBoxLayout(stats_group)
        
        self.stats_text = QTextEdit()
        self.stats_text.setMaximumHeight(120)
        self.stats_text.setReadOnly(True)
        self.stats_text.setStyleSheet(self.get_text_edit_style())
        stats_layout.addWidget(self.stats_text)
        
        layout.addWidget(stats_group)
        
        layout.addStretch()
    
    def update_system_info(self):
        """Update system information display with enhanced data"""
        try:
            # Get application-specific data
            wm = self.main_window.window_manager
            
            # System information
            system_info = f"""
Platform: {sys.platform}
Python: {sys.version.split()[0]}
Directory: {os.getcwd()}

Security: {wm.security_settings.get('security_level', 'high').upper()}
Monitoring: {'ENABLED' if wm.security_settings.get('process_monitoring', True) else 'DISABLED'}

Theme: {wm.security_settings.get('ui_theme', 'cyber_dark').replace('_', ' ').title()}
Compact Mode: {'ON' if wm.security_settings.get('compact_mode', False) else 'OFF'}
            """.strip()
            
            self.system_info_text.setPlainText(system_info)
            
            # Application statistics
            perf_stats = wm.window_manager.get_performance_stats()
            total_apps = len(wm.available_windows)
            
            # Count trusted apps including user overrides
            trusted_apps = 0
            user_overrides = 0
            folder_apps = 0
            configured_folders = 0
            for app_name, app_info in wm.available_windows.items():
                app_type = app_info.get('type', 'file')
                if app_type == 'folder':
                    folder_apps += 1
                    if app_info.get('status') == 'configured':
                        configured_folders += 1
                        
                user_trust = self.main_window.trust_system.get_user_trust_level(app_name)
                if user_trust:
                    user_overrides += 1
                    if user_trust == "trusted":
                        trusted_apps += 1
                elif app_info.get('security_level') == 'trusted':
                    trusted_apps += 1
            
            running_apps = wm.window_manager.get_running_count() + len(wm.embedded_windows)
            
            stats_info = f"""
Applications: {total_apps}
Files: {total_apps - folder_apps}
Folders: {folder_apps} ({configured_folders} configured)
Trusted: {trusted_apps}
User Overrides: {user_overrides}
Running: {running_apps}
Embedded: {len(wm.embedded_windows)}

Launches: {perf_stats['total_launches']}
Success: {perf_stats['successful_launches']}
Failed: {perf_stats['failed_launches']}
Rate: {(perf_stats['successful_launches']/perf_stats['total_launches']*100) if perf_stats['total_launches'] > 0 else 100:.1f}%

Logs: {len(self.main_window.debug_logger.logs)}
Errors: {len(self.main_window.debug_logger.error_logs)}
Security Events: {len(self.main_window.debug_logger.security_logs)}
            """.strip()
            
            self.stats_text.setPlainText(stats_info)
            
        except Exception as e:
            print(f"Error updating system info: {e}")
    
    def get_header_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            color: {css_vars['accent']};
            background-color: {css_vars['secondary']};
            padding: 8px;
            border: 1px solid {css_vars['border']};
            border-radius: {css_vars['border_radius']};
            margin-bottom: 8px;
            font-size: 12px;
        """
    
    def get_group_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            QGroupBox {{
                color: {css_vars['accent']};
                font-weight: bold;
                border: 1px solid {css_vars['border']};
                border-radius: {css_vars['border_radius']};
                margin-top: 1ex;
                padding-top: 1ex;
                font-family: 'Courier New';
                background-color: {css_vars['secondary']};
                font-size: 10px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 8px;
                padding: 0 3px 0 3px;
                background-color: {css_vars['secondary']};
            }}
        """
    
    def get_text_edit_style(self):
        css_vars = self.main_window.theme_manager.get_css_variables()
        return f"""
            QTextEdit {{
                background-color: {css_vars['secondary']};
                color: {css_vars['text']};
                border: 1px solid {css_vars['border']};
                border-radius: {css_vars['border_radius']};
                font-family: 'Courier New';
                font-size: 9px;
            }}
        """

# ========================================
# UIDOCK MAIN WINDOW
# ========================================
class UIDockMainWindow(QMainWindow):
    """UIDock - Universal Interface Dock for Application Management"""
    
    def __init__(self):
        super().__init__()
        
        self.debug_logger = EnhancedDebugLogger()
        self.theme_manager = EnhancedCyberThemeManager()
        self.window_manager = EnhancedGUIWindowManager(self.debug_logger)
        self.trust_system = TrustAnalysisSystem(self.debug_logger)
        
        self.init_ui()
        
        # Process monitoring timer
        self.process_timer = QTimer()
        self.process_timer.timeout.connect(self.monitor_processes)
        self.process_timer.start(3000)  # Check every 3 seconds
        
        self.debug_logger.log("info", "UIDock started successfully", "startup", {
            'theme': self.theme_manager.current_theme,
            'windows_dir': self.window_manager.windows_dir
        })
    
    def init_ui(self):
        self.setWindowTitle("🚀 UIDock - Universal Interface Dock")
        
        # Apply compact mode setting
        if self.window_manager.security_settings.get("compact_mode", False):
            self.setFixedSize(800, 500)  # Compact size
        else:
            self.setFixedSize(900, 600)  # Normal size
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        self.create_navigation_bar()
        main_layout.addWidget(self.nav_bar)
        
        self.stacked_widget = QStackedWidget()
        
        # Add all interfaces
        self.dashboard = EnhancedCyberDashboardWidget(self)
        self.stacked_widget.addWidget(self.dashboard)
        
        self.debugging_widget = EnhancedDebuggingWidget(self)
        self.stacked_widget.addWidget(self.debugging_widget)
        
        self.trust_widget = EnhancedTrustAnalysisWidget(self)
        self.stacked_widget.addWidget(self.trust_widget)
        
        self.security_widget = EnhancedSecuritySettingsWidget(self)
        self.stacked_widget.addWidget(self.security_widget)
        
        self.system_widget = EnhancedSystemInfoWidget(self)
        self.stacked_widget.addWidget(self.system_widget)
        
        self.launcher_widget = CompactLauncherWidget(self)
        self.stacked_widget.addWidget(self.launcher_widget)
        
        main_layout.addWidget(self.stacked_widget)
        
        self.apply_theme()
        
        self.show_dashboard_interface()
    
    def create_navigation_bar(self):
        """Create compact navigation bar"""
        self.nav_bar = QWidget()
        self.nav_bar.setFixedHeight(40)
        self.nav_bar.setStyleSheet(f"""
            background-color: {self.theme_manager.current_secondary};
            border-bottom: 1px solid {self.theme_manager.current_border};
        """)
        
        nav_layout = QHBoxLayout(self.nav_bar)
        nav_layout.setContentsMargins(8, 3, 8, 3)
        nav_layout.setSpacing(4)
        
        nav_buttons = [
            ("🏠", self.show_dashboard_interface),
            ("📱", self.show_launcher_interface),
            ("🐛", self.show_debugging_interface),
            ("🛡️", self.show_trust_interface),
            ("⚙️", self.show_security_interface),
            ("🖥️", self.show_system_interface)
        ]
        
        for icon, callback in nav_buttons:
            btn = QPushButton(icon)
            btn.setFixedSize(32, 32)
            btn.setStyleSheet(self.get_nav_button_style())
            btn.clicked.connect(callback)
            nav_layout.addWidget(btn)
        
        nav_layout.addStretch()
        
        title = QLabel("UIDock - Universal Interface Dock")
        title.setStyleSheet(f"color: {self.theme_manager.current_accent}; font-weight: bold; font-family: 'Courier New'; font-size: 11px;")
        nav_layout.addWidget(title)
    
    def monitor_processes(self):
        """Monitor running processes and update status"""
        try:
            if self.window_manager.security_settings.get("process_monitoring", True):
                self.window_manager.window_manager.process_tracker.check_process_status()
        except Exception as e:
            self.debug_logger.log_error("Process monitoring error", {"error": str(e)})
    
    def show_dashboard_interface(self):
        """Show dashboard"""
        self.stacked_widget.setCurrentIndex(0)
        self.debug_logger.log_debug("Switched to dashboard interface")
    
    def show_launcher_interface(self):
        """Show app launcher"""
        self.stacked_widget.setCurrentIndex(5)
        self.debug_logger.log_debug("Switched to launcher interface")
    
    def show_debugging_interface(self):
        """Show debugging interface"""
        self.stacked_widget.setCurrentIndex(1)
        self.debug_logger.log_debug("Switched to debugging interface")
    
    def show_trust_interface(self):
        """Show trust analysis interface"""
        self.stacked_widget.setCurrentIndex(2)
        self.debug_logger.log_debug("Switched to trust analysis interface")
    
    def show_security_interface(self):
        """Show security settings interface"""
        self.stacked_widget.setCurrentIndex(3)
        self.debug_logger.log_debug("Switched to security settings interface")
    
    def show_system_interface(self):
        """Show system information interface"""
        self.stacked_widget.setCurrentIndex(4)
        self.debug_logger.log_debug("Switched to system information interface")
    
    def apply_theme(self):
        """Apply current theme to the main window"""
        css_vars = self.theme_manager.get_css_variables()
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {css_vars['primary']};
                color: {css_vars['text']};
                font-family: 'Courier New';
                font-size: 9px;
            }}
        """)
    
    def get_nav_button_style(self):
        """Get navigation button style"""
        css_vars = self.theme_manager.get_css_variables()
        return f"""
            QPushButton {{
                background-color: {css_vars['tertiary']};
                color: {css_vars['text']};
                border: 1px solid {css_vars['border']};
                border-radius: {css_vars['button_radius']};
                font-weight: bold;
                font-family: 'Courier New';
                font-size: 10px;
            }}
            QPushButton:hover {{
                background-color: {css_vars['accent']};
                color: {css_vars['primary']};
                border: 1px solid {css_vars['accent']};
            }}
        """

# ========================================
# MAIN APPLICATION
# ========================================
def main():
    """Main application entry point"""
    try:
        app = QApplication(sys.argv)
        
        app.setApplicationName("UIDock")
        app.setApplicationVersion("4.0")
        app.setFont(QFont("Courier New", 9))
        
        window = UIDockMainWindow()
        window.show()
        
        return app.exec_()
        
    except Exception as e:
        print(f"Critical application failure: {e}")
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())
