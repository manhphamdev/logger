import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional
from logging.handlers import RotatingFileHandler


class QTextEditStream:
    """Custom stream that writes to QTextEdit widget"""
    
    def __init__(self, text_edit):
        self.text_edit = text_edit
    
    def write(self, message):
        if message.strip():  # Avoid empty messages
            self.text_edit.append(message.rstrip())
    
    def flush(self):
        pass  # Required for stream interface


class Logger:
    """
    Singleton Logger class for DepthAI Camera Framework
    Provides consistent logging across all modules with file and console output
    """
    
    _instance: Optional['Logger'] = None
    _logger: Optional[logging.Logger] = None
    _file_handler: Optional[RotatingFileHandler] = None
    _console_handler: Optional[logging.StreamHandler] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._logger is None:
            self._setup_logger()
    
    def _setup_logger(self):
        """Setup logger with console handler only (file logging disabled by default)"""
        self._logger = logging.getLogger("DepthAICam")
        self._logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers
        if self._logger.handlers:
            self._logger.handlers.clear()
        
        # Create formatters
        self._simple_formatter = logging.Formatter(
            fmt='%(asctime)s - [%(levelname)s] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        self._detailed_formatter = logging.Formatter(
            fmt='%(asctime)s - [%(levelname)s] - %(name)s - %(funcName)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Console handler only (default)
        self._console_handler = logging.StreamHandler(sys.stdout)
        self._console_handler.setLevel(logging.INFO)
        self._console_handler.setFormatter(self._simple_formatter)
        
        # Add console handler
        self._logger.addHandler(self._console_handler)
    
    def debug(self, message: str, *args, **kwargs):
        """Log debug message"""
        self._logger.debug(message, *args, **kwargs)
            
    def info(self, message: str, *args, **kwargs):
        """Log info message"""
        self._logger.info(message, *args, **kwargs)
            
    def warning(self, message: str, *args, **kwargs):
        """Log warning message"""
        self._logger.warning(message, *args, **kwargs)
            
    def error(self, message: str, *args, **kwargs):
        """Log error message"""
        self._logger.error(message, *args, **kwargs)
            
    def critical(self, message: str, *args, **kwargs):
        """Log critical message"""
        self._logger.critical(message, *args, **kwargs)
            
    def exception(self, message: str, *args, **kwargs):
        """Log exception with traceback"""
        self._logger.exception(message, *args, **kwargs)
            
    def set_level(self, level: str):
        """
        Set logging level
        Args:
            level: One of 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'
        """
        level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
        if level.upper() in level_map:
            self._logger.setLevel(level_map[level.upper()])
            self.info(f"Log level changed to {level.upper()}")
    
    def set_console_level(self, level: str):
        """
        Set console handler logging level
        Args:
            level: One of 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'
        """
        level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
        if level.upper() in level_map and self._console_handler:
            self._console_handler.setLevel(level_map[level.upper()])

    def enable_file_logging(self, log_dir: str = "logs", max_bytes: int = 10 * 1024 * 1024, backup_count: int = 5):
        """
        Enable file logging
        Args:
            log_dir: Directory to store log files (default: 'logs')
            max_bytes: Maximum size of log file before rotation (default: 10MB)
            backup_count: Number of backup files to keep (default: 5)
        """
        if self._file_handler is not None:
            self.warning("File logging is already enabled")
            return
        
        # Create logs directory if it doesn't exist
        log_path = Path(log_dir)
        log_path.mkdir(exist_ok=True)
        
        # Create file handler with rotation
        log_file = log_path / f"camera_{datetime.now().strftime('%Y%m%d')}.log"
        self._file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        self._file_handler.setLevel(logging.DEBUG)
        self._file_handler.setFormatter(self._detailed_formatter)
        
        # Add file handler to logger
        self._logger.addHandler(self._file_handler)
        self.info(f"File logging enabled: {log_file}")
    
    def disable_file_logging(self):
        """Disable file logging"""
        if self._file_handler is None:
            self.warning("File logging is already disabled")
            return
        
        self.info("Disabling file logging")
        self._logger.removeHandler(self._file_handler)
        self._file_handler.close()
        self._file_handler = None
    
    def is_file_logging_enabled(self) -> bool:
        """Check if file logging is enabled"""
        return self._file_handler is not None
    
    def set_console_stream(self, stream):
        """
        Redirect console output to a custom stream (e.g., QTextEdit)
        Args:
            stream: Any object with write() and flush() methods
        
        Example with QTextEdit:
            from logger import QTextEditStream, logger
            
            text_edit = QTextEdit()
            stream = QTextEditStream(text_edit)
            logger.set_console_stream(stream)
        """
        if self._console_handler:
            self._console_handler.setStream(stream)
    
    def reset_console_stream(self):
        if self._console_handler:
            self._console_handler.setStream(sys.stdout)
    
    @classmethod
    def get_instance(cls) -> 'Logger':
        """Get Logger singleton instance"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance


# Create global logger instance for easy import
logger = Logger.get_instance()


# Convenience functions for direct import
def debug(message: str, *args, **kwargs):
    """Log debug message"""
    logger.debug(message, *args, **kwargs)


def info(message: str, *args, **kwargs):
    """Log info message"""
    logger.info(message, *args, **kwargs)


def warning(message: str, *args, **kwargs):
    """Log warning message"""
    logger.warning(message, *args, **kwargs)


def error(message: str, *args, **kwargs):
    """Log error message"""
    logger.error(message, *args, **kwargs)


def critical(message: str, *args, **kwargs):
    """Log critical message"""
    logger.critical(message, *args, **kwargs)


def exception(message: str, *args, **kwargs):
    """Log exception with traceback"""
    logger.exception(message, *args, **kwargs)
