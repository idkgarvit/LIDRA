# src/collectors/syslog/__init__.py
"""Syslog collection module."""

from .server import SyslogServer, create_syslog_server

__all__ = ['SyslogServer', 'create_syslog_server']