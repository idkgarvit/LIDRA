# src/cli/__init__.py
"""LIDRA CLI Package - Interactive command line interface."""

try:
    from utils.version import __version__
except Exception:
    __version__ = "0.0.0"
__author__ = "LIDRA Team"

from .main import main, LIDRACli

__all__ = ['main', 'LIDRACli']