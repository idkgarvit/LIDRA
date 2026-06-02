# src/collectors/network/__init__.py
"""Network packet collection module."""

from .packet_sniffer import PacketSniffer, create_sniffer

__all__ = ['PacketSniffer', 'create_sniffer']