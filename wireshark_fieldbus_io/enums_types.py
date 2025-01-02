"""Enums and types for the `wireshark_fieldbus_io` package"""
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import List
from .utils import MyDataClass


class PacketDirection(StrEnum):
    """Enum for specifying the direction of a data packet."""

    SND = auto()
    """Direction: Send (`host --> partner`)"""
    RCV = auto()
    """Direction: Receive (`host <-- partner`)"""


class Fieldbus(StrEnum):
    """Enum for specifying the fieldbus type."""

    PROFINET = auto()
    """PROFINET fieldbus."""
    ETHERCAT = auto()
    """EtherCAT fieldbus."""


@dataclass
class IoPacket(MyDataClass):
    """Data packet containing the fieldbus IO data."""

    id: int = None
    """Packet number from Wireshark log."""
    time: str = None
    """Time stamp from Wireshark log."""
    direction: PacketDirection = None
    """Direction of the data packet."""
    bytes: List[int] = field(default_factory=list)
    """Fieldbus IO data."""
