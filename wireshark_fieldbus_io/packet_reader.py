"""Packet reader for the `wireshark_fieldbus_io` package"""
import csv
import os
from datetime import datetime
from typing import List # noqa: F401
from pyshark import FileCapture
from pyshark.packet.packet import Packet
from .enums_types import Fieldbus, PacketDirection, IoPacket


class IoPacketReader():
    """
    Class for reading the IO data packets from a Wireshark capture.
    Requires a call of `read_file()`
    """

    def __init__(self):
        self._data_packets = []  # type: List[IoPacket]
        self._previous_snd_packet = IoPacket()
        self._previous_rcv_packet = IoPacket()
        self._snd_packet_indices = []  # type: List[int]
        self._rcv_packet_indices = []  # type: List[int]
        self._mac_address_host = '00.00.00.00.00.00'
        self._mac_address_partner = '00.00.00.00.00.00'
        self._raw_packet_size = 255
        self._io_packet_size = 255
        self._offset_snd_packet = 0
        self._offset_rcv_packet = 0
        self._fieldbus = None  # type: Fieldbus

    def read_file(self, wireshark_file: str, remove_duplicates=False, start_frame: int = None, end_frame: int = None):
        """
        Read the Wireshark capture file and extract the fieldbus IO data packets.

        Args:
            wireshark_file (str): file path for the wireshark capture file.
            remove_duplicates (bool, optional): Ignore subsequent packets with identical data. Defaults to False.
            start_frame (int, optional): Filter packet range: start frame. Defaults to starting from first frame.
            end_frame (int, optional): Filter packet range: end frame. Defaults to ending at last frame.
        """

        pcap = FileCapture(
            input_file=wireshark_file,
            include_raw=True,
            use_json=True,
            display_filter=self._display_filter(start_frame, end_frame)
        )

        # process the packets
        count = 0
        for pkt in pcap:
            pkt: Packet
            io_packet = self._process_io_packet(pkt)
            if io_packet:

                # send packets
                if io_packet.direction == PacketDirection.SND:
                    if not remove_duplicates or (io_packet.bytes != self._previous_snd_packet.bytes):
                        self._data_packets.append(io_packet)
                        self._snd_packet_indices.append(count)
                        self._previous_snd_packet = io_packet
                        count += 1

                # receive packets
                elif io_packet.direction == PacketDirection.RCV:
                    if not remove_duplicates or (io_packet.bytes != self._previous_rcv_packet.bytes):
                        self._data_packets.append(io_packet)
                        self._rcv_packet_indices.append(count)
                        self._previous_rcv_packet = io_packet
                        count += 1

        # close the file capture
        pcap.close()

    def _display_filter(self, start_frame: int = None, end_frame: int = None) -> str:
        """Build display filter for filtering by fieldbus and range of packets"""

        filter_conditions = []
        # filter for relevant fieldbus
        if self.fieldbus == Fieldbus.PROFINET:
            filter_conditions.append('(eth.type == 0x8892)')

        if self.fieldbus == Fieldbus.ETHERCAT:
            filter_conditions.append('(eth.type == 0x88a4)')

        # filter by packet range
        if start_frame:
            filter_conditions.append(f'(frame.number >= {start_frame})')
        if end_frame:
            filter_conditions.append(f'(frame.number <= {end_frame})')

        return ' && '.join(filter_conditions)

    def _process_io_packet(self, pkt: Packet) -> IoPacket:
        """Get IO packet from wireshark log entry"""

        io_packet = IoPacket()

        if self.fieldbus == Fieldbus.PROFINET:
            packet_bytes = self._packet_bytes_profinet(pkt)
        elif self.fieldbus == Fieldbus.ETHERCAT:
            packet_bytes = self._packet_bytes_ethercat(pkt)
        else:
            packet_bytes = [None] * self.raw_packet_size

        # filter by length
        length_ok = len(packet_bytes) == self.raw_packet_size

        if length_ok:
            io_packet.id = self._packet_number(pkt)
            io_packet.time = self._packet_timestamp(pkt)
            io_packet.direction = self._packet_direction(pkt)
            if io_packet.direction == PacketDirection.SND:
                io_packet.bytes = packet_bytes[self.offset_snd_packet: (
                    self.io_packet_size + self.offset_snd_packet)]
            elif io_packet.direction == PacketDirection.RCV:
                io_packet.bytes = packet_bytes[self.offset_rcv_packet: (
                    self.io_packet_size + self.offset_rcv_packet)]
            return io_packet

    @staticmethod
    def _packet_number(pkt: Packet) -> int:
        """get packet number"""

        return pkt.number

    @staticmethod
    def _packet_timestamp(pkt: Packet) -> datetime:
        """get packet time stamp"""

        return pkt.sniff_time

    @staticmethod
    def _packet_bytes_profinet(pkt: Packet) -> list[int]:
        """get PROFINET packet bytes (this includes any header/status bytes)"""

        str_packet_data = pkt[pkt.highest_layer].value
        packet_data = list(bytes.fromhex(str_packet_data))
        return packet_data

    @staticmethod
    def _packet_bytes_ethercat(pkt: Packet) -> list[int]:
        """get EtherCAT packet bytes (this includes any header/status bytes)"""

        str_packet_data = pkt[pkt.highest_layer].value
        packet_data = list(bytes.fromhex(str_packet_data))
        return packet_data

    def _packet_direction(self, pkt: Packet) -> PacketDirection:
        """get packet direction"""

        src = self._source_mac(pkt)
        dst = self._destination_mac(pkt)

        if src == self.mac_address_host and dst == self.mac_address_partner:
            return PacketDirection.SND
        if src == self.mac_address_partner and dst == self.mac_address_host:
            return PacketDirection.RCV

    @staticmethod
    def _source_mac(pkt: Packet) -> str:
        """get source MAC address"""

        if 'ETH Layer' in str(pkt.layers) and 'eth.src' in pkt.eth._all_fields:
            return pkt.eth.src

    @staticmethod
    def _destination_mac(pkt: Packet) -> str:
        """get destination MAC address"""

        if 'ETH Layer' in str(pkt.layers) and 'eth.dst' in pkt.eth._all_fields:
            return pkt.eth.dst

    @property
    def data_packets(self):
        """List of IO data packets"""

        return self._data_packets

    @property
    def nr_of_packets(self):
        """Number of IO data packets"""

        return len(self._data_packets)

    @property
    def nr_of_snd_packets(self):
        """Number of sent IO data packets"""

        return len(self._snd_packet_indices)

    @property
    def nr_of_rcv_packets(self):
        """Number of received IO data packets"""

        return len(self._rcv_packet_indices)

    @property
    def data_packets_snd(self):
        """List of sent IO data packets"""

        packets = []  # type: List[IoPacket]
        for index in self._snd_packet_indices:
            packets.append(self._data_packets[index])
        return packets

    @property
    def data_packets_rcv(self):
        """List of received IO data packets"""

        packets = []  # type: List[IoPacket]
        for index in self._rcv_packet_indices:
            packets.append(self._data_packets[index])
        return packets

    @property
    def mac_address_host(self):
        """Specified MAC address for host. Used for determing direction of data packet"""

        return self._mac_address_host

    @mac_address_host.setter
    def mac_address_host(self, mac_address: str):
        self._mac_address_host = mac_address

    @property
    def mac_address_partner(self):
        """Specified MAC address for partner. Used for determing direction of data packet"""

        return self._mac_address_partner

    @mac_address_partner.setter
    def mac_address_partner(self, mac_address: str):
        self._mac_address_partner = mac_address

    @property
    def raw_packet_size(self):
        """Specified raw data packet size (this includes any header/status bytes)."""

        return self._raw_packet_size

    @raw_packet_size.setter
    def raw_packet_size(self, raw_packet_size: int):
        self._raw_packet_size = raw_packet_size

    @property
    def io_packet_size(self):
        """Specified IO data packet size."""

        return self._io_packet_size

    @io_packet_size.setter
    def io_packet_size(self, io_packet_size: int):
        self._io_packet_size = io_packet_size

    @property
    def offset_snd_packet(self):
        """Specified start byte of IO data packet sent to partner."""

        return self._offset_snd_packet

    @offset_snd_packet.setter
    def offset_snd_packet(self, offset_snd_packet: int):
        self._offset_snd_packet = offset_snd_packet

    @property
    def offset_rcv_packet(self):
        """Specified start byte of IO data packet received from partner."""

        return self._offset_rcv_packet

    @offset_rcv_packet.setter
    def offset_rcv_packet(self, offset_rcv_packet: int):
        self._offset_rcv_packet = offset_rcv_packet

    @property
    def fieldbus(self):
        """Specified fieldbus type for reading the wireshark log."""

        return self._fieldbus

    @fieldbus.setter
    def fieldbus(self, fieldbus: Fieldbus):
        self._fieldbus = fieldbus

    def export_csv(self, file_path: str = 'output.csv'):
        """
        Export the fieldbus IO data packets to a CSV file.
        Creates subdirectories where necessary.

        Args:
            file_path (str, optional): file path for the CSV file. Defaults to `output.csv`.
        """

        if self.data_packets:
            # create subdirs
            parent_folder = os.path.dirname(file_path)
            if parent_folder:
                os.makedirs(os.path.dirname(file_path), exist_ok=True)

            with open(file_path, mode='w', newline='') as file:
                writer = csv.writer(file)

                # create header
                header = []
                # use keys from the IoPacket class, except for the bytes
                for key, value in IoPacket().items():
                    if not isinstance(value, list):
                        header.append(key)
                # each byte gets its own column
                header.extend([f"b{i}" for i in range(self.io_packet_size)])
                writer.writerow(header)

                # write packet data
                for packet in self.data_packets:
                    row = [packet.id, packet.time, packet.direction] + packet.bytes
                    writer.writerow(row)
