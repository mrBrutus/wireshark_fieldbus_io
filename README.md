# wireshark_fieldbus_io

Python package for extracting industrial fieldbus IO data packets from a Wireshark capture file.

It makes it easy to get the IO data between two specific devices on the fieldbus (e.g. PROFINET).
After extracting, the data can be further analyzed using some Python code or in third party tools.
For the latter the IO data can be exported as CSV file.

Some use cases:

- Interface development
- Troubleshooting
- Checking data consistency

This package uses [pyshark](https://github.com/KimiNewt/pyshark) for reading the Wireshark files.

## Installation

You can install the package using pip:

```bash
pip install wireshark_fieldbus_io
```

## Usage

Example for extracting the `436 byte` IO data packets from a Wireshark file,
where the `PROFINET` data exchange between a PLC and a robot controller was captured.

```py
from wireshark_fieldbus_io.packet_reader import IoPacketReader, Fieldbus
from wireshark_fieldbus_io.enums_types import Fieldbus

# Create the instance
wireshark_log = IoPacketReader()

# Settings
# Fieldbus selection
wireshark_log.fieldbus = Fieldbus.PROFINET

# MAC address of the first device (e.g. a PLC)
wireshark_log.mac_address_host = '01:02:03:04:05:06'

# MAC address of the other device (e.g. a robot controller)
wireshark_log.mac_address_partner = '51:52:53:54:55:56'

# Raw packet size (can be recognized in the Wireshark UI)
wireshark_log.raw_packet_size = 442

# IO packet size between the two devices (comes from your system configuration)
wireshark_log.io_packet_size = 436

# Device specific offsets (can be recognized in the Wireshark UI)
wireshark_log.offset_snd_packet = 5
wireshark_log.offset_rcv_packet = 4

# Process file
wireshark_log.read_file(
    wireshark_file='my-wireshark-log.pcapng',
    remove_duplicates=True,  # removes subsequent packets with same IO data
    # start_frame=500,       # optional: filter packet range (start)
    # end_frame=750          # optional: filter packet range (end)
)

# show result
print(
    f'found {wireshark_log.nr_of_packets} packets'
    f' ({wireshark_log.nr_of_snd_packets} packets sent,'
    f' {wireshark_log.nr_of_rcv_packets} packets received)'
)

# Output:
# found 13289 packets (10521 packets sent, 2768 packets received)
```

### Analyze packet data

Now you can work with the captured IO data packets:

```py
# Print a part of the data from each packet (sent and received)
for pkt in wireshark_log.data_packets:
    print(pkt.id, pkt.time, pkt.direction, len(pkt.bytes), pkt.bytes[1:4])

# Output (partial):
# 26318 2024-12-30 16:54:10.973099 snd 436 [7, 1, 180]
# 26319 2024-12-30 16:54:10.974128 rcv 436 [32, 0, 254]
# 26320 2024-12-30 16:54:10.974128 snd 436 [8, 1, 180]
```

Or do some decoding on the received packets:

```py
# Some simple decoding function
def decode_input_data(bytes: list[int]) -> dict:
    obj = {}
    obj['var1'] = bytes[1]
    obj['var2'] = bytes[435]
    obj['same_val'] = obj['var1'] == obj['var2']
    return obj

# Print the decoded data of each received packet
for pkt in wireshark_log.data_packets_rcv:
    print(pkt.id, pkt.time, decode_input_data(pkt.bytes))

# Output (partial):
# 17924 2024-12-30 16:54:07.192184 {'var1': 32, 'var2': 32, 'same_val': True}
# 17928 2024-12-30 16:54:07.194178 {'var1': 80, 'var2': 80, 'same_val': True}
# 17936 2024-12-30 16:54:07.198175 {'var1': 16, 'var2': 16, 'same_val': True}
```

### Export packet data

The data packets can be exported to `.csv` file using the `export_csv` function:

```py
# Export the packet data as CSV file
wireshark_log.export_csv(f'my-profinet-packets.csv')

# Content of CSV file (partial):
id,time,direction,b0,b1,b2,b3,b4,[..]
26318,2024-12-30 16:54:10.973099,snd,35,7,1,180,1,[..]
26319,2024-12-30 16:54:10.974128,rcv,35,32,0,254,36,[..]
26320,2024-12-30 16:54:10.974128,snd,35,8,1,180,1,[..]
```

## Known issues

- Send- and receive packet must have the same size.
- Processing larger files can take some time.
- Uses `pyshark`'s deprecated `use_json` instead of the recommended `use_ek`.
- No input validation or error handling.
- EtherCAT not fully functional yet.
