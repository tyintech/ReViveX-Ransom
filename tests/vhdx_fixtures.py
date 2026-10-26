"""Real-format synthetic VHDX fixtures; not disk-reader mocks.

Fields follow Microsoft MS-VHDX sections 2.2/2.5/2.6. Independently checksummed
by a bitwise Castagnoli routine (not the production CRC implementation).
"""
import struct
from pathlib import Path
from uuid import UUID

MB = 1048576


def fixture_crc(data):
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def checksum(data):
    data = bytearray(data)
    data[4:8] = bytes(4)
    struct.pack_into('<I', data, 4, fixture_crc(data))
    return data


def build_vhdx(path, payload, *, block_size=MB, fixed=False, states=None,
               sector_size=512, parent=False, active_log=False, order=None):
    """Return path. Payload allocations begin at 4 MiB; log/BAT/metadata 1/2/3 MiB.

    ``order`` (optional) lists allocated logical blocks in physical file order,
    like a dynamic disk whose blocks were first written out of sequence.
    """
    path = Path(path)
    if not payload or len(payload) % sector_size:
        raise ValueError('Supply nonempty sector-aligned logical bytes')
    count = (len(payload) + block_size - 1) // block_size
    states = list(states) if states is not None else [6] * count
    if len(states) != count:
        raise ValueError('One state per logical block')
    ratio = (2**23 * sector_size) // block_size
    bat_entries = count + (count - 1) // ratio
    bat_length = ((bat_entries * 8 + MB - 1) // MB) * MB
    metadata_offset = 2 * MB + bat_length
    payload_offset = metadata_offset + MB
    image = bytearray(payload_offset + sum(state == 6 for state in states) * block_size)
    image[:8] = b'vhdxfile'
    for slot, sequence in ((65536, 1), (131072, 2)):
        header = bytearray(4096)
        header[:4] = b'head'
        struct.pack_into('<Q', header, 8, sequence)
        if active_log:
            header[48:64] = UUID(int=1).bytes_le
        struct.pack_into('<HHIQ', header, 64, 0, 1, MB, MB)
        image[slot:slot + 4096] = checksum(header)
    region = bytearray(65536)
    region[:4] = b'regi'
    struct.pack_into('<I', region, 8, 2)
    for i, (guid, offset, length) in enumerate([
        ('2dc27766-f623-4200-9d64-115e9bfd4a08', 2 * MB, bat_length),
        ('8b7ca206-4790-4b9a-b8fe-575f050f886e', metadata_offset, MB),
    ]):
        struct.pack_into('<16sQII', region, 16 + 32*i, UUID(guid).bytes_le, offset, length, 1)
    for slot in (196608, 262144):
        image[slot:slot + 65536] = checksum(region)
    metadata = bytearray(MB)
    metadata[:8] = b'metadata'
    items = [
        ('caa16737-fa36-4d43-b3b6-33f0aa44e76b', struct.pack('<II', block_size, int(fixed) | (2 if parent else 0)), 4),
        ('2fa54224-cd1b-4876-b211-5dbed83bf4b8', struct.pack('<Q', len(payload)), 6),
        ('beca12ab-b2e6-4523-93ef-c309e000c746', UUID(int=42).bytes_le, 6),
        ('8141bf1d-a96f-4709-ba47-f233a8faab5f', struct.pack('<I', sector_size), 6),
        ('cda348c7-445d-4471-9cc9-e9885251c556', struct.pack('<I', sector_size), 6),
    ]
    struct.pack_into('<H', metadata, 10, len(items))
    cursor = 65536
    for i, (guid, value, flags) in enumerate(items):
        struct.pack_into('<16sIIII', metadata, 32 + 32*i, UUID(guid).bytes_le, cursor, len(value), flags, 0)
        metadata[cursor:cursor + len(value)] = value
        cursor += len(value)
    image[metadata_offset:metadata_offset + MB] = metadata
    allocated = [i for i, state in enumerate(states) if state == 6]
    order = list(order) if order is not None else allocated
    if sorted(order) != allocated:
        raise ValueError('order must list every allocated block exactly once')
    slot = {block: payload_offset + n * block_size for n, block in enumerate(order)}
    for i, state in enumerate(states):
        value = state
        if state == 6:
            value |= slot[i]
            chunk = payload[i * block_size:(i + 1) * block_size]
            image[slot[i]:slot[i] + len(chunk)] = chunk
        struct.pack_into('<Q', image, 2 * MB + 8 * (i + i // ratio), value)
    path.write_bytes(image)
    return path
