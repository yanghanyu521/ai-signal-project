"""Minimal bounded PE/ELF file-offset mappings; never loads executable images."""
import struct


def sections(data):
    """Return pointer width and (file offset, file size, VA, executable) rows."""
    rows = []
    if data.startswith(b'MZ'):
        pe = struct.unpack_from('<I', data, 60)[0]
        if data[pe:pe+4] != b'PE\0\0':
            raise ValueError('invalid_pe_signature')
        count = struct.unpack_from('<H', data, pe+6)[0]
        optional_size = struct.unpack_from('<H', data, pe+20)[0]
        optional = pe+24
        magic = struct.unpack_from('<H', data, optional)[0]
        if magic not in (0x10b, 0x20b) or count > 96:
            raise ValueError('unsupported_pe_layout')
        width = 8 if magic == 0x20b else 4
        base = struct.unpack_from('<Q' if width == 8 else '<I', data, optional+(24 if width == 8 else 28))[0]
        for i in range(count):
            pos = optional+optional_size+i*40
            virtual, size, offset = struct.unpack_from('<III', data, pos+12)
            flags = struct.unpack_from('<I', data, pos+36)[0]
            if offset+size > len(data):
                raise ValueError('invalid_pe_section')
            rows.append((offset, size, base+virtual, bool(flags & 0x20000000)))
    elif data.startswith(b'\x7fELF'):
        if data[4:6] != b'\x02\x01':
            raise ValueError('unsupported_elf_layout')
        width = 8
        table = struct.unpack_from('<Q', data, 40)[0]
        stride, count = struct.unpack_from('<HH', data, 58)
        if stride < 64 or count > 4096 or table+stride*count > len(data):
            raise ValueError('invalid_elf_section_table')
        for i in range(count):
            pos = table+i*stride
            kind = struct.unpack_from('<I', data, pos+4)[0]
            flags, va, offset, size = struct.unpack_from('<QQQQ', data, pos+8)
            if kind == 8 or not (flags & 2):  # NOBITS or not allocated
                continue
            if offset+size > len(data):
                raise ValueError('invalid_elf_section')
            rows.append((offset, size, va, bool(flags & 4)))
    else:
        raise ValueError('unsupported_binary_layout')
    return width, rows


def go_literal_lengths(data, offset, max_length):
    """Return verified pointer+length descriptors, not guessed pool delimiters."""
    width, rows = sections(data)
    containing = next((r for r in rows if r[0] <= offset < r[0]+r[1]), None)
    if containing is None:
        return []
    address = containing[2]+offset-containing[0]
    fmt = '<Q' if width == 8 else '<I'
    needle = struct.pack(fmt, address)
    found = []
    for start, size, _, executable in rows:
        if executable:
            continue
        pos = start
        for _ in range(128):
            pos = data.find(needle, pos, start+size)
            if pos < 0:
                break
            if pos % width == 0 and pos+width*2 <= start+size:
                length = struct.unpack_from(fmt, data, pos+width)[0]
                if 32 <= length <= max_length and offset+length <= containing[0]+containing[1]:
                    found.append((length, pos))
            pos += 1
    return sorted(set(found))
