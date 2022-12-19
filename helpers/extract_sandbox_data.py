#!/usr/bin/env python3

import sys
import argparse
import r2pipe
import struct

TEXT_SECTION = '__text'
CSTRING_SECTION = '__cstring'
CONST_SECTION = '__const'
DATA_SECTION = '__data'


class Session:
    def __init__(self, radare):
        self.word_size = radare.cmdj('ij')['bin']['bits'] // 8
        self._sections = [Section.from_json(s, radare) for s in radare.cmdj('e cfg.json.num=hex; iSj')]
        self.radare = radare

    def all_sandbox_sections(self):
        result = [s for s in self._sections if s.id.startswith('com.apple.security.sandbox.')]
        if len(result) == 1:
            result += [s for s in self._sections if s.id[0].isdigit() and "TEXT_EXEC" not in s.id and s.size > 0]
        return result

    def section_from_virtual_address(self, virtual_address):
        identifier = self.radare.cmdj(f'iSj. @ 0x{virtual_address:x}')['name']
        return next(s for s in self._sections if s.id == identifier)

    def get_content_from_virtual_address(self, virtual_address, size):
        return self.radare.cmdj(f'b {size}; pxj @ 0x{virtual_address:x}')

    def get_cstring_from_virtual_address(self, virtual_address):
        return self.radare.cmdj(f'pszj @ 0x{virtual_address:x}')['string']


class Section:
    def __init__(self, identifier, vaddr, size, radare):
        self.id = identifier
        self.name = identifier.split('.')[-1]
        self.virtual_address = vaddr
        self.size = size
        self.original_size = size
        self._cached_content = None
        self.radare = radare

    @classmethod
    def from_json(cls, data, radare):
        identifier = data['name']
        vaddr = int(data['vaddr'], 16)
        vsize = data['vsize']
        return Section(identifier, vaddr, vsize, radare)

    @property
    def content(self):
        if self._cached_content is None:
            self._cached_content = self.radare.cmdj(f's {self.virtual_address}; b {self.size}; pxj')
        return self._cached_content

    def search_all(self, needle):
        if isinstance(needle, str):
            needle = needle.encode('utf-8')
        raw_needle = ''.join([f'{b:02x}' for b in needle])
        raw_commands = ';'.join(self._make_search_config_commands() + [
            'e search.show=false',
            f'/xj {raw_needle}',
        ])
        matches = self.radare.cmdj(raw_commands)
        return [int(m['offset'], 16) - self.virtual_address for m in matches]

    def search_instructions(self, sequence):
        raw_sequence = ';'.join(sequence)
        return self.radare.cmdj(';'.join(self._make_search_config_commands() + [
            f'""/adj {raw_sequence}',
        ]))

    def _make_search_config_commands(self):
        return [
            'b 0x100000',
            'e search.in=range',
            f'e search.from=0x{self.virtual_address:x}',
            f'e search.to=0x{self.virtual_address + self.size:x}',
        ]


def unpack(bytes_list):
    """Unpacks bytes

    The information is stored as little endian so '<' is needed.
    For 32bit 'I' is needed and for 64bit 'Q'.

    Args:
        bytes_list: A packed list of bytes.

    Returns:
        The unpacked 'higher-order' equivalent.
    """

    if len(bytes_list) == 4:
        return struct.unpack('<I', bytes(bytes_list))[0]

    return struct.unpack('<Q', bytes(bytes_list))[0]


def binary_get_string_from_address(session: Session, vaddr: int):
    """Returns the string from a given MachO binary at a given virtual address.

        Note: The virtual address must be in the CSTRING section.

        Args:
            session: A Session instance.
            vaddr: An address.

        Returns:
            A string with the content stored at the given virtual address.

        Raises:
            LIEF_ERR("Can't find a segment associated with the virtual address
             0x{:x}", address);
    """

    section = get_section_from_segment(session, "__TEXT", CSTRING_SECTION)
    if not is_vaddr_in_section(vaddr, section):
        return None

    str = ''
    while True:
        try:
            byte = session.get_content_from_virtual_address(vaddr, 1)
        except(Exception,):
            return None

        if byte is None or len(byte) == 0:
            return None

        byte = byte[0]
        if byte == 0:
            break

        vaddr += 1
        str += chr(byte)

    return str


def untag_pointer(tagged_pointer):
    """Returns the untagged pointer.

    On iOS 12 the first 16 bits(MSB) of a pointer are used to store extra
    information. We say that the pointers from iOS 12 are tagged.
    The pointers should have the 2 first bytes 0xffff, the next digits should
    be fff0 and the pointed-to values should be multiple of 4.
    More information can be found here:
    https://bazad.github.io/2018/06/ios-12-kernelcache-tagged-pointers/

    Args:
        tagged_pointer: a pointer with the first 16 bits used to store extra
                        information.

    Returns:
        A pointer with the 'tag' removed and starting with 0xffff
        (the traditional way).
    """

    return (tagged_pointer & ((1 << 48) -1)) | (0xffff << 48)


def get_section_from_segment(session,
                             segment_name: str, section_name: str):
    """This can be used for retrieving const, cstring and data sections.
    Const section contains two tables: one with the names of the sandbox
    profile and one with the content of the sandbox profile.
    This section is in the __DATA segment.

    Constant string section (cstring) contains the names of the profiles.
    This section is in the __TEXT segment.

    Data section contains the structures describing the content of the
    profiles and the content itself.
    This section is in the __DATA segment.

    Args:
        session: A Session instance.
        segment_name: The segment name (can be __DATA or __TEXT).
        section_name: The section name (can be CSTRING_SECTION, CONST_SECTION,
                      DATA_SECTION, all of them are macros)

    Returns:
        A binary section with the name given.
    """

    name_suffix = f".{segment_name}.{section_name}"
    return next((s for s in session.all_sandbox_sections() if s.id.endswith(name_suffix)), None)


def get_xref(session, vaddr: int):
    """Custom cross reference implementation which supports tagged pointers
    from iOS 12. Searches for pointers in the given MachO binary to the given
    virtual address.

    Args:
        session: A Session instance.
        vaddr: An address.

    Returns:
        A list with all the pointers to the given virtual address.
    """

    ans = []
    word_size = session.word_size

    if word_size == 8:
        raw_pointer_value = struct.pack('<Q', vaddr)
    else:
        raw_pointer_value = struct.pack('<I', vaddr)

    for sect in session.all_sandbox_sections():
        for match in sect.search_all(raw_pointer_value):
            if match % word_size == 0:
                ans.append(sect.virtual_address + match)

    return ans


def get_tables_section(session):
    """Searches for the section containing the sandbox operations table and
    the sandbox binary profiles for older versions of iOS.

    Args:
        session: A Session instance.

    Returns:
        A binary section.
    """

    str_sect = get_section_from_segment(session, "__TEXT", CSTRING_SECTION)
    strs = str_sect.search_all('default\x00')

    for s in strs:
        vaddr_str = str_sect.virtual_address + s
        xref_vaddrs = get_xref(session, vaddr_str)

        if len(xref_vaddrs) > 0:
            sects = [session.section_from_virtual_address(x) for x in xref_vaddrs]
            sects = [s for s in sects if 'const' in s.name.lower()]
            assert len(sects) >= 1 and all([sects[0] == s for s in sects])
            return sects[0]

    seg = binary.get_segment('__DATA')
    if seg:
        sects = [s for s in seg.sections if s.name == CONST_SECTION]
        assert len(sects) <= 1

        if len(sects) == 1:
            return sects[0]

    return binary.get_section(CONST_SECTION)


def is_vaddr_in_section(vaddr, section):
    """Checks if given virtual address is inside given section.

    Args:
        vaddr: A virtual address.
        section: A section of the binary.

    Returns:
        True: if the address is inside the section
        False: Otherwise
    """

    return vaddr >= section.virtual_address \
        and vaddr < section.virtual_address + section.size


def unpack_pointer(addr_size, session: Session, vaddr):
    """Unpacks a pointer and untags it if it is necessary.

    Args:
        session: A Session instance.
        vaddr: A virtual address.
        addr_size: The size of an address (4 or 8).

    Returns:
        A pointer.
    """

    ptr = unpack(
        session.get_content_from_virtual_address(vaddr, addr_size))
    if addr_size == 8:
        ptr = untag_pointer(ptr)
    return ptr


def extract_data_tables_from_section(session: Session, to_data, section):
    """ Generic implementation of table search. A table is formed of adjacent
    pointers to data.

    Args:
        session: A Session instance.
        to_data: Function that checks if the data is valid. This function
                 returns None for invalid data and anything else otherwise.
        section: A section of the binary.

    Returns:
            An array of tables (arrays of data).
    """

    addr_size = session.word_size
    start_addr = section.virtual_address
    end_addr = section.virtual_address + section.size
    tables = []
    vaddr = start_addr

    while vaddr <= end_addr - addr_size:
        ptr = unpack_pointer(addr_size, session, vaddr)

        data = to_data(session, ptr)
        if data is None:
            vaddr += addr_size
            continue

        table = [data]
        vaddr += addr_size

        while vaddr <= end_addr - addr_size:
            ptr = unpack_pointer(addr_size, session, vaddr)

            data = to_data(session, ptr)
            if data is None:
                break

            table.append(data)
            vaddr += addr_size

        if table not in tables:
            tables.append(table)

        vaddr += addr_size

    return tables


def extract_string_tables(session: Session):
    """Extracts string tables from the given MachO binary.

    Args:
        session: A Session instance.

    Returns:
        The string tables.
    """

    return extract_data_tables_from_section(session,
                                            binary_get_string_from_address,
                                            get_tables_section(session))


def extract_separated_profiles(session: Session, string_tables):
    """Extract separated profiles from given MachO binary. It requires all
    string tables. This function is intended to be used for older version
    of iOS(<=7) because in newer versions the sandbox profiles are bundled.

    Args:
        session: A Session instance.
        string_tables: The extracted string tables.

    Returns:
        A zip object with profiles.
    """

    def get_profile_names():
        """Extracts the profile names.

            Returns:
                A list with the names of the sandbox profiles.
        """

        def transform(arr):
            if len(arr) <= 3:
                return None

            ans = []
            tmp = []
            for val in arr:
                if val in ['default', '0123456789abcdef']:
                    ans.append(tmp)
                    tmp = []
                else:
                    tmp.append(val)
            ans.append(tmp)
            return ans

        def get_sol(posible):
            ans = [arr for arr in posible
                   if 'com.apple.sandboxd' in arr]
            assert len(ans) == 1
            return ans[0]

        profile_names_v = [transform(v) for v in string_tables]
        profile_names_v = [v for v in profile_names_v if v is not None]
        profile_names_v = [x for v in profile_names_v for x in v]
        return get_sol(profile_names_v)

    def get_profile_contents():
        """Extracts the profile names.

            Returns:
                 The contents of the sandbox profiles.
        """

        def get_profile_content(binary, vaddr):
            addr_size = binary_get_word_size(binary)
            section = get_section_from_segment(session, "__DATA", DATA_SECTION)

            if not is_vaddr_in_section(vaddr, section):
                return None

            data = binary.get_content_from_virtual_address(vaddr, 2 * addr_size)
            if len(data) != 2 * addr_size:
                return None

            data_vaddr = unpack(data[:addr_size])
            size = unpack(data[addr_size:])
            if not is_vaddr_in_section(vaddr, section):
                return None

            data = binary.get_content_from_virtual_address(data_vaddr, size)
            if len(data) != size:
                return None
            return bytes(data)

        contents_v = [v for v in
                      extract_data_tables_from_section(binary,
                                                       get_profile_content,
                                                       get_tables_section(radare))
                      if len(v) > 3]

        assert len(contents_v) == 1
        return contents_v[0]

    profile_names = get_profile_names()
    profile_contents = get_profile_contents()

    assert len(profile_names) == len(profile_contents)
    return zip(profile_names, profile_contents)


def extract_sbops(string_tables):
    """ Extracts sandbox operations from a given MachO binary.
    If the sandbox profiles are stored either in sandboxd or sandbox kernel
    extension, the operations are stored always in the kernel extension.
    The sandbox operations are stored similar to the separated sandbox profiles
    but this time we have only one table: the name table.

    Args:
        string_tables: The binary's string tables.

    Returns:
        The sandbox operations.
    """

    def transform(arr):
        if len(arr) <= 3:
            return None

        idxs = []
        for idx, val in enumerate(arr):
            if val == 'default':
                idxs.append(idx)

        return [arr[idx:] for idx in idxs]

    def get_sol(possible):
        assert len(possible) >= 1

        sol = []
        if len(possible) > 1:
            cnt = min(len(arr) for arr in possible)
            for vals in zip(*[val[:cnt] for val in possible]):
                if not all(val == vals[0] for val in vals):
                    break
                sol.append(vals[0])
        else:
            sol.append(possible[0][0])
            for pos in possible[0][1:]:
                if pos in ['HOME', 'default']:
                    break
                sol.append(pos)

        return sol

    sbops_v = [transform(v) for v in string_tables]
    sbops_v = [v for v in sbops_v if v is not None and v != []]
    sbops_v = [x for v in sbops_v for x in v]

    return get_sol(sbops_v)


def get_ios_major_version(version: str):
    """Extracts the major iOS version from a given version.

        Args:
            version: A string with the 'full' version.
        Returns:
            An integer with the major iOS version.

    """

    return int(version.split('.')[0])


def findall(searching, pattern):
    """Finds all the substring in the given string.

    Args:
        searching: A string.
        pattern: A pattern that needs to be searched in the searching string.

    Returns:
        The indexes of all substrings equal to pattern inside searching string.
    """

    i = searching.find(pattern)
    while i != -1:
        yield i
        i = searching.find(pattern, i + 1)


def check_regex(data: bytes, base_index: int, ios_version: int):
    """ Checks if the regular expression (from sandbox profile) at offset
    base_index from data is valid for newer versions of iOS(>=8).

    Args:
        data: An array of bytes.
        base_index: The starting index.
        ios_version: An integer representing the iOS version.

    Returns:
        True: if the regular expression is valid for iOS version >= 8.
        False: otherwise.
    """

    if base_index + 0x10 > len(data):
        return False

    if ios_version >= 13:
        size = struct.unpack('<H', data[base_index: base_index + 0x2])[0]
        version = struct.unpack('>I', data[base_index + 0x2: base_index + 0x6])[0]
    else:
        size = struct.unpack('<I', data[base_index: base_index + 0x4])[0]
        version = struct.unpack('>I', data[base_index + 0x4: base_index + 0x8])[0]

    if size > 0x1000 or size < 0x8 or base_index + size + 4 > len(data):
        return False

    if version != 3:
        return False

    if ios_version >= 13:
        sub_size = struct.unpack('<H', data[base_index + 0x6: base_index + 0x8])[0]
    else:
        sub_size = struct.unpack('<H', data[base_index + 0x8: base_index + 0xa])[0]

    return size == sub_size + 6


def unpack_for_newer_ios(base_index, count, data):
    """Unpacking for newer iOS versions (>= 13).

    Args:
        base_index: The starting index.
        count: Bundle size.
        data: An array of bytes.
    Returns:
        The new base index and an offset.
    """

    re_offset = base_index + 12
    op_nodes_count = struct.unpack('<H', data[base_index + 2:base_index + 4])[0]
    sb_ops_count = struct.unpack('<H', data[base_index + 4:base_index + 6])[0]
    sb_profiles_count = struct.unpack('<H', data[base_index + 6:base_index + 8])[0]
    global_table_count = struct.unpack('<B', data[base_index + 10:base_index + 11])[0]
    debug_table_count = struct.unpack('<B', data[base_index + 11:base_index + 12])[0]
    # base_index will be now at the of op_nodes
    base_index += 12 + (count + global_table_count + debug_table_count) * 2 + \
                  (2 + sb_ops_count) * 2 * sb_profiles_count + \
                  op_nodes_count * 8 + 4

    return base_index, re_offset


def check_bundle(data: bytes, base_index: int, ios_version: int):
    """Checks if the sandbox profile bundle at offset base_index from data
    is valid for the given ios_version. Note that sandbox profile bundles are
    used for newer versions of iOS(>=8).

    Args:
        data: An array of bytes.
        base_index: The starting index.
        ios_version: An integer representing the iOS version.

    Returns:
        True: if the sandbox profile bundle is valid.
        False: otherwise.
    """

    if len(data) - base_index < 50:
        return False
    re_offset, aux = struct.unpack('<2H', data[base_index + 2:base_index + 6])

    if ios_version >= 13:
        count = struct.unpack('<H', data[base_index + 8:base_index + 10])[0]
        if count < 0x10:
            return False
    elif ios_version >= 12:
        count = (aux - re_offset) * 4
        # bundle should be big
        if count < 0x10:
            return False
    else:
        count = aux

    if count > 0x1000 or re_offset < 0x10:
        return False

    if ios_version >= 13:
        base_index, re_offset = unpack_for_newer_ios(base_index, count, data)

    else:
        re_offset = base_index + re_offset * 8
        if len(data) - re_offset < count * 2:
            return False

    for off_index in range(re_offset, re_offset + 2 * count, 2):
        index = struct.unpack('<H', data[off_index:off_index + 2])[0]
        if index == 0:
            if off_index < re_offset + 2 * count - 4:
                return False
            continue

        index = base_index + index * 8

        if not check_regex(data, index, ios_version):
            return False

    return True


def extract_bundle_profiles(session: Session, ios_version: int):
    """Extracts sandbox profile bundle from the given MachO binary which was
    extracted from a device with provided ios version.

    Args:
        session: A Session instance.
        ios_version: The major ios version.

    Returns:
        The sandbox profile bundle.
    """

    if ios_version >= 16:
        text = get_section_from_segment(session, "__TEXT_EXEC", TEXT_SECTION)
        r = session.radare
        for match in text.search_instructions(['adrp x0', 'add x0',
                                               'adrp x1', 'add x1',
                                               'adrp x2', 'add x2',
                                               'adrp x4', 'add x4',
                                               'mov w3', 'movk w3',
                                               'bl']):
            start_address = int(match['offset'], 16)
            bl_address = start_address + match['len'] - 4

            regs = r.cmdj(';'.join([
                f's 0x{start_address:x}',
                'aei',
                'aeip',
                f'aesu 0x{bl_address:x}',
                'arj'
            ]))

            name_cstr = int(regs['x1'], 16)
            collection_base = int(regs['x2'], 16)
            collection_size = int(regs['x3'], 16)

            name = session.get_cstring_from_virtual_address(name_cstr)
            if name == 'builtin collection':
                return bytes(session.get_content_from_virtual_address(collection_base, collection_size))

        assert False

    matches = []
    for section in session.all_sandbox_sections():
        if section.name == TEXT_SECTION:
            continue

        content = bytes(section.content)
        for index in section.search_all([0x00, 0x80]):
            address = section.virtual_address + index
            if check_bundle(content, index, ios_version):
                matches.append(content[index:])

    assert len(matches) == 1
    return matches[0]


def main(args):
    if args.input_binary is not None:
        r = r2pipe.open(args.input_binary)
    else:
        r = r2pipe.open()
    session = Session(r)

    retcode = 0
    string_tables = extract_string_tables(session)

    if args.sbops_file is not None:
        sbops = extract_sbops(string_tables)
        sbops_str = '\n'.join(sbops)
        if args.sbops_file == '-':
            print(sbops_str)
        else:
            try:
                with open(args.sbops_file, 'w') as file:
                    file.write(sbops_str + '\n')
            except IOError as exception:
                retcode = exception.errno
                print(exception, file=sys.stderr)

    if args.sbs_dir is not None:
        if args.version <= 8:
            profiles = extract_separated_profiles(binary, string_tables)
            for name, content in profiles:
                try:
                    with open(args.sbs_dir + '/' + name + '.sb.bin', 'wb') as file:
                        file.write(content)
                except IOError as exception:
                    retcode = exception.errno
                    print(exception, file=sys.stderr)
        else:
            content = extract_bundle_profiles(session, args.version)
            try:
                with open(args.sbs_dir + '/sandbox_bundle', 'wb') as file:
                    file.write(content)
            except IOError as exception:
                retcode = exception.errno
                print(exception, file=sys.stderr)
    exit(retcode)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Sandbox profiles and operations extraction tool(iOS <9)')
    parser.add_argument('version', metavar='VERSION',
                        type=get_ios_major_version, help='iOS version for given binary')
    parser.add_argument('-i', '--input-binary',
                        help='path to sandbox(seatbelt) kernel exenstion' +
                        '(iOS 4-12) in order to extract sandbox operations OR ' +
                        'path to sandboxd(iOS 5-8) / sandbox(seatbelt) kernel extension' +
                        '(iOS 4 and 9-12) in order to extract sandbox profiles')
    parser.add_argument('-o', '--output-sbops', dest='sbops_file', type=str,
                        default=None,
                        help='path to sandbox profile operations store file')
    parser.add_argument('-O', '--output-profiles', dest='sbs_dir', type=str,
                        default=None,
                        help='path to directory in which sandbox profiles should be stored')

    args = parser.parse_args()
    exit(main(args))
