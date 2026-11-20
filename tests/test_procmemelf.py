from malduck import procmem, procmemelf


def test_hello():
    with procmemelf.from_file("tests/files/hello", image=True) as pelf:
        assert pelf.imgbase == 0x0
        assert pelf.readv(pelf.imgbase, 4) == b"\x7fELF"
        assert pelf.elf.elfclass == 64
        assert pelf.elf.get_machine_arch() == 'x64'
        assert pelf.elf.little_endian


def test_hello_static():
    with procmemelf.from_file("tests/files/hello_static", image=True) as pelf:
        assert pelf.imgbase == 0x400000
        assert pelf.readv(pelf.imgbase, 4) == b"\x7fELF"
        assert pelf.elf.elfclass == 64
        assert pelf.elf.get_machine_arch() == 'x64'
        assert pelf.elf.little_endian
        assert pelf.imgend == 7159808
        

def test_hello_32():
    with procmemelf.from_file("tests/files/hello_32", image=True) as pelf:
        assert pelf.imgbase == 0x0
        assert pelf.readv(pelf.imgbase, 4) == b"\x7fELF"
        assert pelf.elf.elfclass == 32
        assert pelf.elf.get_machine_arch() == 'x86'
        assert pelf.elf.little_endian
        assert pelf.imgend == 8192
        

def test_hello_32_static():
    with procmemelf.from_file("tests/files/hello_32_static", image=True) as pelf:
        assert pelf.imgbase == 0x8048000
        assert pelf.readv(pelf.imgbase, 4) == b"\x7fELF"
        assert pelf.elf.elfclass == 32
        assert pelf.elf.get_machine_arch() == 'x86'
        assert pelf.elf.little_endian
        assert pelf.imgend == 135200768


def test_hidden_32_static():
    with procmemelf.from_file("tests/files/hidden_32_static", image=True) as pelf:
        assert pelf.imgbase == 0x8048000
        assert pelf.readv(pelf.imgbase, 4) == b"\x7fELF"
        assert pelf.elf.elfclass == 32
        assert pelf.elf.get_machine_arch() == 'x86'
        assert pelf.elf.little_endian
        hidden_code = b"\x50\x53\x51\x52\xba\x0f\x00\x00\x00\xb9\x24\xd2\x0e\x08\xbb\x01\x00\x00\x00\xb8\x04\x00\x00"\
                      b"\x00\xcd\x80\x5a\x59\x5b\x58\x68\x73\x87\x04\x08\xc3\x28\x68\x69\x64\x64\x65\x6e\x20\x63\x6f"\
                      b"\x64\x65\x21\x29\x0a"
        assert pelf.readv(0x80ed200, len(hidden_code)) == hidden_code
        assert pelf.imgend == 135200768


def test_carved_elf_image_coords():
    with open("tests/files/hello_static", "rb") as f:
        elf_data = f.read()
    # ELF embedded at non-zero offset in a larger dump
    mem = procmem(b"\xcc" * 0x200 + elf_data, base=0x700000)
    pelf = procmemelf.from_memory(mem, base=0x700200, image=True)
    assert pelf.imgbase == 0x400000
    assert pelf.readv(pelf.imgbase, 4) == b"\x7fELF"
    # Regions keep offsets in the coordinate system of the underlying dump
    assert pelf.regions[0].offset == 0x200
    # Dump offset of the embedded ELF start maps to the image base
    assert pelf.p2v(0x200) == pelf.imgbase
    # Hits located before the embedded ELF must not be mapped into the image
    assert pelf.p2v(0x100) is None
    # Reads through the image view return the same bytes as the dump buffer
    assert pelf.readv(pelf.imgbase, 16) == mem.readp(0x200, 16)
