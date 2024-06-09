"""Test Cvdump SYMBOLS parser, reading function stack/params"""

from isledecomp.cvdump.symbols import CvdumpSymbolsParser

PROC_WITH_BLOC = """
(000638) S_GPROC32: [0001:000C6135], Cb: 00000361, Type:             0x10ED, RegistrationBook::ReadyWorld
         Parent: 00000000, End: 00000760, Next: 00000000
         Debug start: 0000000C, Debug end: 0000035C
         Flags: Frame Ptr Present
(00067C)  S_BPREL32: [FFFFFFD0], Type:             0x10EC, this
(000690)  S_BPREL32: [FFFFFFDC], Type:             0x10F5, checkmarkBuffer
(0006AC)  S_BPREL32: [FFFFFFE8], Type:             0x10F6, letterBuffer
(0006C8)  S_BPREL32: [FFFFFFF4], Type:      T_SHORT(0011), i
(0006D8)  S_BPREL32: [FFFFFFF8], Type:             0x10F8, players
(0006EC)  S_BPREL32: [FFFFFFFC], Type:             0x1044, gameState
(000704)  S_BLOCK32: [0001:000C624F], Cb: 000001DA,
          Parent: 00000638, End: 0000072C
(00071C)   S_BPREL32: [FFFFFFD8], Type:      T_SHORT(0011), j
(00072C)  S_END
(000730)  S_BLOCK32: [0001:000C6448], Cb: 00000032,
          Parent: 00000638, End: 0000075C
(000748)   S_BPREL32: [FFFFFFD4], Type:             0x10FA, infoman
(00075C)  S_END
(000760) S_END
"""


def test_sblock32():
    """S_END has double duty as marking the end of a function (S_GPROC32)
    and a scope block (S_BLOCK32). Make sure we can distinguish between
    the two and not end a function early."""
    parser = CvdumpSymbolsParser()
    for line in PROC_WITH_BLOC.split("\n"):
        parser.read_line(line)

    # Make sure we can read the proc and all its stack references
    assert len(parser.symbols) == 1
    assert len(parser.symbols[0].stack_symbols) == 8
