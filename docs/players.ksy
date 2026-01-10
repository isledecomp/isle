meta:
  id: players
  title: Players Save File
  application: LEGO Island
  file-extension: gsi
  license: CC0-1.0
  endian: le
doc: |
  Player profile save data for LEGO Island (1997). Stores up to 9 player
  profiles, each identified by a 7-character username. Usernames are stored
  as letter indices rather than ASCII characters.

  The file is located at `<save_path>/Players.gsi` where save_path is
  typically the game's installation directory.

seq:
  - id: count
    type: s2
    doc: |
      Number of saved player profiles. The game supports a maximum of 9
      players; when a 10th player is added, the oldest profile is deleted.
  - id: entries
    type: username
    repeat: expr
    repeat-expr: count
    doc: Array of player username entries, ordered by most recently played.

types:
  username:
    doc: |
      A player username consisting of up to 7 letters. Each letter is stored
      as a signed 16-bit index. The struct is always 14 bytes (0x0e).
    seq:
      - id: letters
        type: s2
        repeat: expr
        repeat-expr: 7
        doc: |
          Letter indices for the username characters:
          - 0-25: Standard alphabet (0=A, 1=B, ..., 25=Z)
          - 29: International ä, å, or ñ (language-dependent)
          - 30: International ö or æ (language-dependent)
          - 31: International ß or ø (language-dependent)
          - 32: International ü
          - -1 (0xFFFF): Empty/unused position

          Unused positions are filled with -1. A name shorter than 7
          characters will have trailing -1 values.
