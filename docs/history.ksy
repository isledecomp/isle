meta:
  id: history
  title: Score History Save File
  application: LEGO Island
  file-extension: gsi
  license: CC0-1.0
  endian: le
doc: |
  Score history save data for LEGO Island (1997). Stores up to 20 player
  score entries, tracking high scores across all missions and characters.

  The file is located at `<save_path>/History.gsi` where save_path is
  typically the game's installation directory.

seq:
  - id: next_player_id
    type: s2
    doc: |
      The next player ID to be assigned when a new player profile is created.
      Increments each time a new player is added, ensuring unique IDs.
  - id: count
    type: s2
    doc: Number of score entries in the history (0-20 max).
  - id: entries
    type: score_entry
    repeat: expr
    repeat-expr: count
    doc: Array of score history entries, sorted by total score descending.

types:
  score_entry:
    doc: |
      A single score history entry containing a player's high scores across
      all minigames and characters. Total serialized size is 45 bytes
      (2 for index + 43 for score_item data).
    seq:
      - id: index
        type: s2
        doc: Array index of this entry (0 to count-1). Stored redundantly in file.
      - id: total_score
        type: s2
        doc: Sum of all individual high scores across all missions and actors.
      - id: scores
        type: mission_scores
        doc: High scores organized by mission type, each containing scores per actor.
      - id: name
        type: username
        doc: The player's username associated with these scores.
      - id: player_id
        type: s2
        doc: Unique player identifier matching the player's profile.

  mission_scores:
    doc: |
      High scores for all 5 missions. Each mission contains scores for all
      5 playable actors.
    seq:
      - id: car_race
        type: actor_scores
        doc: Car Race mission high scores.
      - id: jetski_race
        type: actor_scores
        doc: Jetski Race mission high scores.
      - id: pizza_delivery
        type: actor_scores
        doc: Pizza Delivery mission high scores.
      - id: tow_track
        type: actor_scores
        doc: Tow Track mission high scores.
      - id: ambulance
        type: actor_scores
        doc: Ambulance mission high scores.

  actor_scores:
    doc: |
      High scores for a single mission across all 5 playable actors.
    seq:
      - id: pepper
        type: u1
        enum: score_color
        doc: High score for Pepper.
      - id: mama
        type: u1
        enum: score_color
        doc: High score for Mama.
      - id: papa
        type: u1
        enum: score_color
        doc: High score for Papa.
      - id: nick
        type: u1
        enum: score_color
        doc: High score for Nick.
      - id: laura
        type: u1
        enum: score_color
        doc: High score for Laura.

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

enums:
  score_color:
    0: grey
    1: yellow
    2: blue
    3: red
