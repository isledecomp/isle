meta:
  id: dta
  title: Animation Data File
  application: LEGO Island
  file-extension: dta
  license: CC0-1.0
  endian: le

doc: |
  Animation data file format for LEGO Island (1997). Contains animation
  information for world objects including their positions, orientations,
  and associated models.

  DTA files are located at `<install_path>/lego/data/<world>inf.dta` where
  <world> is the world name (e.g., "isle", "act1", "act2m", etc.). They are
  loaded by LegoAnimationManager::LoadWorldInfo() to populate animation
  information for the current world.

  File structure:
  1. Header - version (must be 3) and animation count
  2. AnimInfo entries - animation references with nested model placement data

seq:
  - id: version
    type: u4
    doc: |
      File format version. Must be 3 for valid files.
      The game rejects files with mismatched versions.
  - id: num_anims
    type: u2
    doc: Number of animation info entries in this file.
  - id: anims
    type: anim_info
    repeat: expr
    repeat-expr: num_anims
    doc: Animation information entries.

types:
  anim_info:
    doc: |
      Animation information for a single animation (AnimInfo struct).
      Contains metadata about the animation and a list of models involved.
      Parsed by LegoAnimationManager::ReadAnimInfo().
    seq:
      - id: name_length
        type: u1
        doc: Length of the animation name in bytes.
      - id: name
        type: str
        size: name_length
        encoding: ASCII
        doc: |
          Animation name identifier. The last two characters are used
          to look up a character index via GetCharacterIndex().
      - id: object_id
        type: u4
        doc: Object ID used to identify this animation in the game.
      - id: location
        type: s2
        doc: |
          Location index referencing a LegoLocation. A value of -1
          indicates no specific location is assigned.
      - id: unk_0x0a
        type: u1
        doc: Boolean flag (MxBool). Purpose unknown.
      - id: unk_0x0b
        type: u1
        doc: Unknown byte field.
      - id: unk_0x0c
        type: u1
        doc: Unknown byte field.
      - id: unk_0x0d
        type: u1
        doc: Unknown byte field.
      - id: unk_0x10
        type: f4
        repeat: expr
        repeat-expr: 4
        doc: Array of 4 unknown float values (16 bytes total).
      - id: model_count
        type: u1
        doc: Number of model entries that follow.
      - id: models
        type: model_info
        repeat: expr
        repeat-expr: model_count
        doc: Model information for each model in this animation.

  model_info:
    doc: |
      Model information defining position and orientation for a single
      model within an animation (ModelInfo struct). Used to place characters
      and objects in the world during animation playback.
      Parsed by LegoAnimationManager::ReadModelInfo().
    seq:
      - id: name_length
        type: u1
        doc: Length of the model name in bytes.
      - id: name
        type: str
        size: name_length
        encoding: ASCII
        doc: |
          Model name used to look up the character or vehicle.
          Examples: "caprc01" (race car), "irt001d1" (character).
      - id: unk_0x04
        type: u1
        doc: Unknown byte field.
      - id: position
        type: vertex3
        doc: World position (X, Y, Z) of the model.
      - id: direction
        type: vertex3
        doc: Forward direction vector of the model.
      - id: up
        type: vertex3
        doc: Up direction vector of the model.
      - id: unk_0x2c
        type: u1
        doc: |
          Boolean flag. When non-zero, this model is considered a vehicle
          and tracked in the animation's vehicle list (m_unk0x2a).

  vertex3:
    doc: A 3D point or vector with X, Y, Z components.
    seq:
      - id: x
        type: f4
        doc: X component.
      - id: y
        type: f4
        doc: Y component.
      - id: z
        type: f4
        doc: Z component.
