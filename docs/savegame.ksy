meta:
  id: savegame
  title: Main Save Game File
  application: LEGO Island
  file-extension: gs
  license: CC0-1.0
  endian: le
doc: |
  Main save game file format for LEGO Island (1997). Stores complete game
  progress including customization, mission scores, and world state.

  The file is located at `<save_path>/G<slot>.GS` where slot is 0-9 and
  save_path is typically the game's installation directory.

  File structure:
  1. Header (version, player ID, act, actor)
  2. Variables section (vehicle colors, background color, light position)
  3. Character manager data (66 actors)
  4. Plant manager data (81 plants)
  5. Building manager data (16 buildings)
  6. Game states (mission progress, scores, etc.)
  7. Previous area (for Act 2/3 saves)

seq:
  - id: version
    type: s4
    doc: |
      File format version. Must be 0x1000c (65548) for valid saves.
      The game rejects files with mismatched versions.
  - id: player_id
    type: s2
    doc: Current player's unique ID from the player profile.
  - id: current_act
    type: u2
    enum: act
    doc: Current game act (0 = Act 1, 1 = Act 2, 2 = Act 3).
  - id: actor_id
    type: u1
    enum: actor
    doc: Currently selected playable character.
  - id: variables
    type: variable
    repeat: until
    repeat-until: _.is_end_marker
    doc: |
      Vehicle customization colors and game settings. Contains 43 color
      variables, background color, light position, and ends with
      "END_OF_VARIABLES" marker.
  - id: characters
    type: character_entry
    repeat: expr
    repeat-expr: 66
    doc: Character manager data for all 66 actors in the game.
  - id: plants
    type: plant_entry
    repeat: expr
    repeat-expr: 81
    doc: Plant manager data for all 81 plants in the game world.
  - id: buildings
    type: building_entry
    repeat: expr
    repeat-expr: 16
    doc: Building manager data for all 16 buildings in the game world.
  - id: building_next_variant
    type: u1
    doc: Next building variant to use (cycles through variants).
  - id: state_count
    type: s2
    doc: Number of serialized game states that follow.
  - id: states
    type: game_state
    repeat: expr
    repeat-expr: state_count
    doc: Serialized game state objects (mission progress, scores, etc.).
  - id: previous_area
    type: s2
    doc: |
      Previous area ID for Act 2/3 saves. Set to -1 (undefined) for Act 1.
      Used to restore the player's location when loading a save.

types:
  variable:
    doc: |
      A named variable with a string value. Used for vehicle colors and
      game settings. The "END_OF_VARIABLES" marker has no value.
    seq:
      - id: name_length
        type: u1
        doc: Length of variable name in bytes.
      - id: name
        type: str
        size: name_length
        encoding: ASCII
        doc: Variable name (e.g., "c_dbbkfny0", "backgroundcolor").
      - id: value_length
        type: u1
        if: not is_end_marker
        doc: Length of variable value in bytes.
      - id: value
        type: str
        size: value_length
        encoding: ASCII
        if: not is_end_marker
        doc: |
          Variable value. For colors this is a color name like "lego red".
          For backgroundcolor this is "set R G B".
          For lightposition this is a number "1" or "2".
    instances:
      is_end_marker:
        value: name == "END_OF_VARIABLES"
        doc: True if this is the end-of-variables marker.

  character_entry:
    doc: |
      Character customization and state for a single actor.
      Total size is 16 bytes per character.
    seq:
      - id: sound
        type: s4
        doc: Sound/voice variant index.
      - id: move
        type: s4
        doc: Movement/animation variant index.
      - id: mood
        type: u1
        doc: Character mood state.
      - id: hat_part_name_index
        type: u1
        doc: Hat part name table index.
      - id: hat_name_index
        type: u1
        doc: Hat variant name table index.
      - id: infogron_name_index
        type: u1
        doc: Torso (infogron) variant name table index.
      - id: armlft_name_index
        type: u1
        doc: Left arm variant name table index.
      - id: armrt_name_index
        type: u1
        doc: Right arm variant name table index.
      - id: leglft_name_index
        type: u1
        doc: Left leg variant name table index.
      - id: legrt_name_index
        type: u1
        doc: Right leg variant name table index.

  plant_entry:
    doc: |
      Plant state data for a single plant in the game world.
      Total size is 12 bytes per plant.
    seq:
      - id: variant
        type: u1
        enum: plant_variant
        doc: Plant type (flower, tree, bush, palm).
      - id: sound
        type: u4
        doc: Sound effect index when interacting.
      - id: move
        type: u4
        doc: Movement/animation state.
      - id: mood
        type: u1
        doc: Plant mood/state value.
      - id: color
        type: u1
        enum: plant_color
        doc: Plant color variant.
      - id: counter
        type: s1
        doc: |
          Growth/interaction counter. Affects plant height.
          Negative values indicate special states.

  building_entry:
    doc: |
      Building state data for a single building in the game world.
      Total size is 10 bytes per building.
    seq:
      - id: sound
        type: u4
        doc: Sound effect index.
      - id: move
        type: u4
        doc: Movement/animation state.
      - id: mood
        type: u1
        doc: Building mood/state value.
      - id: counter
        type: s1
        doc: |
          Interaction counter. Affects building height adjustment.
          Used for destructible buildings.

  game_state:
    doc: |
      A serialized game state object. The name determines the type and
      format of the data that follows.
    seq:
      - id: name_length
        type: s2
        doc: Length of state class name.
      - id: name
        type: str
        size: name_length
        encoding: ASCII
        doc: |
          State class name (e.g., "Act1State", "PizzeriaState").
          Determines the format of the following data.
      - id: data
        type:
          switch-on: name
          cases:
            '"PizzeriaState"': pizzeria_state_data
            '"PizzaMissionState"': pizza_mission_state_data
            '"TowTrackMissionState"': score_mission_state_data
            '"AmbulanceMissionState"': score_mission_state_data
            '"HospitalState"': hospital_state_data
            '"GasStationState"': gas_station_state_data
            '"PoliceState"': police_state_data
            '"JetskiRaceState"': race_state_data
            '"CarRaceState"': race_state_data
            '"LegoJetskiBuildState"': vehicle_build_state_data
            '"LegoCopterBuildState"': vehicle_build_state_data
            '"LegoDuneCarBuildState"': vehicle_build_state_data
            '"LegoRaceCarBuildState"': vehicle_build_state_data
            '"AnimState"': anim_state_data
            '"Act1State"': act1_state_data
        doc: State-specific data. Format depends on state class name.

  pizzeria_state_data:
    doc: |
      Pizzeria state tracking playlist indices for each actor.
      Total size is 10 bytes (5 x S16).
    seq:
      - id: playlist_indices
        type: s2
        repeat: expr
        repeat-expr: 5
        doc: Next playlist index for each of the 5 playable actors.

  pizza_mission_state_data:
    doc: |
      Pizza delivery mission state for all 5 actors.
      Total size is 40 bytes (5 missions x 4 x S16).
    seq:
      - id: missions
        type: pizza_mission_entry
        repeat: expr
        repeat-expr: 5
        doc: Mission data for each playable actor.

  pizza_mission_entry:
    doc: Single actor's pizza mission data (8 bytes).
    seq:
      - id: unk0x06
        type: s2
        doc: Unknown field at offset 0x06.
      - id: counter
        type: s2
        doc: Mission attempt counter.
      - id: score
        type: s2
        doc: Current/last mission score.
      - id: hi_score
        type: s2
        doc: High score for this mission.

  score_mission_state_data:
    doc: |
      Mission state with scores and high scores for all 5 actors.
      Used by TowTrackMissionState and AmbulanceMissionState.
      Total size is 20 bytes (10 x S16).
    seq:
      - id: pe_score
        type: s2
        doc: Pepper's current/last score.
      - id: ma_score
        type: s2
        doc: Mama's current/last score.
      - id: pa_score
        type: s2
        doc: Papa's current/last score.
      - id: ni_score
        type: s2
        doc: Nick's current/last score.
      - id: la_score
        type: s2
        doc: Laura's current/last score.
      - id: pe_high_score
        type: s2
        doc: Pepper's high score.
      - id: ma_high_score
        type: s2
        doc: Mama's high score.
      - id: pa_high_score
        type: s2
        doc: Papa's high score.
      - id: ni_high_score
        type: s2
        doc: Nick's high score.
      - id: la_high_score
        type: s2
        doc: Laura's high score.

  hospital_state_data:
    doc: |
      Hospital interaction state for all actors.
      Total size is 12 bytes (6 x S16).
    seq:
      - id: state_actor
        type: s2
        doc: Current actor state.
      - id: state_pepper
        type: s2
        doc: Pepper's hospital interaction state.
      - id: state_mama
        type: s2
        doc: Mama's hospital interaction state.
      - id: state_papa
        type: s2
        doc: Papa's hospital interaction state.
      - id: state_nick
        type: s2
        doc: Nick's hospital interaction state.
      - id: state_laura
        type: s2
        doc: Laura's hospital interaction state.

  gas_station_state_data:
    doc: |
      Gas station interaction state for all actors.
      Total size is 10 bytes (5 x S16).
    seq:
      - id: pepper_action
        type: s2
        doc: Pepper's gas station action state.
      - id: mama_action
        type: s2
        doc: Mama's gas station action state.
      - id: papa_action
        type: s2
        doc: Papa's gas station action state.
      - id: nick_action
        type: s2
        doc: Nick's gas station action state.
      - id: laura_action
        type: s2
        doc: Laura's gas station action state.

  police_state_data:
    doc: |
      Police station state. Stores the police script ID.
      Total size is 4 bytes (1 x S32).
    seq:
      - id: police_script
        type: s4
        doc: Current police script/animation ID.

  race_state_data:
    doc: |
      Race state with scores for all 5 actors.
      Used by JetskiRaceState and CarRaceState.
      Total size is 25 bytes (5 entries x 5 bytes).
    seq:
      - id: entries
        type: race_entry
        repeat: expr
        repeat-expr: 5
        doc: Race entry for each playable actor.

  race_entry:
    doc: Single actor's race score entry (5 bytes).
    seq:
      - id: id
        type: u1
        doc: Actor ID (1-5).
      - id: last_score
        type: s2
        doc: Score from last race.
      - id: high_score
        type: s2
        doc: Best score (high score).

  vehicle_build_state_data:
    doc: |
      Vehicle build state tracking build progress.
      Used by LegoJetskiBuildState, LegoCopterBuildState,
      LegoDuneCarBuildState, and LegoRaceCarBuildState.
      Total size is 4 bytes (4 x U8).
    seq:
      - id: introduction_counter
        type: u1
        doc: Number of times intro has been shown.
      - id: finished_build
        type: u1
        doc: Whether vehicle build was completed (0/1).
      - id: played_exit_script
        type: u1
        doc: Whether exit animation has played (0/1).
      - id: placed_part_count
        type: u1
        doc: Number of parts placed during current build.

  anim_state_data:
    doc: |
      Animation manager state. Contains extra character ID and
      two variable-length arrays for tracking animation states.
    seq:
      - id: extra_character_id
        type: u4
        doc: Extra character ID.
      - id: anim_count
        type: u4
        doc: Number of animation entries in first array.
      - id: anim_indices
        type: u2
        repeat: expr
        repeat-expr: anim_count
        doc: Animation index values.
      - id: location_flags_count
        type: u4
        doc: Number of location flag entries.
      - id: location_flags
        type: u1
        repeat: expr
        repeat-expr: location_flags_count
        doc: Location flags for animation positions.

  act1_state_data:
    doc: |
      Act 1 state containing named plane data and textures.
      Always contains exactly 7 named planes (for each vehicle type),
      followed by conditional textures based on which planes have names,
      and two final fields.
    seq:
      - id: motocycle_plane
        type: named_plane
        doc: Motorcycle spawn plane.
      - id: bike_plane
        type: named_plane
        doc: Bike spawn plane.
      - id: skateboard_plane
        type: named_plane
        doc: Skateboard spawn plane.
      - id: helicopter_plane
        type: named_plane
        doc: Helicopter spawn plane.
      - id: jetski_plane
        type: named_plane
        doc: Jetski spawn plane.
      - id: dunebuggy_plane
        type: named_plane
        doc: Dune buggy spawn plane.
      - id: racecar_plane
        type: named_plane
        doc: Racecar spawn plane.
      - id: helicopter_textures
        type: act1_texture
        repeat: expr
        repeat-expr: 3
        if: helicopter_plane.name_length > 0
        doc: Helicopter textures (windshield, left jet, right jet).
      - id: jetski_textures
        type: act1_texture
        repeat: expr
        repeat-expr: 2
        if: jetski_plane.name_length > 0
        doc: Jetski textures (front, windshield).
      - id: dunebuggy_texture
        type: act1_texture
        if: dunebuggy_plane.name_length > 0
        doc: Dune buggy front texture.
      - id: racecar_textures
        type: act1_texture
        repeat: expr
        repeat-expr: 3
        if: racecar_plane.name_length > 0
        doc: Racecar textures (front, back, tail).
      - id: dialogue_next_index
        type: s2
        doc: Next dialogue index for Captain Click.
      - id: played_exit_explanation
        type: u1
        doc: Whether exit explanation has been played (0/1).

  act1_texture:
    doc: |
      A texture used for customizable surfaces in Act 1.
      Contains filename and LegoImage bitmap data.
    seq:
      - id: name_length
        type: s2
        doc: Length of texture filename.
      - id: name
        type: str
        size: name_length
        encoding: ASCII
        doc: Texture filename (e.g., "chwind.gif").
      - id: width
        type: u4
        doc: Image width in pixels.
      - id: height
        type: u4
        doc: Image height in pixels.
      - id: palette_count
        type: u4
        doc: Number of palette entries.
      - id: palette
        type: palette_entry
        repeat: expr
        repeat-expr: palette_count
        doc: Palette entries (RGB values).
      - id: bitmap_data
        size: width * height
        doc: Raw pixel data (1 byte per pixel, indexed).

  palette_entry:
    doc: A single RGB palette entry.
    seq:
      - id: red
        type: u1
        doc: Red component (0-255).
      - id: green
        type: u1
        doc: Green component (0-255).
      - id: blue
        type: u1
        doc: Blue component (0-255).

  named_plane:
    doc: |
      A named plane used for actor positioning in Act 1.
      Total size is variable: 2 + name_length + 36 bytes.
    seq:
      - id: name_length
        type: s2
        doc: Length of plane name (S16 format like other strings).
      - id: name
        type: str
        size: name_length
        encoding: ASCII
        doc: Plane name identifier (e.g., "INT43", "EDG02_51").
      - id: position
        type: f4
        repeat: expr
        repeat-expr: 3
        doc: Position vector (X, Y, Z).
      - id: direction
        type: f4
        repeat: expr
        repeat-expr: 3
        doc: Direction/forward vector (X, Y, Z).
      - id: up
        type: f4
        repeat: expr
        repeat-expr: 3
        doc: Up vector (X, Y, Z).

enums:
  act:
    0: act1
    1: act2
    2: act3

  actor:
    0: none
    1: pepper
    2: mama
    3: papa
    4: nick
    5: laura

  plant_variant:
    0: flower
    1: tree
    2: bush
    3: palm

  plant_color:
    0: white
    1: black
    2: yellow
    3: red
    4: green
