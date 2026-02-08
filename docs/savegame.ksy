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
    type: character_manager
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
          For backgroundcolor and tempBackgroundColor this is "set H S V" where
          H, S, V are HSV color values scaled 0-100 (not RGB). The game internally
          converts to RGB using ConvertHSVToRGB().
          For lightposition this is a number "0" through "5" (6 sun positions).
    instances:
      is_end_marker:
        value: name == "END_OF_VARIABLES"
        doc: True if this is the end-of-variables marker.

  character_manager:
    doc: |
      All 66 character entries in the game, in the order defined by g_actorInfoInit.
      Each entry is 16 bytes, for a total of 1056 bytes.
    seq:
      - id: pepper
        type: pepper_character_entry
        doc: Pepper Roni
      - id: mama
        type: standard_character_entry
        doc: Mama Brickolini
      - id: papa
        type: standard_character_entry
        doc: Papa Brickolini
      - id: nick
        type: standard_character_entry
        doc: Nick Brick
      - id: laura
        type: standard_character_entry
        doc: Laura Brick
      - id: infoman
        type: infoman_character_entry
        doc: Infomaniac
      - id: brickstr
        type: standard_character_entry
        doc: Brickster
      - id: studs
        type: standard_character_entry
        doc: Studs Linkin
      - id: rhoda
        type: standard_character_entry
        doc: Rhoda Hogg
      - id: valerie
        type: standard_character_entry
        doc: Valerie Stubbins
      - id: snap
        type: standard_character_entry
        doc: Snap Lockitt
      - id: pt
        type: standard_character_entry
      - id: mg
        type: standard_character_entry
        doc: Margaret Patricia "Maggie" Post
      - id: bu
        type: standard_character_entry
        doc: Buck Pounds
      - id: ml
        type: standard_character_entry
        doc: Ed Mail
      - id: nu
        type: standard_character_entry
        doc: Nubby Stevens
      - id: na
        type: standard_character_entry
        doc: Nancy Nubbins
      - id: cl
        type: standard_character_entry
        doc: Dr. Clickitt
      - id: en
        type: standard_character_entry
        doc: Enter
      - id: re
        type: standard_character_entry
        doc: Return
      - id: ro
        type: standard_character_entry
        doc: Captain D. Rom
      - id: d1
        type: standard_character_entry
        doc: Bill Ding (Race Car)
      - id: d2
        type: standard_character_entry
        doc: Bill Ding (Helicopter)
      - id: d3
        type: standard_character_entry
        doc: Bill Ding (Dune Buggy)
      - id: d4
        type: standard_character_entry
        doc: Bill Ding (Jetski)
      - id: l1
        type: standard_character_entry
        doc: The Flying Legandos #1
      - id: l2
        type: standard_character_entry
        doc: The Flying Legandos #2
      - id: l3
        type: standard_character_entry
        doc: The Flying Legandos #3
      - id: l4
        type: standard_character_entry
        doc: The Flying Legandos #4
      - id: l5
        type: standard_character_entry
        doc: The Flying Legandos #5
      - id: l6
        type: standard_character_entry
        doc: The Flying Legandos #6
      - id: b1
        type: standard_character_entry
        doc: The Legobobs #1
      - id: b2
        type: standard_character_entry
        doc: The Legobobs #2
      - id: b3
        type: standard_character_entry
        doc: The Legobobs #3
      - id: b4
        type: standard_character_entry
        doc: The Legobobs #4
      - id: cm
        type: standard_character_entry
        doc: Brazilian Carmen
      - id: gd
        type: standard_character_entry
        doc: Gideon Worse
      - id: rd
        type: standard_character_entry
        doc: Red Greenbase
      - id: pg
        type: standard_character_entry
        doc: Polly Gone
      - id: bd
        type: standard_character_entry
        doc: Bradford Brickford
      - id: sy
        type: standard_character_entry
        doc: Shiney Doris
      - id: gn
        type: standard_character_entry
        doc: Glen Funberg
      - id: df
        type: standard_character_entry
        doc: Dorothy Funberg
      - id: bs
        type: standard_character_entry
        doc: Brian Shrimp
      - id: lt
        type: standard_character_entry
        doc: Luke Tepid
      - id: st
        type: standard_character_entry
        doc: Shorty Tails
      - id: bm
        type: standard_character_entry
        doc: Bumpy Kindergreen
      - id: jk
        type: standard_character_entry
        doc: Jack O'Trades
      - id: ghost
        type: ghost_character_entry
        doc: Ghost #1
      - id: ghost01
        type: ghost_character_entry
        doc: Ghost #2
      - id: ghost02
        type: ghost_character_entry
        doc: Ghost #3
      - id: ghost03
        type: ghost_character_entry
        doc: Ghost #4
      - id: ghost04
        type: ghost_character_entry
        doc: Ghost #5
      - id: ghost05
        type: ghost_character_entry
        doc: Ghost #6
      - id: hg
        type: standard_character_entry
      - id: pntgy
        type: standard_character_entry
      - id: pep
        type: pepper_character_entry
      - id: cop01
        type: standard_character_entry
      - id: actor_01
        type: standard_character_entry
      - id: actor_02
        type: standard_character_entry
      - id: actor_03
        type: standard_character_entry
      - id: actor_04
        type: standard_character_entry
      - id: actor_05
        type: standard_character_entry
      - id: btmncycl
        type: standard_character_entry
      - id: cboycycl
        type: standard_character_entry
      - id: boatman
        type: standard_character_entry

  standard_character_entry:
    doc: |
      Character customization and state for actors using the standard hat parts
      (g_hatPartIndices). Hat index 0-19 maps directly to hat_part enum.
      Total size is 16 bytes.
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
        enum: standard_hat
        doc: Index into standard hat parts (0-19 = standard hats).
      - id: hat_name_index
        type: u1
        enum: lego_color
        doc: Hat color.
      - id: infogron_name_index
        type: u1
        enum: lego_color
        doc: Torso (infogron) color.
      - id: armlft_name_index
        type: u1
        enum: lego_color
        doc: Left arm color.
      - id: armrt_name_index
        type: u1
        enum: lego_color
        doc: Right arm color.
      - id: leglft_name_index
        type: u1
        enum: lego_color
        doc: Left leg color.
      - id: legrt_name_index
        type: u1
        enum: lego_color
        doc: Right leg color.

  pepper_character_entry:
    doc: |
      Character customization and state for Pepper (uses g_pepperHatPartIndices).
      Hat index 0=phat, 1-20 map to standard hats 0-19.
      Total size is 16 bytes.
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
        enum: pepper_hat
        doc: Index into Pepper's hat parts (0=phat, 1-20=standard hats 0-19).
      - id: hat_name_index
        type: u1
        enum: lego_color
        doc: Hat color.
      - id: infogron_name_index
        type: u1
        enum: lego_color
        doc: Torso (infogron) color.
      - id: armlft_name_index
        type: u1
        enum: lego_color
        doc: Left arm color.
      - id: armrt_name_index
        type: u1
        enum: lego_color
        doc: Right arm color.
      - id: leglft_name_index
        type: u1
        enum: lego_color
        doc: Left leg color.
      - id: legrt_name_index
        type: u1
        enum: lego_color
        doc: Right leg color.

  infoman_character_entry:
    doc: |
      Character customization and state for Infoman (uses g_infomanHatPartIndices).
      Hat index 0=icap (only option).
      Total size is 16 bytes.
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
        enum: infoman_hat_index
        doc: Index into Infoman's hat parts (0=icap only).
      - id: hat_name_index
        type: u1
        enum: lego_color
        doc: Hat color.
      - id: infogron_name_index
        type: u1
        enum: lego_color
        doc: Torso (infogron) color.
      - id: armlft_name_index
        type: u1
        enum: lego_color
        doc: Left arm color.
      - id: armrt_name_index
        type: u1
        enum: lego_color
        doc: Right arm color.
      - id: leglft_name_index
        type: u1
        enum: lego_color
        doc: Left leg color.
      - id: legrt_name_index
        type: u1
        enum: lego_color
        doc: Right leg color.

  ghost_character_entry:
    doc: |
      Character customization and state for ghosts (uses g_ghostHatPartIndices).
      Hat index 0=sheet (only option).
      Total size is 16 bytes.
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
        enum: ghost_hat_index
        doc: Index into ghost hat parts (0=sheet only).
      - id: hat_name_index
        type: u1
        enum: lego_color
        doc: Hat color.
      - id: infogron_name_index
        type: u1
        enum: lego_color
        doc: Torso (infogron) color.
      - id: armlft_name_index
        type: u1
        enum: lego_color
        doc: Left arm color.
      - id: armrt_name_index
        type: u1
        enum: lego_color
        doc: Right arm color.
      - id: leglft_name_index
        type: u1
        enum: lego_color
        doc: Left leg color.
      - id: legrt_name_index
        type: u1
        enum: lego_color
        doc: Right leg color.

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
          This is used in Act 2/3.

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
          This is used in Act 2/3.

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
      - id: pepper_playlist_index
        type: s2
        doc: Pepper's next playlist index.
      - id: mama_playlist_index
        type: s2
        doc: Mama's next playlist index.
      - id: papa_playlist_index
        type: s2
        doc: Papa's next playlist index.
      - id: nick_playlist_index
        type: s2
        doc: Nick's next playlist index.
      - id: laura_playlist_index
        type: s2
        doc: Laura's next playlist index.

  pizza_mission_state_data:
    doc: |
      Pizza delivery mission state for all 5 actors.
      Total size is 40 bytes (5 missions x 4 x S16).
    seq:
      - id: pepper
        type: pizza_mission_entry
        doc: Pepper's pizza delivery mission data.
      - id: mama
        type: pizza_mission_entry
        doc: Mama's pizza delivery mission data.
      - id: papa
        type: pizza_mission_entry
        doc: Papa's pizza delivery mission data.
      - id: nick
        type: pizza_mission_entry
        doc: Nick's pizza delivery mission data.
      - id: laura
        type: pizza_mission_entry
        doc: Laura's pizza delivery mission data.

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
        enum: score_color
        doc: Current/last mission score.
      - id: hi_score
        type: s2
        enum: score_color
        doc: High score for this mission.

  score_mission_state_data:
    doc: |
      Mission state with scores and high scores for all 5 actors.
      Used by TowTrackMissionState and AmbulanceMissionState.
      Total size is 20 bytes (10 x S16).
    seq:
      - id: pepper_score
        type: s2
        enum: score_color
        doc: Pepper's current/last score.
      - id: mama_score
        type: s2
        enum: score_color
        doc: Mama's current/last score.
      - id: papa_score
        type: s2
        enum: score_color
        doc: Papa's current/last score.
      - id: nick_score
        type: s2
        enum: score_color
        doc: Nick's current/last score.
      - id: laura_score
        type: s2
        enum: score_color
        doc: Laura's current/last score.
      - id: pepper_high_score
        type: s2
        enum: score_color
        doc: Pepper's high score.
      - id: mama_high_score
        type: s2
        enum: score_color
        doc: Mama's high score.
      - id: papa_high_score
        type: s2
        enum: score_color
        doc: Papa's high score.
      - id: nick_high_score
        type: s2
        enum: score_color
        doc: Nick's high score.
      - id: laura_high_score
        type: s2
        enum: score_color
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
      - id: pepper
        type: race_entry
        doc: Pepper's race scores.
      - id: mama
        type: race_entry
        doc: Mama's race scores.
      - id: papa
        type: race_entry
        doc: Papa's race scores.
      - id: nick
        type: race_entry
        doc: Nick's race scores.
      - id: laura
        type: race_entry
        doc: Laura's race scores.

  race_entry:
    doc: Single actor's race score entry (5 bytes).
    seq:
      - id: id
        type: u1
        enum: actor
        doc: Actor ID.
      - id: last_score
        type: s2
        enum: score_color
        doc: Score from last race.
      - id: high_score
        type: s2
        enum: score_color
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
      - id: cpt_click_dialogue_next_index
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

  lego_color:
    0: white
    1: black
    2: yellow
    3: red
    4: blue
    5: brown
    6: lt_grey
    7: green

  hat_part:
    0: baseball
    1: chef
    2: cap
    3: cophat
    4: helmet
    5: ponytail
    6: pageboy
    7: shrthair
    8: bald
    9: flower
    10: cboyhat
    11: cuphat
    12: cathat
    13: backbcap
    14: pizhat
    15: caprc
    16: capch
    17: capdb
    18: capjs
    19: capmd
    20: sheet
    21: phat
    22: icap

  standard_hat:
    0: baseball
    1: chef
    2: cap
    3: cophat
    4: helmet
    5: ponytail
    6: pageboy
    7: shrthair
    8: bald
    9: flower
    10: cboyhat
    11: cuphat
    12: cathat
    13: backbcap
    14: pizhat
    15: caprc
    16: capch
    17: capdb
    18: capjs
    19: capmd

  pepper_hat:
    0: phat
    1: baseball
    2: chef
    3: cap
    4: cophat
    5: helmet
    6: ponytail
    7: pageboy
    8: shrthair
    9: bald
    10: flower
    11: cboyhat
    12: cuphat
    13: cathat
    14: backbcap
    15: pizhat
    16: caprc
    17: capch
    18: capdb
    19: capjs
    20: capmd

  infoman_hat_index:
    0: icap

  ghost_hat_index:
    0: sheet

  score_color:
    0: grey
    1: yellow
    2: blue
    3: red
