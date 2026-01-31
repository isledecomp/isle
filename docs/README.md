# LEGO Island File Format Documentation

This folder contains documentation for LEGO Island's custom binary file formats using [Kaitai Struct](https://kaitai.io/), a declarative language for describing binary data structures.

## What is Kaitai Struct?

Kaitai Struct allows you to define binary formats in a YAML-based `.ksy` file, which can then be:
- Compiled into parser libraries for [many programming languages](https://kaitai.io/#quick-start) (C++, Python, JavaScript, etc.)
- Visualized interactively using the [Kaitai Struct Visualizer](https://github.com/kaitai-io/kaitai_struct_visualizer)
- Dumped to human-readable formats using `ksdump`

<img width="1877" height="706" alt="image" src="https://github.com/user-attachments/assets/0d124219-1208-48ce-83bb-f433d9bb84b1" />

## Documented Formats

| File | Extension | Description |
|------|-----------|-------------|
| [`savegame.ksy`](/docs/savegame.ksy) | `.GS` | Main game save data (game state, progress, customizations) |
| [`players.ksy`](/docs/players.ksy) | `.gsi` | Player profile save data (usernames) |
| [`history.ksy`](/docs/history.ksy) | `.gsi` | Score history and high scores |
| [`animation.ksy`](/docs/animation.ksy) | `.ani` | Animation data (keyframes, actor references, camera animation) |
| [`wdb.ksy`](/docs/wdb.ksy) | `.wdb` | World database (textures, parts, models, ROI hierarchies, LODs) |

## Using the Tools

### Installation

See the [Kaitai Struct Visualizer installation instructions](https://github.com/kaitai-io/kaitai_struct_visualizer?tab=readme-ov-file#downloading-and-installing) for setup details.

### Kaitai Struct Visualizer (ksv)

The [Kaitai Struct Visualizer](https://github.com/kaitai-io/kaitai_struct_visualizer) (`ksv`) provides an interactive terminal UI for exploring binary files.

```bash
# View a save game file
ksv samples/G0.GS savegame.ksy

# View a Players.gsi file
ksv samples/Players.gsi players.ksy

# View a History.gsi file
ksv samples/History.gsi history.ksy

# View an animation file
ksv samples/pns065rd.ani animation.ksy

# View the world database (from game installation)
ksv /path/to/lego/data/world.wdb wdb.ksy
```

### Kaitai Struct Dump (ksdump)

`ksdump` outputs the parsed structure as JSON or YAML for scripting and inspection.

```bash
# Dump a save game to JSON
ksdump --format json samples/G0.GS savegame.ksy

# Dump Players.gsi to JSON
ksdump --format json samples/Players.gsi players.ksy

# Dump History.gsi to YAML
ksdump --format yaml samples/History.gsi history.ksy

# Dump an animation file to JSON
ksdump --format json samples/pns065rd.ani animation.ksy

# Dump world database to YAML (from game installation)
ksdump --format yaml /path/to/lego/data/world.wdb wdb.ksy
```

## Sample Files

The [`samples/`](/docs/samples/) directory contains example files for testing:
- `G0.GS`, `G1.GS`, `G2.GS` - Sample main game save files (slots 0, 1, 2)
- `Players.gsi` - Sample player profile data
- `History.gsi` - Sample score history data
- `pns065rd.ani` - Sample animation file

Note: The world database (`world.wdb`) can be found in your LEGO Island installation at `lego/data/world.wdb`.
