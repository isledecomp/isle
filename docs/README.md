# LEGO Island File Format Documentation

This folder contains documentation for LEGO Island's custom binary file formats using [Kaitai Struct](https://kaitai.io/), a declarative language for describing binary data structures.

## What is Kaitai Struct?

Kaitai Struct allows you to define binary formats in a YAML-based `.ksy` file, which can then be:
- Compiled into parser libraries for [many programming languages](https://doc.kaitai.io/lang_cpp_stl.html) (C++, Python, JavaScript, etc.)
- Visualized interactively using the [Kaitai Struct Visualizer](https://github.com/kaitai-io/kaitai_struct_visualizer)
- Dumped to human-readable formats using `ksdump`

## Documented Formats

| File | Extension | Description |
|------|-----------|-------------|
| [`players.ksy`](/docs/players.ksy) | `.gsi` | Player profile save data (usernames) |
| [`history.ksy`](/docs/history.ksy) | `.gsi` | Score history and high scores |

## Using the Tools

### Kaitai Struct Visualizer (ksv)

The [Kaitai Struct Visualizer](https://github.com/kaitai-io/kaitai_struct_visualizer) (`ksv`) provides an interactive terminal UI for exploring binary files.

```bash
# View a Players.gsi file
ksv samples/Players.gsi players.ksy

# View a History.gsi file
ksv samples/History.gsi history.ksy
```

### Kaitai Struct Dump (ksdump)

`ksdump` outputs the parsed structure as JSON or YAML for scripting and inspection.

```bash
# Dump Players.gsi to JSON
ksdump samples/Players.gsi players.ksy

# Dump History.gsi to YAML
ksdump --format yaml samples/History.gsi history.ksy
```

### Installation

See the [Kaitai Struct Visualizer installation instructions](https://github.com/kaitai-io/kaitai_struct_visualizer#installing) for setup details.

## Sample Files

The [`samples/`](/docs/samples/) directory contains example save files for testing:
- `Players.gsi` - Sample player profile data
- `History.gsi` - Sample score history data
