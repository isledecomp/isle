meta:
  id: tex
  title: Texture Data File
  application: LEGO Island
  file-extension: tex
  license: CC0-1.0
  endian: le

doc: |
  Texture data format for LEGO Island (1997). Contains one or more named
  textures with 8-bit indexed color image data.

  Texture data is embedded in SI (Interleaf) container files and parsed by
  LegoTexturePresenter::Read(). Each texture consists of a length-prefixed
  name followed by image data with a color palette and pixel indices.

  The image format is shared with the world database (world.wdb) texture
  data, using the same LegoImage and LegoPaletteEntry serialization.

  File structure:
  1. Texture count
  2. Named texture entries - name + palette + pixel data

seq:
  - id: num_textures
    type: u4
    doc: Number of textures in this file.
  - id: textures
    type: named_texture
    repeat: expr
    repeat-expr: num_textures
    doc: Array of named textures.

types:
  named_texture:
    doc: |
      A named texture with 8-bit indexed color image data.
    seq:
      - id: name_length
        type: u4
        doc: Length of the texture name buffer in bytes.
      - id: name
        type: str
        size: name_length
        encoding: ASCII
        terminator: 0
        doc: |
          Texture name (e.g., "dbfrfn.gif"). The name is a null-terminated
          C string within the allocated buffer. Bytes after the null
          terminator are unused padding and consumed but not included
          in the string value.
      - id: image
        type: image
        doc: The texture image data.

  image:
    doc: |
      An 8-bit indexed color image with palette. Parsed by LegoImage::Read().
    seq:
      - id: width
        type: u4
        doc: Image width in pixels.
      - id: height
        type: u4
        doc: Image height in pixels.
      - id: palette_size
        type: u4
        doc: Number of entries in the color palette (max 256).
      - id: palette
        type: palette_entry
        repeat: expr
        repeat-expr: palette_size
        doc: Color palette entries.
      - id: pixels
        size: width * height
        doc: |
          Pixel data as palette indices. Each byte is an index into
          the palette array.

  palette_entry:
    doc: RGB color palette entry. Parsed by LegoPaletteEntry::Read().
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
