meta:
  id: wdb
  title: World Database File
  application: LEGO Island
  file-extension: wdb
  license: CC0-1.0
  endian: le

doc: |
  World Database file format for LEGO Island (1997). Contains world geometry
  data including textures, parts (ROI definitions), and models with their
  transforms and LOD (Level of Detail) information.

  The file is located at `<install_path>/lego/data/world.wdb` on either
  the hard drive or CD-ROM.

  File structure:
  1. World headers - list of worlds with part/model references
  2. Global textures - shared texture data (read once)
  3. Global parts - shared part definitions (read once)
  4. Part data blobs - at offsets specified in headers
  5. Model data blobs - at offsets specified in headers

seq:
  - id: num_worlds
    type: s4
    doc: Number of world entries in this file.
  - id: worlds
    type: world_entry
    repeat: expr
    repeat-expr: num_worlds
    doc: |
      World entries containing references to parts and models.
      Each world represents a distinct game area (e.g., "Act1", "Act2", "Act3").
  - id: global_textures_size
    type: u4
    doc: Size in bytes of the global textures block.
  - id: global_textures
    type: texture_list
    size: global_textures_size
    doc: |
      Global textures shared across all worlds. These are loaded once
      when the first world is loaded and cached for subsequent worlds.
  - id: global_parts_size
    type: u4
    doc: Size in bytes of the global parts block.
  - id: global_parts
    type: part_list
    size: global_parts_size
    doc: |
      Global parts (ROI definitions) shared across all worlds.
      Like textures, these are loaded once and cached.

types:
  world_entry:
    doc: |
      A world entry containing references to parts and models.
      Parts define reusable geometry, while models are placed instances
      with specific transforms.
    seq:
      - id: name_length
        type: s4
        doc: Length of the world name in bytes.
      - id: name
        type: str
        size: name_length
        encoding: ASCII
        doc: |
          World name used to identify this world (e.g., "Act1", "Act2", "Act3").
      - id: num_parts
        type: s4
        doc: Number of part references in this world.
      - id: parts
        type: part_reference
        repeat: expr
        repeat-expr: num_parts
        doc: References to part data stored elsewhere in the file.
      - id: num_models
        type: s4
        doc: Number of model entries in this world.
      - id: models
        type: model_entry
        repeat: expr
        repeat-expr: num_models
        doc: |
          Model entries with transform data. Each model references
          geometry and specifies its position, orientation, and visibility.

  part_reference:
    doc: |
      Reference to part data stored at an offset in the file.
      The actual part data contains ROI definitions with textures and LODs.
    seq:
      - id: name_length
        type: u4
        doc: Length of the ROI name in bytes.
      - id: name
        type: str
        size: name_length
        encoding: ASCII
        doc: ROI (Realtime Object Instance) name identifying this part.
      - id: data_length
        type: u4
        doc: Length of the part data in bytes.
      - id: data_offset
        type: u4
        doc: Absolute file offset to the part data.
    instances:
      data:
        io: _root._io
        pos: data_offset
        size: data_length
        type: part_data
        doc: The actual part data at the specified offset.

  model_entry:
    doc: |
      A model entry defining a placed instance in the world.
      Contains transform data (location, direction, up vector) and
      a reference to the model geometry.
    seq:
      - id: name_length
        type: u4
        doc: Length of the model name in bytes.
      - id: name
        type: str
        size: name_length
        encoding: ASCII
        doc: |
          Model name. Names starting with "isle" have quality variants
          (isle_lo, isle, isle_hi). Names starting with "haus" have
          special loading rules.
      - id: data_length
        type: u4
        doc: Length of the model data in bytes.
      - id: data_offset
        type: u4
        doc: Absolute file offset to the model data.
      - id: presenter_name_length
        type: u4
        doc: Length of the presenter class name in bytes.
      - id: presenter_name
        type: str
        size: presenter_name_length
        encoding: ASCII
        doc: |
          Presenter class name determining how the model is created.
          Common values: "LegoActorPresenter", "LegoEntityPresenter".
      - id: location
        type: vertex3
        doc: World position of the model (X, Y, Z).
      - id: direction
        type: vertex3
        doc: Forward direction vector of the model.
      - id: up
        type: vertex3
        doc: Up direction vector of the model.
      - id: visible
        type: u1
        doc: Visibility flag. Non-zero means the model is initially visible.
    instances:
      data:
        io: _root._io
        pos: data_offset
        size: data_length
        type: model_data
        doc: The model data (textures, animation, ROI) at the specified offset.

  texture_list:
    doc: |
      A list of named textures. Each texture includes palette and pixel data.
    seq:
      - id: num_textures
        type: u4
        doc: Number of textures in this list.
      - id: textures
        type: named_texture
        repeat: expr
        repeat-expr: num_textures
        doc: Array of named textures.

  named_texture:
    doc: |
      A named texture with 8-bit indexed color image data.
    seq:
      - id: name_length
        type: u4
        doc: Length of the texture name in bytes.
      - id: name
        type: str
        size: name_length
        encoding: ASCII
        doc: Texture name used for lookup.
      - id: image
        type: image
        doc: The texture image data.

  image:
    doc: |
      An 8-bit indexed color image with palette.
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
    doc: RGB color palette entry.
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

  part_list:
    doc: |
      A list of named parts (ROI definitions). Parts can be shared
      across multiple models and worlds.
    seq:
      - id: texture_info_offset
        type: u4
        doc: Offset within this block to texture information.
      - id: num_rois
        type: u4
        doc: Number of ROI definitions.
      - id: rois
        type: named_part
        repeat: expr
        repeat-expr: num_rois
        doc: Array of named part definitions.

  named_part:
    doc: |
      A named part containing LOD (Level of Detail) definitions.
    seq:
      - id: name_length
        type: u4
        doc: Length of the ROI name in bytes.
      - id: name
        type: str
        size: name_length
        encoding: ASCII
        doc: ROI name for lookup.
      - id: num_lods
        type: u4
        doc: Number of LOD levels for this part.
      - id: next_roi_offset
        type: u4
        doc: Offset to the next ROI definition (for skipping LOD data).
      - id: lods
        type: lod
        repeat: expr
        repeat-expr: num_lods
        doc: LOD definitions from highest to lowest detail.

  part_data:
    doc: |
      Part data blob containing textures and ROI definitions.
      This is the format used for part data at offsets in the file.
    seq:
      - id: texture_info_offset
        type: u4
        doc: Offset within this block to texture information.
      - id: num_rois
        type: u4
        doc: Number of ROI definitions in this part.
      - id: rois
        type: named_part
        repeat: expr
        repeat-expr: num_rois
        doc: ROI definitions for this part.

  model_data:
    doc: |
      Model data blob containing version info, textures, animation data,
      and ROI hierarchy. This is the format used for model data at offsets.
      Parsed by LegoModelPresenter::CreateROI.
    seq:
      - id: version
        type: u4
        doc: Format version. Must be 19 (MODEL_VERSION).
      - id: texture_info_offset
        type: u4
        doc: Offset within this blob to texture information.
      - id: num_rois
        type: u4
        doc: Number of ROIs (typically 1 for models).
      - id: anim
        type: model_anim
        doc: Animation data for this model.
      - id: roi
        type: roi
        doc: The root ROI containing the model geometry.

  model_anim:
    doc: |
      Animation data embedded in model data. This is a simplified form
      of LegoAnim without camera/scene animation (p_parseScene=FALSE).
    seq:
      - id: num_actors
        type: u4
        doc: Number of actor entries.
      - id: actors
        type: anim_actor_entry
        repeat: expr
        repeat-expr: num_actors
        doc: Actor entries for this animation.
      - id: duration
        type: s4
        doc: Animation duration in milliseconds.
      - id: root_node
        type: anim_tree_node
        doc: Root node of the animation tree.

  anim_actor_entry:
    doc: |
      An actor reference in the animation. The name identifies which ROI
      (Realtime Object Instance) to animate, and the type determines
      how the actor is managed by the character manager.
    seq:
      - id: name_length
        type: u4
        doc: Length of the actor name in bytes.
      - id: name
        type: str
        size: name_length
        encoding: ASCII
        if: name_length > 0
        doc: Actor name used to look up the ROI in the scene.
      - id: actor_type
        type: u4
        enum: actor_type
        if: name_length > 0
        doc: |
          Determines how the actor ROI is created and managed.
          See actor_type enum for possible values.

  anim_tree_node:
    doc: Node in the animation tree hierarchy.
    seq:
      - id: data
        type: anim_node_data
        doc: Animation keyframe data for this node.
      - id: num_children
        type: u4
        doc: Number of child nodes.
      - id: children
        type: anim_tree_node
        repeat: expr
        repeat-expr: num_children
        doc: Child nodes.

  anim_node_data:
    doc: Animation keyframe data for a single node.
    seq:
      - id: name_length
        type: u4
        doc: Length of node name.
      - id: name
        type: str
        size: name_length
        encoding: ASCII
        if: name_length > 0
        doc: Node name for matching to ROI.
      - id: num_translation_keys
        type: u2
        doc: Number of translation keyframes.
      - id: translation_keys
        type: translation_key
        repeat: expr
        repeat-expr: num_translation_keys
        doc: Translation keyframes.
      - id: num_rotation_keys
        type: u2
        doc: Number of rotation keyframes.
      - id: rotation_keys
        type: rotation_key
        repeat: expr
        repeat-expr: num_rotation_keys
        doc: Rotation keyframes (quaternion format).
      - id: num_scale_keys
        type: u2
        doc: Number of scale keyframes.
      - id: scale_keys
        type: scale_key
        repeat: expr
        repeat-expr: num_scale_keys
        doc: Scale keyframes.
      - id: num_morph_keys
        type: u2
        doc: Number of morph (visibility) keyframes.
      - id: morph_keys
        type: morph_key
        repeat: expr
        repeat-expr: num_morph_keys
        doc: Morph keyframes.

  anim_key:
    doc: |
      Base animation key containing time and flags. The time and flags
      are packed into a single 32-bit value: bits 0-23 contain the time
      in milliseconds, and bits 24-31 contain flags.
    seq:
      - id: time_and_flags
        type: s4
        doc: |
          Packed time and flags value.
          - Bits 0-23: Time in milliseconds (mask with 0xFFFFFF)
          - Bits 24-31: Flags (shift right by 24)
    instances:
      time:
        value: time_and_flags & 0xFFFFFF
        doc: Keyframe time in milliseconds.
      flags:
        value: (time_and_flags >> 24) & 0xFF
        doc: |
          Keyframe flags:
          - 0x01 (active): Key has meaningful data
          - 0x02 (negate_rotation): Negate quaternion for interpolation
          - 0x04 (skip_interpolation): Use this key's value without blending

  translation_key:
    doc: |
      Translation keyframe containing position offset (LegoTranslationKey).
      The translation is applied relative to the parent node's transform.
    seq:
      - id: key
        type: anim_key
        doc: Base key with time and flags.
      - id: x
        type: f4
        doc: X component of translation.
      - id: y
        type: f4
        doc: Y component of translation.
      - id: z
        type: f4
        doc: Z component of translation.

  rotation_key:
    doc: |
      Rotation keyframe containing a quaternion (LegoRotationKey).
      The quaternion is stored as (angle, x, y, z) where angle is the
      scalar/w component and (x, y, z) is the vector part.
    seq:
      - id: key
        type: anim_key
        doc: Base key with time and flags.
      - id: angle
        type: f4
        doc: |
          Quaternion scalar component (w). A value of 1.0 with x=y=z=0
          represents no rotation (identity quaternion).
      - id: x
        type: f4
        doc: Quaternion x component.
      - id: y
        type: f4
        doc: Quaternion y component.
      - id: z
        type: f4
        doc: Quaternion z component.

  scale_key:
    doc: |
      Scale keyframe containing scale factors (LegoScaleKey).
      Scale is applied relative to the local origin of the node.
    seq:
      - id: key
        type: anim_key
        doc: Base key with time and flags.
      - id: x
        type: f4
        doc: X scale factor (1.0 = no scaling).
      - id: y
        type: f4
        doc: Y scale factor (1.0 = no scaling).
      - id: z
        type: f4
        doc: Z scale factor (1.0 = no scaling).

  morph_key:
    doc: |
      Morph/visibility keyframe (LegoMorphKey). Controls whether the
      node's ROI is visible at a given time.
    seq:
      - id: key
        type: anim_key
        doc: Base key with time and flags.
      - id: visible
        type: u1
        doc: Visibility flag. Non-zero means visible.

  roi:
    doc: |
      ROI (Realtime Object Instance) defining a piece of geometry.
      ROIs form a hierarchy with parent-child relationships.
    seq:
      - id: name_length
        type: u4
        doc: Length of the ROI name in bytes.
      - id: name
        type: str
        size: name_length
        encoding: ASCII
        doc: ROI name used for lookup and animation binding.
      - id: bounding_sphere
        type: sphere
        doc: Bounding sphere for visibility culling.
      - id: bounding_box
        type: box
        doc: Axis-aligned bounding box.
      - id: texture_name_length
        type: u4
        doc: Length of texture/material name (0 if none).
      - id: texture_name
        type: str
        size: texture_name_length
        encoding: ASCII
        if: texture_name_length > 0
        doc: |
          Texture or material name. Names starting with "t_" reference
          textures; other names are color aliases (e.g., "lego red").
      - id: shared_lod_list
        type: u1
        doc: |
          If non-zero, LODs are shared with another ROI and not stored here.
          The ROI name (minus trailing digits) is used to look up shared LODs.
      - id: num_lods
        type: u4
        if: shared_lod_list == 0
        doc: Number of LOD levels (only if not using shared LODs).
      - id: next_roi_offset
        type: u4
        if: shared_lod_list == 0 and num_lods > 0
        doc: Offset to continue reading after LOD data.
      - id: lods
        type: lod
        repeat: expr
        repeat-expr: num_lods
        if: shared_lod_list == 0 and num_lods > 0
        doc: LOD definitions from highest to lowest detail.
      - id: num_children
        type: u4
        doc: Number of child ROIs in this hierarchy.
      - id: children
        type: roi
        repeat: expr
        repeat-expr: num_children
        doc: Child ROIs forming a hierarchy.

  sphere:
    doc: Bounding sphere defined by center point and radius.
    seq:
      - id: center
        type: vertex3
        doc: Center point of the sphere.
      - id: radius
        type: f4
        doc: Radius of the sphere.

  box:
    doc: Axis-aligned bounding box defined by min and max corners.
    seq:
      - id: min
        type: vertex3
        doc: Minimum corner (smallest X, Y, Z values).
      - id: max
        type: vertex3
        doc: Maximum corner (largest X, Y, Z values).

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

  lod:
    doc: |
      Level of Detail definition containing mesh data.
      LODs are ordered from highest to lowest detail.
    seq:
      - id: flags
        type: u4
        doc: |
          LOD flags. Bit 0 (0x01) indicates this is an "extra" LOD.
          Other bits control visibility and rendering behavior.
      - id: num_meshes
        type: u4
        doc: Number of meshes in this LOD.
      - id: vertex_normal_counts
        type: u4
        if: num_meshes > 0
        doc: |
          Packed vertex and normal counts.
          Lower 16 bits: vertex count
          Upper 15 bits (shifted right by 1): normal count
      - id: num_texture_vertices
        type: s4
        if: num_meshes > 0
        doc: Number of texture coordinate pairs.
      - id: vertices
        type: vertex3
        repeat: expr
        repeat-expr: vertex_count
        if: num_meshes > 0 and vertex_count > 0
        doc: Vertex positions shared across meshes.
      - id: normals
        type: vertex3
        repeat: expr
        repeat-expr: normal_count
        if: num_meshes > 0 and normal_count > 0
        doc: Normal vectors shared across meshes.
      - id: texture_vertices
        type: texture_vertex
        repeat: expr
        repeat-expr: num_texture_vertices
        if: num_meshes > 0 and num_texture_vertices > 0
        doc: Texture coordinates (UV pairs).
      - id: meshes
        type: mesh
        repeat: expr
        repeat-expr: num_meshes
        if: num_meshes > 0
        doc: Mesh definitions using the shared vertex/normal/UV data.
    instances:
      vertex_count:
        value: '(num_meshes > 0) ? (vertex_normal_counts & 0xFFFF) : 0'
        doc: Number of vertices (lower 16 bits of packed value).
      normal_count:
        value: '(num_meshes > 0) ? ((vertex_normal_counts >> 17) & 0x7FFF) : 0'
        doc: Number of normals (upper 15 bits, shifted right by 1).

  texture_vertex:
    doc: Texture coordinate pair (UV).
    seq:
      - id: u
        type: f4
        doc: U coordinate (horizontal, 0.0-1.0).
      - id: v
        type: f4
        doc: V coordinate (vertical, 0.0-1.0).

  mesh:
    doc: |
      A mesh within an LOD, containing polygons and material properties.
    seq:
      - id: num_polygons
        type: u2
        doc: Number of triangular polygons.
      - id: num_vertices
        type: u2
        doc: Number of vertices used by this mesh.
      - id: polygon_indices
        type: polygon_indices
        repeat: expr
        repeat-expr: num_polygons
        doc: Vertex indices for each triangle.
      - id: num_texture_indices
        type: u4
        doc: |
          Total number of texture indices. Should equal num_polygons * 3
          if textured, or 0 if untextured.
      - id: texture_indices
        type: texture_indices
        repeat: expr
        repeat-expr: num_polygons
        if: num_texture_indices > 0
        doc: |
          Texture coordinate indices for each triangle. Unlike polygon_indices,
          these are simple U32 indices into the LOD's texture_vertices array,
          not packed values. Each index directly references a UV coordinate pair.
      - id: properties
        type: mesh_properties
        doc: Material and rendering properties.

  polygon_indices:
    doc: |
      Three packed indices forming a triangle. Each 32-bit value contains
      vertex index, normal index, and a "create vertex" flag used by
      Direct3D Retained Mode mesh building.

      Bit layout of each packed value:
      - Bits 0-15 (16 bits): When create flag is set, this is the index into
        the LOD's vertices array. When create flag is clear, this is the index
        into the mesh's built vertex buffer (referencing a previously created vertex).
      - Bits 16-30 (15 bits): Index into the LOD's normals array
      - Bit 31: Create vertex flag. When set (1), a new mesh vertex is created
        combining position, normal, and texture UV. When clear (0), the value
        in bits 0-15 references an existing mesh vertex by index.

      The mesh builder creates a vertex buffer where each unique position+normal+UV
      combination gets an entry. Texture indices (in texture_indices) are only
      consumed when the create flag is set.
    seq:
      - id: a
        type: u4
        doc: First packed vertex/normal index with create flag.
      - id: b
        type: u4
        doc: Second packed vertex/normal index with create flag.
      - id: c
        type: u4
        doc: Third packed vertex/normal index with create flag.

  texture_indices:
    doc: |
      Three texture coordinate indices forming a triangle. Unlike polygon_indices,
      these are simple U32 values that directly index into the LOD's texture_vertices
      array. Each value is only used when the corresponding polygon_indices entry
      has its create flag (bit 31) set.
    seq:
      - id: a
        type: u4
        doc: First texture vertex index.
      - id: b
        type: u4
        doc: Second texture vertex index.
      - id: c
        type: u4
        doc: Third texture vertex index.

  mesh_properties:
    doc: |
      Material and rendering properties for a mesh.
    seq:
      - id: color
        type: color_rgb
        doc: Base color of the mesh.
      - id: alpha
        type: f4
        doc: Transparency (0.0 = fully transparent, 1.0 = opaque).
      - id: shading
        type: u1
        enum: shading_mode
        doc: Shading mode for rendering this mesh.
      - id: unknown_0x0d
        type: u1
        doc: Unknown flag. When > 0, special material is applied.
      - id: unknown_0x20
        type: u1
        doc: Unknown field.
      - id: use_alias
        type: u1
        doc: |
          If non-zero, texture_name and material_name are looked up
          as aliases rather than literal names.
      - id: texture_name_length
        type: u4
        doc: Length of texture name (0 if no texture).
      - id: texture_name
        type: str
        size: texture_name_length
        encoding: ASCII
        if: texture_name_length > 0
        doc: Texture name for this mesh.
      - id: material_name_length
        type: u4
        doc: Length of material/color name (0 if none).
      - id: material_name
        type: str
        size: material_name_length
        encoding: ASCII
        if: material_name_length > 0
        doc: |
          Material or color alias name (e.g., "lego red", "lego blue").

  color_rgb:
    doc: RGB color with 8-bit components.
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

enums:
  shading_mode:
    0: flat
    1: gouraud
    2: wireframe

  actor_type:
    2: managed_lego_actor
    3: managed_invisible_roi_trimmed
    4: managed_invisible_roi
    5: scene_roi_1
    6: scene_roi_2
