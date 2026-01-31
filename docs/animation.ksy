meta:
  id: animation
  title: Animation File
  application: LEGO Island
  file-extension: ani
  license: CC0-1.0
  endian: le
doc: |
  Animation file format for LEGO Island (1997). Contains skeletal animation
  data including actor references, keyframes for translation/rotation/scale,
  morph visibility keys, and optional camera animation data.

  Animation files are embedded within SI (Interleaf) files and
  parsed by LegoAnimPresenter. The format consists of a header with bounding
  information, an actor list, animation duration, optional camera animation,
  and a hierarchical tree of animation nodes.

seq:
  - id: magic
    type: s4
    doc: |
      Magic number identifying the file format. Must be 0x11 (17 decimal).
  - id: bounding_radius
    type: f4
    doc: |
      Radius of the bounding sphere encompassing the entire animation.
      Used for visibility culling and collision detection.
  - id: center_x
    type: f4
    doc: X coordinate of the bounding sphere center point.
  - id: center_y
    type: f4
    doc: Y coordinate of the bounding sphere center point.
  - id: center_z
    type: f4
    doc: Z coordinate of the bounding sphere center point.
  - id: has_camera_anim
    type: s4
    doc: |
      Flag indicating whether camera animation data follows the actor list.
      If non-zero, a camera_anim structure is present after the duration field.
  - id: unused
    type: s4
    doc: |
      Unused field. Read by the parser but not used for anything.
  - id: num_actors
    type: u4
    doc: Number of actor entries in the actor list.
  - id: actors
    type: actor_entry
    repeat: expr
    repeat-expr: num_actors
    doc: |
      List of actors referenced by this animation. Each entry contains
      the actor name and type, which determines how the actor ROI is
      managed during animation playback.
  - id: duration
    type: s4
    doc: Total duration of the animation in milliseconds.
  - id: camera_anim
    type: camera_anim
    if: has_camera_anim != 0
    doc: |
      Camera animation data including position, target, and rotation keys.
      Only present if has_camera_anim is non-zero.
  - id: root_node
    type: tree_node
    doc: |
      Root node of the animation tree. The tree structure mirrors the
      skeletal hierarchy of the animated model, with each node containing
      keyframe data for its corresponding bone/part.

types:
  actor_entry:
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

  camera_anim:
    doc: |
      Camera animation data (LegoAnimScene). Contains keyframes for camera
      position, look-at target position, and roll rotation around the
      view axis.
    seq:
      - id: num_translation_keys
        type: u2
        doc: Number of camera position keyframes.
      - id: translation_keys
        type: translation_key
        repeat: expr
        repeat-expr: num_translation_keys
        doc: Camera position keyframes.
      - id: num_target_keys
        type: u2
        doc: Number of look-at target position keyframes.
      - id: target_keys
        type: translation_key
        repeat: expr
        repeat-expr: num_target_keys
        doc: Look-at target position keyframes.
      - id: num_rotation_keys
        type: u2
        doc: Number of camera roll rotation keyframes.
      - id: rotation_keys
        type: rotation_z_key
        repeat: expr
        repeat-expr: num_rotation_keys
        doc: Camera roll rotation keyframes (rotation around view axis).

  tree_node:
    doc: |
      A node in the animation tree hierarchy. Each node contains animation
      data for one part of the model and references to child nodes.
    seq:
      - id: data
        type: node_data
        doc: Animation keyframe data for this node.
      - id: num_children
        type: u4
        doc: Number of child nodes.
      - id: children
        type: tree_node
        repeat: expr
        repeat-expr: num_children
        doc: Child nodes in the animation hierarchy.

  node_data:
    doc: |
      Animation data for a single node (LegoAnimNodeData). Contains the
      node name and arrays of keyframes for translation, rotation, scale,
      and morph (visibility) animations.
    seq:
      - id: name_length
        type: u4
        doc: Length of the node name in bytes.
      - id: name
        type: str
        size: name_length
        encoding: ASCII
        if: name_length > 0
        doc: |
          Node name used to match this animation data to a ROI in the scene.
          Names starting with '*' indicate special handling (actor name
          substitution). Names starting with '-' are ignored.
      - id: num_translation_keys
        type: u2
        doc: Number of translation keyframes.
      - id: translation_keys
        type: translation_key
        repeat: expr
        repeat-expr: num_translation_keys
        doc: Translation (position) keyframes.
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
        doc: Morph keyframes controlling visibility.

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

  rotation_z_key:
    doc: |
      Z-axis rotation keyframe (LegoRotationZKey). Used for camera roll
      animation where only rotation around the view axis is needed.
    seq:
      - id: key
        type: anim_key
        doc: Base key with time and flags.
      - id: z
        type: f4
        doc: Rotation angle around the Z axis in radians.

enums:
  actor_type:
    2: managed_lego_actor
    3: managed_invisible_roi_trimmed
    4: managed_invisible_roi
    5: scene_roi_1
    6: scene_roi_2
