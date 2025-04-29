# Documentation

## Nomenclature
- **Script**: SI File (it appears they wanted to use SI much more as actual scripts, but ended up hard-coding almost everything)
- **Action**: Mostly media file inside SI

## Classes

### MxAtom
Key (string) / Value (U16) pair.

Inc()
Dec()

### MxAtomId
String with lookup method (upper case/lower case/exact). Used for IDs.

MxOmni holds an AtomSet that contains MxAtoms for every MxAtom ID created + a counter of how many instances exists.

### MxString
Typical string class with utility functions.

### MxCore
Virtual base class.

Tickle()
Notifiy(MyParam)
GetId()
ClassName()

IsA()
Checks ALL parents.

### MxDSObject : MxCore
Base Object for extracted objects from SI files.

Adds AtomId, ObjectId, Type, Flags, ObjectName and SourceName as well as a Deserialize method.

Deserializes SourceName and ObjectName. It also saves the flags provided as a param.

Also provides DeserializeDSObjectDispatch which deserializes an MxOb chunk into the corresponding MxDSObject child.

### MxDSAction : MxDSObject
Deserializes Flags (ignores param), StartTime, Duration, LoopCount, Location (Vec3), Direction (Vec3) and Up (Vec3).

Also if extra is available it appends it to ExtraData.

### MxDSMediaAction : MxDSAction
Deserializes MediaSrcPath, two U32 into an unknown struct, FramesPerSecond, MediaFormat, PaletteManagement, SustainTime.

### MxDSMultiAction : MxDSAction
Deserializes multiple chunks? into MxDSActions using DeserializeDSObjectDispatch

### MxDSParallelAction : MxDSMultiAction
Just a rename from MxDSMultiAction.

### MxDSSelectAction : MxDSParallelAction
Deserializes Unknown0x9c, checks if it starts with "RANDOM_" and if so, parses the number after "RANDOM_", gets a number from 0 to number. If not reads a string and saves it in the VariableTable.

Then reads a list of strings (presumably numbers) into a list. Then reads the same number of chunks into objects (Actions), chooses nth one where N is the index of the string that equals to the random number.

### MxDSSound : MxDSMediaAction
Deserializes a volume.

### MxVariableTable : MxHashTable<MxVariable*>
MxOmni holds a VariableTable that is just a key/value store string/string.

### LegoBuildingManager : MxCore

#### CreateBuilding()

### MxEntity : MxCore
Adds EntityId (S32) and AtomID (MxAtomId).

### LegoEntity : MxEntity
Adds WorldDirection, WorldUp, WorldPostion, WorldSpeed, ROI, CameraFlag, Flags,

Virtual methods:
ClickSound(bool)
ClickAnimation()
SwitchVariant()
SwitchSound()
SwitchMove()
SwitchColor(LegoROI*)
SwitchMood()

#### ParseAction(char*)
Parses a string like ""ACTION:<action>; <filename>; <entity-id>"

If action is not 7 (e_exit), it stores the filename into m_siFile, and if the action is not 6 (e_run) it stores the ID into m_targetEntityId.

### ROI
Has LODlist (a list of LODObject), Visibility and ROIList (a list of ROI-pointers, via CompoundObject).

Provides (deleted) functions for world velocity, bounding box and bounding sphere.

### OrientableROI : ROI
Adds Local2World 4x4-matrix, WorldBoundingBox (and WorldBoundingSphere), WorldVelocity, ParentROI (another OrientableROI).
Also has an unknown bounding box and u32. The u32 can be enabled/disabled which either sets bit 1 and 3 or clears only bit 1.

WorldUp, WorldDirection and WorldPosition are within `local2world`'s second, third and forth row.

### ViewROI : OrientableROI
Adds Geometry saved withing a Tgl::Group and Unknown int.

Uses the lod list with its own type ViewLODList (ref counted).

### LegoROI : ViewROI
Adds Name, Entity, BoundingSphere. Provides functions to color/texture every lod (also based on global handlers).

### LegoWorld : LegoEntity

#### PlaceActor(...)
Goes through all controllers in m_controllerList and calls PlaceActor().

### LegoActor : LegoEntity
Adds Controller (LegoPathController*), Boundary, CollideBox, LastTime, ActorTime
Has UserNavFlag which presumably defines if user controls this character. Also has an ActorState:

```
enum ActorState {
  // States
  c_initial = 0,
  c_one = 1,
  c_two = 2,
  c_three = 3,
  c_disabled = 4`
  c_maxState = 255,

  // Flags
  c_noCollide = 0x100
}
```

UpdatePlane(LegoNamedPlane&)
PlaceActor(LegoNamedPlane&)

#### ParseAction(char*)
Parses a string like ""ATTACH_CAMERA: location direction up", "SPEED speed", "SOUND sound" , "MUTE" and "VISIBILITY". Saves it into the corresponding member.

### LegoPathController : MxCore
Has PathBoundary (LegoPathBoundary*)

#### PlaceActor(LegoPathActor*)
Removes actor from current controller, and set it to this.

#### PlaceActor(LegoPathActor*, LegoAnimPresenter*, ...)
Removes actor from current controller, does through all boundaries, goes through all presenters of them

### LegoEdge
Has FaceA (LegoWEEdge*), FaceB (LegoWEEdge*), PointA (Vector3), PointB (Vector3). Also utility functions like CWVertex (LegoWEEdge&), CCWVertex (LegoWEEdge&), GetClockwiseEdge(LegoWEEdge&) and GetCounterclockwiseEdge(LegoWEEdge&).

### LegoUnknown100db7f4 : LegoEdge
Adds Flags, a Mx3DPointFloat and a float and some utility functions like DistanceToMidpoint.

### LegoWEEdge
Has Edges (LegoUnknown100db7f4*)

### LegoWEGEdge : LegoWEEdge
Adds EdgeNormal, Flags and other lots of other stuff.

### LegoPathBoundary : LegoWEGEdge
Has actors and presenters.

### LegoNamedPlane
Has Name (char*), Position, Direction and Up. Can be serialized.

### LegoPathActor : LegoActor

### Mx3DPointFloat : Vector3
Just a Vector3, doesn't add much.

## Global Functions

### KeyValueStringParse(char* p_output, const char* p_command, const char* p_string)
The function KeyValueStringParse searches a text (p_string) for a keyword (p_command).
If it finds the keyword, it copies the value immediately after that keyword into p_output.
It returns TRUE if it found the keyword, otherwise FALSE.

Example:
p_string = "foo:123, bar:456, baz:789"
p_command = "bar"

Result:
p_output = "456"
Return value: TRUE
