#!/usr/bin/env python3
import os
import shutil
from pathlib import Path

import dotenv
from openai import OpenAI

dotenv.load_dotenv()

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])


def get_skeleton(header: str, source: str) -> str:
    response = client.responses.create(
        model="gpt-4.1",
        instructions="""You will receive the code of a header and source file. Add Doxygen annotations to it.

Use the documentation and source files to understand what every class, member, method and function does. Add detailed explanations for everything in the annotations.

- Prefix everything you add with "[AI]" so that we can validate it later
- If there are already comment or annotations, add them to your annotations.
- Ignore the cpp and reference files. They only there for you to give you some context for the annotations.
- Don't add generic annotations that are not helpful. For example, if the function is getPosition, don't add an annotation like "Gets the position"
- If you encounter a class/method or member that is unknown (e.g. m_unk0x10, FUN_10001510 etc.) and you know what it is or does, add a "[AI_SUGGESTED_NAME: <name>]" in the annotations to it.
- Only return the annotated header file, nothing else. Do NOT return the source file. Do NOT put it into a ``` markdown code block.

I will now give you a rough documentation of the codebase to use as a reference:

# Documentation

This codebase is a decompilation of the 1997 game LEGO Island and implements the game's rendering, user input, game logic, and resource management. It uses a combination of custom C++ classes and the Microsoft DirectX 5 API for 3D graphics and sound.

## Terminology and Core Concepts:
* **Script**: SI File (it appears they wanted to use SI much more as actual scripts, but ended up hard-coding almost everything)
* **ROI (Real-time Object Instance):**  The base class for any object that can be placed in the 3D world.  It handles visibility, world bounding volumes (bounding box and sphere), intrinsic importance (for LOD), and contains a list of LOD objects.
* **Mx (Mindscape):** Prefix for general utility classes provided by Mindscape, the game developer, like `MxString`, `MxMatrix`, `MxList`, etc.
* **Omni:** Name of the engine.

## Basic Architecture:

The code follows a component-based architecture, with separate modules for rendering, input, game logic, and resource management.  The `LegoOmni` class acts as the central hub, coordinating the different subsystems.

The code uses a combination of event-driven programming (for input and notifications) and a tick-based update loop (for game logic and animation).  It makes heavy use of the retained mode features of Direct3DRM for scene management.

## Core Concepts

### Tickling

MxCore objects can be registered to be tickled by the MxTickleManager. This is used to update them in a set interval. This is used for loading the next frame of a video, update 3D sound positions and more.

## Classes

### MxAtom
Key (string) / Value (U16) pair.

Inc()
Dec()

### MxAtomId
String with lookup method (upper case/lower case/exact). Used for IDs.

MxOmni holds an AtomSet that contains MxAtoms for every MxAtomId created + a counter of how many instances exists (purpose unclear).

### MxString
Typical string class with utility functions.

### MxCore
Virtual base class.

Tickle()
Notify(MyParam)
GetId()
ClassName()

IsA()
Checks ALL parents.

### MxTickleManager : MxCore
Holds a list of MxTickleClient*. Goes though them on Tickle() and calls Tickle() if interval time has passed.

### MxTickleClient
Holds a MxCore*, Interval, LastUpdateTime and Flags (only used for TICKLE_MANAGER_FLAG_DESTROY?).

### IsleApp
Main class and the entry point of the game.

### MxOmni

#### Start(MxDSAction*)


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

### MxDSObjectAction : MxDSMediaAction
Adds nothing.

### MxVariableTable : MxHashTable<MxVariable*>
MxOmni holds a VariableTable that is just a key/value store string/string.

### MxPresenter : MxCore
Abstract base class for all presenters. Separates the tickle down to ReadyTickle(), StartingTickle(), StreamingTickle(), RepeatingTickle(), FreezingTickle() and DoneTickle()

Similar to DeserializeDSObjectDispatch, there is a PresenterNameDispatch() that reads the media format (" FLC", " SMK", " MID", " WAV") and returns the corresponding HandlerClassName().

### MxMediaPresenter : MxPresenter
Hold a MxDSSubscriber* and reads data from it on the tickles.

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

UpdatePlane(LegoNamedPlane&)
PlaceActor(LegoNamedPlane&)

#### ParseAction(char*)
Parses a string like ""ATTACH_CAMERA: location direction up", "SPEED speed", "SOUND sound" , "MUTE" and "VISIBILITY". Saves it into the corresponding member.

### LegoPathController : MxCore
Has PathBoundary (LegoPathBoundary*) a set of actors and many other things. Presumably it controls the movement of actors along paths.

#### PlaceActor(LegoPathActor*)
Removes actor from current controller, and set it to this.

#### PlaceActor(LegoPathActor*, LegoAnimPresenter*, ...)
Removes actor from current controller, does through all boundaries, goes through all presenters of them


### LegoPathActor : LegoActor

### MxStreamer : MxCore
MxMisc holds a MxStreamer singleton. Also holds a list of MxStreamController.

#### Open(const char*, MxU16 p_lookupType)
Creates and calls Open() on a MxDiskStreamController or MxRAMStreamController depending on lookupType if not already exists.

### MxDSSubscriber : MxCore

#### Create(MxStreamController* p_controller, MxU32 p_objectId, MxS16 p_unk0x48)
Calls MxStreamController::AddSubscriber() and sets some properties on itself.

### MxStreamController : MxCore
Holds a list of subscriber.

#### AddSubscriber(MxDSSubscriber*)
Puts it into the subscriber list.

#### Open(const char* p_filename)
Removes "<letter>:" and ".SI" from filename and stores it in m_atom.

### MxRAMStreamController : MxStreamController
Holds an MxDSBuffer.

### MxDSBuffer : MxCore

### MxStreamProvider : MxCore
Abstract base class. Holds an MxDSFile.

### MxRAMStreamProvider : MxStreamProvider

#### SetResourceToGet(MxStreamController*)
Gets the stream controllers Atom, adds ".SI". Tries to load it first from HDD and then from disk. Sets BufferSize to MxDSFile.BufferSize. Then reads the entire file into m_pContentsOfFile.

#### MxU32 ReadData(MxU8* p_buffer, MxU32 p_size)
Return total size of MxOb. Rearranged p_buffer so that split chunks are merged.

### MxDSStreamingAction : MxDSAction
Mostly unknown.

### MxDiskStreamProvider : MxStreamProvider
Holds a list of MxDSStreamingAction.

#### SetResourceToGet(MxStreamController*)
Gets the stream controllers Atom, adds ".SI". Tries to load it first from HDD and then from disk. Then starts a MxDiskStreamProviderThread with target this.

#### MxDiskStreamProvider::WaitForWorkToComplete()
Called by the thread. Run indefinitely until object is destroyed. Streams data, code mostly unknown.

### MxThread
Abstract base class for threads. Starts and manages one. Has abstract Run() method.

### MxDiskStreamProviderThread : MxThread
Calls MxDiskStreamProvider::WaitForWorkToComplete.

### MxDSChunk : MxCore
Holds Flags, ObjectId, Time, Data (U8*) and Length. Also some static utility functions.

### MxDSSource : MxCore
Holds a buffer, length and position and offers abstract function to read and write.

### MxDSFile : MxDSSource
Presumably this represents an SI file. Holds a MXIOINFO and on Open() opens m_filename and starts reading the starting chunks ("OMNI" etc.) also checks SI version (2.2). Then it reads the length of the MxOf chunk and puts it into m_pBuffer from parent class.

Also holds the header chunk as ChunkHeader. GetBufferSize() returns the buffer size from the header.

### LegoEdge
Has FaceA (LegoWEEdge*), FaceB (LegoWEEdge*), PointA (Vector3), PointB (Vector3). Also utility functions like CWVertex (LegoWEEdge&), CCWVertex (LegoWEEdge&), GetClockwiseEdge(LegoWEEdge&) and GetCounterclockwiseEdge(LegoWEEdge&).

### LegoUnknown100db7f4 : LegoEdge
Adds Flags, a Mx3DPointFloat and a float and some utility functions like DistanceToMidpoint.

### LegoWEEdge
Has Edges (LegoUnknown100db7f4*)

### LegoWEGEdge : LegoWEEdge
Adds EdgeNormal, Flags and other lots of other stuff.

### LegoPathBoundary : LegoWEGEdge
Adds actors and presenters.

### LegoNamedPlane
Has Name (char*), Position, Direction and Up. Can be serialized.

### LegoStorage
Abstract base class for a file-file object with positioning, reading/writing basic data types etc.

### LegoMemory : LegoStorage
LegoStorage operating on a U8 pointer.

### LegoFile : LegoStorage
LegoStorage operating on a File.

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

Return just the annotated header file, nothing else. Do NOT return the source file. Do NOT put it into a ``` markdown code block.

Here are some relevant source and header files. They are just a reference for you to better understand the code:
""",
        input=f"Header: {header}\nSource: {source}\n\nNow return just the annotated header file, nothing else. Do NOT return the source file. Do NOT put it into a ``` markdown code block.",
    )
    return response.output_text


root = Path.cwd()
out_root = root / "skeleton"

import asyncio
from concurrent.futures import ThreadPoolExecutor

headers = [
    p
    for p in root.rglob("*")
    if p.is_file()
    and p.suffix in {".h", ".hpp", ".hh", ".hxx"}
    and "skeleton" not in str(p)
]
total = len(headers)


def handle(n, h):
    s = h.with_suffix(".cpp")
    if not s.exists():
        try:
            r = h.relative_to(root)
            parts = list(r.parts)
            if "include" in parts:
                parts[parts.index("include")] = "source"
                s = root / Path(*parts).with_suffix(".cpp")
        except ValueError:
            pass
    if not s.exists():
        m = list(root.rglob(f"{h.stem}.cpp"))
        if m:
            s = m[0]
    if not s.exists():
        return
    oh = out_root / h.relative_to(root)
    oh.parent.mkdir(parents=True, exist_ok=True)
    if not oh.exists():
        oh.write_text(get_skeleton(h.read_text(), s.read_text()))
    os = out_root / s.relative_to(root)
    os.parent.mkdir(parents=True, exist_ok=True)
    if not os.exists():
        shutil.copy2(s, os)
    print(f"processed {n}/{total}")


async def main():
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=20) as ex:
        await asyncio.gather(
            *(loop.run_in_executor(ex, handle, n, h) for n, h in enumerate(headers, 1))
        )


asyncio.run(main())
