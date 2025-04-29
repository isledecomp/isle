# View Management and Rendering

## ViewManager
- **`ViewManager::ViewManager(Tgl::Renderer*, Tgl::Group*, const OrientableROI*)`**: Constructor.
- **`ViewManager::IsBoundingBoxInFrustum(const BoundingBox&)`**: Checks if a bounding box is within the view frustum.
- **`ViewManager::ProjectedSize(const BoundingSphere&)`**: Calculates projected screen size of a bounding sphere.
- **`ViewManager::Update(float, float)`**: Updates visibility and LOD for all ROIs.
- **`ViewManager::CalculateFrustumTransformations()`**: Calculates frustum planes and vertices.
- **`ViewManager::UpdateViewTransformations()`**: Transforms frustum vertices into world space.
- **`ViewManager::SetFrustrum(float, float, float)`**: Sets frustum parameters (FOV, near, far).
- **`ViewManager::SetResolution(int, int)`**: Sets screen resolution.
- **`ViewManager::SetPOVSource(const OrientableROI*)`**: Sets the point of view.
- **`ViewManager::Pick(Tgl::View*, unsigned long, unsigned long)`**: Ray picking to find a `ViewROI`.

## ViewROI
- **`ViewROI::ViewROI(Tgl::Renderer*, ViewLODList*)`**: Constructor.
- **`ViewROI::GetGeometry()`**: Returns `Tgl::Group`.
- **`ViewROI::UpdateWorldData(const Matrix4&)`**: Updates world transform.
- **`ViewROI::SetLocalTransform(const Matrix4&)`**: Sets local transform.
- **`ViewROI::IntrinsicImportance()`**: Returns intrinsic importance (default 0.5).

## ViewLOD
- **`ViewLOD::ViewLOD(Tgl::Renderer*)`**: Constructor.
- **`ViewLOD::GetMeshBuilder()`**: Returns `Tgl::MeshBuilder`.
- **`ViewLOD::AveragePolyArea()`**: Placeholder.
- **`ViewLOD::NVerts()`**: Placeholder.
- `m_unk0x08`: Flags, tested by `GetUnknown0x08Test4()` and `GetUnknown0x08Test8()`.

## ViewLODList
- **`ViewLODList::AddRef()`**: Increments refcount.
- **`ViewLODList::Release()`**: Decrements refcount, deletes if zero.

## ViewLODListManager
- **`ViewLODListManager::Create(const ROIName&, int)`**: Creates `ViewLODList`.
- **`ViewLODListManager::Lookup(const ROIName&)`**: Retrieves `ViewLODList`.
- **`ViewLODListManager::Destroy(ViewLODList*)`**: Destroys `ViewLODList`.

## OrientableROI
- **`OrientableROI::SetLocalTransform(const Matrix4&)`**: Updates transforms.
- **`OrientableROI::UpdateWorldData(const Matrix4&)`**: Updates world data.
- **`OrientableROI::GetLocal2World()`**: Returns local-to-world matrix.
- **`OrientableROI::GetWorldPosition()`**: Returns world position.
- **`OrientableROI::GetWorldDirection()`**: Returns direction vector.
- **`OrientableROI::GetWorldUp()`**: Returns up vector.
- `m_unk0xd8`: Internal flags.

# LEGO-Specific Classes

## LegoROI
- **`LegoROI::LegoROI(Tgl::Renderer*)`**: Constructor.
- **`LegoROI::Read(...)`**: Reads from `LegoStorage`.
- **`LegoROI::FindChildROI(const LegoChar*, LegoROI*)`**: Recursive child search.
- **`LegoROI::SetFrame(LegoAnim*, LegoTime)`**: Sets transform from animation.
- **`LegoROI::IntrinsicImportance()`**: Returns 0.5.
- **`LegoROI::UpdateWorldBoundingVolumes()`**: Updates bounding sphere and box.
- `m_name`, `m_entity`, `m_sphere`: Name, entity pointer, bounding sphere.

## LegoLOD
- **`LegoLOD::LegoLOD(Tgl::Renderer*)`**: Constructor.
- **`LegoLOD::Read(...)`**: Reads and creates meshes.
- **`LegoLOD::Clone(Tgl::Renderer*)`**: Clones the LOD.
- **`LegoLOD::FUN_100aacb0(...)`**: Sets color for non-textured meshes.
- **`LegoLOD::FUN_100aad00(...)`**: Sets texture.
- `m_melems`: Mesh array.
- `m_numMeshes`, `m_numPolys`: Mesh and polygon counts.

## LegoEntity
- **`LegoEntity::Create(MxDSAction&)`**: Initializes entity.
- **`LegoEntity::SetROI(LegoROI*, MxBool, MxBool)`**: Associates ROI.
- **`LegoEntity::SetWorldTransform(...)`**: Sets transform.
- **`LegoEntity::SetWorldSpeed(MxFloat)`**: Sets speed.
- **`LegoEntity::ParseAction(char*)`**: Parses actions.
- **`LegoEntity::ClickSound(MxBool)`**: Plays click sound.
- **`LegoEntity::ClickAnimation()`**: Plays click animation.
- **`LegoEntity::SwitchVariant()`**: Switches model variant.
- `m_roi`, `m_worldLocation`, `m_worldDirection`, `m_worldUp`, `m_worldSpeed`, `m_type`, `m_actionType`, `m_flags`: Entity fields.

## Lego3DManager
- **`Lego3DManager::Create(CreateStruct&)`**: Creates renderer/device/view.
- **`Lego3DManager::Destroy()`**: Destroys renderer/device/view.
- **`Lego3DManager::Render(double)`**: Renders scene.
- **`Lego3DManager::SetFrustrum(float, float, float)`**: Sets frustum.

## Lego3DView
- **`Lego3DView::Create(...)`**: Creates view and `ViewManager`.
- **`Lego3DView::Add(ViewROI&)`**: Adds ROI.
- **`Lego3DView::Remove(ViewROI&)`**: Removes ROI.
- **`Lego3DView::SetPointOfView(ViewROI&)`**: Sets camera ROI.
- **`Lego3DView::Moved(ViewROI&)`**: Updates camera if needed.
- **`Lego3DView::Render(double)`**: Renders scene.
- **`Lego3DView::Pick(unsigned long, unsigned long)`**: Picks ROI.
- `m_pViewManager`: Pointer to `ViewManager`.

## LegoView
- Base class for `Lego3DView`. Manages scene and camera.

## LegoView1
- Subclass of `LegoView`. Adds lighting.

## LegoNavController
- **`LegoNavController::SetTargets(int, int, MxBool)`**: Sets targets.
- **`LegoNavController::CalculateNewPosDir(...)`**: Calculates new position/direction.

## LegoCameraController
- Camera control using mouse and `LegoNavController`.

## LegoPointOfViewController
- Abstracts point-of-view control. Uses `Lego3DView` and `LegoNavController`.

## LegoMouseController
- Handles mouse input (clicks, drags, releases).

# LEGO Game Management

## LegoOmni
- **`LegoOmni::Create(MxOmniCreateParam&)`**: Initializes subsystems.
- **`LegoOmni::Start(MxDSAction*)`**: Starts an action.
- **`LegoOmni::RegisterWorlds()`**: Registers game worlds.
- **`LegoOmni::FindWorld(const MxAtomId&, MxS32)`**: Finds world.
- **`LegoOmni::FindROI(const char*)`**: Finds ROI.

## LegoWorld
- **`LegoWorld::Create(MxDSAction&)`**: Creates world.
- **`LegoWorld::ReadyWorld()`**: Prepares world.
- **`LegoWorld::Enable(MxBool)`**: Enables/disables world.
- **`LegoWorld::Add(MxCore*)`**, **`LegoWorld::Remove(MxCore*)`**: Adds/removes objects.
- **`LegoWorld::Find(const char*, const char*)`**: Finds object.
- **`LegoWorld::PlaceActor(...)`**: Places actor on path.

## LegoWorldList
- List of all worlds, managed by `LegoOmni`.

## LegoGameState
- **`LegoGameState::Save(MxULong)`**, **`LegoGameState::Load(MxULong)`**: Save/load state.
- **`LegoGameState::SwitchArea(Area)`**: Switches area.
- `m_currentAct`, `m_currentArea`, `m_previousArea`: Area tracking.

## LegoState
- Base class for various game element states.

# Media and Animation

## LegoAnim
- **`LegoAnim::Read(...)`**: Reads animation.
- `m_duration`, `m_modelList`: Duration and actors.

## LegoAnimNodeData
- **`LegoAnimNodeData::CreateLocalTransform(LegoFloat, Matrix4&)`**: Local transform at time.

## LegoAnimKey
- Base class for animation keys.
- `m_time`, `m_flags`: Time and flags.

## LegoTranslationKey, LegoRotationKey, LegoScaleKey, LegoMorphKey
- Specialized animation keys.

# Other Utilities

## LegoStorage, LegoMemory, LegoFile
- Abstract base and concrete storage classes.

## BoundingBox, BoundingSphere
- Basic bounding volume structures.

## LegoVertex, LegoColor, LegoSphere, LegoBox, LegoMesh
- Geometry structures.

## LegoTree, LegoTreeNode, LegoTreeNodeData
- Tree structures.

## LegoContainer<T>, LegoTextureContainer
- Containers for collections.

## LegoTextureInfo
- Texture metadata.

## LegoNamedPartList, LegoNamedPart
- Named LEGO parts.

## LegoPathBoundary
- Path boundary, subclass of `LegoWEGEdge`.

## LegoPathController
- Manages paths.

## LegoPathEdgeContainer
- Edge list for paths.

## LegoPathStruct
- Path triggers.

## LegoPathStructNotificationParam
- Notification parameter for path triggers.

# Audio

## LegoCacheSound, LegoCacheSoundManager
- Caching and managing sound effects.

## LegoSoundManager
- Sound management system.

## MxBackgroundAudioManager
- Background music manager.

# Transitions

## MxTransitionManager
- Handles world/area transitions.
