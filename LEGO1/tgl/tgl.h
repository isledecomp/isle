
#ifndef _tgl_h
#define _tgl_h

#include "tglvector.h"

#include <d3d.h>
#include <ddraw.h>
#include <windows.h>

namespace Tgl
{

enum ColorModel {
	// Note: Not used in shipped game, no way to verify contents.
	Ramp,
	RGB
};

enum ShadingModel {
	Wireframe,
	UnlitFlat,
	Flat,
	Gouraud,
	Phong
};

enum LightType {
	Ambient,
	Point,
	Spot,
	Directional,
	ParallelPoint
};

enum ProjectionType {
	Perspective,
	Orthographic
};

enum TextureMappingMode {
	Linear,
	PerspectiveCorrect
};

// Not in the Tgl leak, inferred from the assembly
enum MaterialMode {
	FromParent,
	FromFrame,
	FromMesh,
};

struct PaletteEntry {
	unsigned char m_red;
	unsigned char m_green;
	unsigned char m_blue;
};

struct DeviceDirect3DCreateData {
	IDirect3D2* m_pDirect3D;
	IDirect3DDevice2* m_pDirect3DDevice;
};

struct DeviceDirectDrawCreateData {
	const GUID* m_driverGUID;
	HWND m_hWnd;
	IDirectDraw* m_pDirectDraw;
	IDirectDrawSurface* m_pFrontBuffer;
	IDirectDrawSurface* m_pBackBuffer;

	// These have possibly been removed in the shipped game
	// (Put them back if we can verify when we find a callsite
	// which constructs this type)
	// IDirectDrawPalette* m_pPalette;
	// int m_isFullScreen;
};

// Result type used for all methods in the Tgl API
enum Result {
	Error = 0,
	Success = 1
};

inline int Succeeded(Result result)
{
	return (result == Success);
}

// Forward declarations
class Renderer;
class Object;
class Device;
class View;
class Light;
class Camera;
class Group;
class Mesh;
class Texture;
class MeshBuilder;

// VTABLE: LEGO1 0x100db980
class Object {
public:
	// FUNCTION: LEGO1 0x100a2240
	virtual ~Object() {}

	virtual void* ImplementationDataPtr() = 0;

	// SYNTHETIC: LEGO1 0x100a2250
	// Tgl::Object::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100db948
class Renderer : public Object {
public:
	// vtable+0x08
	virtual Device* CreateDevice(const DeviceDirectDrawCreateData&) = 0;
	virtual Device* CreateDevice(const DeviceDirect3DCreateData&) = 0;

	// vtable+0x10
	virtual View* CreateView(
		const Device*,
		const Camera*,
		unsigned long x,
		unsigned long y,
		unsigned long width,
		unsigned long height
	) = 0;
	virtual Camera* CreateCamera() = 0;
	virtual Light* CreateLight(LightType, float r, float g, float b) = 0;
	virtual Group* CreateGroup(const Group* pParent = 0) = 0;

	// vtable+0x20
	virtual MeshBuilder* CreateMeshBuilder() = 0;
	virtual Texture* CreateTexture(
		int width,
		int height,
		int bitsPerTexel,
		const void* pTexels,
		int pTexelsArePersistent,
		int paletteEntryCount,
		const PaletteEntry* pEntries
	) = 0;
	virtual Texture* CreateTexture() = 0;
	virtual Result SetTextureDefaultShadeCount(unsigned long) = 0;

	// vtable+0x30
	virtual Result SetTextureDefaultColorCount(unsigned long) = 0;

	// SYNTHETIC: LEGO1 0x100a1770
	// Tgl::Renderer::~Renderer

	// SYNTHETIC: LEGO1 0x100a17c0
	// Tgl::Renderer::`scalar deleting destructor'
};

Renderer* CreateRenderer();

// VTABLE: LEGO1 0x100db9b8
class Device : public Object {
public:
	// vtable+0x08
	virtual unsigned long GetWidth() = 0;
	virtual unsigned long GetHeight() = 0;

	// vtable+0x10
	virtual Result SetColorModel(ColorModel) = 0;
	virtual Result SetShadingModel(ShadingModel) = 0;
	virtual Result SetShadeCount(unsigned long) = 0;
	virtual Result SetDither(int) = 0;

	// vtable+0x20
	virtual Result Update() = 0;
	virtual void InitFromD3DDevice(Device*) = 0;
	virtual void InitFromWindowsDevice(Device*) = 0;

	// SYNTHETIC: LEGO1 0x100a2350
	// Tgl::Device::~Device

	// SYNTHETIC: LEGO1 0x100a28e0
	// Tgl::Device::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dba28
class View : public Object {
public:
	virtual Result Add(const Light*) = 0;
	virtual Result Remove(const Light*) = 0;

	// vtable+0x10
	virtual Result SetCamera(const Camera*) = 0;
	virtual Result SetProjection(ProjectionType) = 0;
	virtual Result SetFrustrum(float frontClippingDistance, float backClippingDistance, float degrees) = 0;
	virtual Result SetBackgroundColor(float r, float g, float b) = 0;

	// vtable+0x20
	virtual Result GetBackgroundColor(float* r, float* g, float* b) = 0;
	virtual Result Clear() = 0;
	virtual Result Render(const Group*) = 0;
	virtual Result ForceUpdate(unsigned long x, unsigned long y, unsigned long width, unsigned long height) = 0;

	// vtable+0x30
	virtual Result TransformWorldToScreen(const float world[3], float screen[4]) = 0;
	virtual Result TransformScreenToWorld(const float screen[4], float world[3]) = 0;

	// Pick():
	//  x, y:
	//      view coordinates
	//
	//  ppGroupsToPickFrom:
	//      array of (Group*) in any order
	//      Groups to pick from
	//
	//  groupsToPickFromCount:
	//      size of ppGroupsToPickFrom
	//
	//  rppPickedGroups:
	//      output parameter
	//      array of (Group*) representing a Group hierarchy
	//      top-down order (element 0 is root/scene)
	//      caller must deallocate array
	//      ref count of each element (Group*) has not been increased
	//      an element will be 0, if a corresponding Group was not found in ppGroupsToPickFrom
	//
	//  rPickedGroupCount:
	//      output parameter
	//      size of rppPickedGroups
	virtual Result Pick(
		unsigned long x,
		unsigned long y,
		const Group** ppGroupsToPickFrom,
		int groupsToPickFromCount,
		const Group**& rppPickedGroups,
		int& rPickedGroupCount
	) = 0;

	// SYNTHETIC: LEGO1 0x100a2430
	// Tgl::View::~View

	// SYNTHETIC: LEGO1 0x100a2950
	// Tgl::View::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dbae8
class Camera : public Object {
public:
	virtual Result SetTransformation(FloatMatrix4&) = 0;

	// SYNTHETIC: LEGO1 0x100a25f0
	// Tgl::Camera::~Camera

	// SYNTHETIC: LEGO1 0x100a2a30
	// Tgl::Camera::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dbb08
class Light : public Object {
public:
	virtual Result SetTransformation(FloatMatrix4&) = 0;
	virtual Result SetColor(float r, float g, float b) = 0;

	// SYNTHETIC: LEGO1 0x100a26d0
	// Tgl::Light::~Light

	// SYNTHETIC: LEGO1 0x100a2aa0
	// Tgl::Light::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dbbb0
class Mesh : public Object {
public:
	// SYNTHETIC: LEGO1 0x100a3e10
	// Tgl::Mesh::~Mesh

	virtual Result SetColor(float r, float g, float b, float a) = 0;
	virtual Result SetTexture(const Texture*) = 0;
	virtual Result GetTexture(Texture*&) = 0;

	virtual Result SetTextureMappingMode(TextureMappingMode) = 0;
	virtual Result SetShadingModel(ShadingModel) = 0;

	// Clone data in underlying group
	virtual Mesh* DeepClone(MeshBuilder*) = 0;

	// Just get another Group pointing to the same underlying data
	virtual Mesh* ShallowClone(MeshBuilder*) = 0;

	// SYNTHETIC: LEGO1 0x100a3e60
	// Tgl::Mesh::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dbaa0
class Group : public Object {
public:
	virtual Result SetTransformation(FloatMatrix4&) = 0;
	virtual Result SetColor(float r, float g, float b, float a) = 0;
	virtual Result SetTexture(const Texture*) = 0;
	virtual Result GetTexture(Texture*&) = 0;
	virtual Result SetMaterialMode(MaterialMode) = 0;
	virtual Result Add(const Group*) = 0;
	virtual Result Add(const MeshBuilder*) = 0;
	virtual Result Remove(const Group*) = 0;
	virtual Result Remove(const MeshBuilder*) = 0;
	virtual Result RemoveAll() = 0;

	// This is TransformLocalToWorld in the leak, however it seems
	// to have been replaced by something else in the shipped code.
	virtual Result Unknown() = 0;

	// SYNTHETIC: LEGO1 0x100a2510
	// Tgl::Group::~Group

	// SYNTHETIC: LEGO1 0x100a29c0
	// Tgl::Group::`scalar deleting destructor'
};

// Don't know what this is. Seems like another Tgl object which
// was not in the leaked Tgl code. My suspicion is that it's
// some kind of builder class for creating meshes.
// VTABLE: LEGO1 0x100dbb30
class MeshBuilder : public Object {
public:
	virtual Mesh* CreateMesh(
		unsigned long faceCount,
		unsigned long vertexCount,
		float (*pPositions)[3],
		float (*pNormals)[3],
		float (*pTextureCoordinates)[2],
		unsigned long (*pFaceIndices)[3],
		unsigned long (*pTextureIndices)[3],
		ShadingModel shadingModel
	) = 0;
	virtual Result GetBoundingBox(float min[3], float max[3]) = 0;
	virtual MeshBuilder* Clone() = 0;

	// SYNTHETIC: LEGO1 0x100a27b0
	// Tgl::MeshBuilder::~MeshBuilder

	// SYNTHETIC: LEGO1 0x100a2b10
	// Tgl::MeshBuilder::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dbb68
class Texture : public Object {
public:
	// vtable+0x08
	virtual Result SetTexels(int width, int height, int bitsPerTexel, void* pTexels) = 0;
	virtual void FillRowsOfTexture(int y, int height, void* pBuffer) = 0;

	// vtable+0x10
	virtual Result Changed(int texelsChanged, int paletteChanged) = 0;
	virtual Result GetBufferAndPalette(
		int* pWidth,
		int* pHeight,
		int* pDepth,
		void** ppBuffer,
		int* pPaletteSize,
		PaletteEntry** ppPalette
	) = 0;
	virtual Result SetPalette(int entryCount, PaletteEntry* pEntries) = 0;

	// SYNTHETIC: LEGO1 0x100a2890
	// Tgl::Texture::~Texture

	// SYNTHETIC: LEGO1 0x100a2b80
	// Tgl::Texture::`scalar deleting destructor'
};

} // namespace Tgl

#endif /* _tgl_h */
