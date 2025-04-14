
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

// FUNCTION: BETA10 0x10169c60
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
// VTABLE: BETA10 0x101c3148
class Object {
public:
	// FUNCTION: LEGO1 0x100a2240
	// FUNCTION: BETA10 0x10169c90
	virtual ~Object() {}

	virtual void* ImplementationDataPtr() = 0;

	// SYNTHETIC: BETA10 0x10169b50
	// Tgl::Object::Object

	// SYNTHETIC: LEGO1 0x100a2250
	// SYNTHETIC: BETA10 0x10169cb0
	// Tgl::Object::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100db948
// VTABLE: BETA10 0x101c3110
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

	// SYNTHETIC: BETA10 0x10169ae0
	// Tgl::Renderer::Renderer

	// SYNTHETIC: LEGO1 0x100a1770
	// SYNTHETIC: BETA10 0x10169b80
	// Tgl::Renderer::~Renderer

	// SYNTHETIC: LEGO1 0x100a17c0
	// SYNTHETIC: BETA10 0x10169be0
	// Tgl::Renderer::`scalar deleting destructor'
};

Renderer* CreateRenderer();

// VTABLE: LEGO1 0x100db9b8
// VTABLE: BETA10 0x101c32b0
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
	virtual void HandleActivate(WORD) = 0;
	virtual void HandlePaint(HDC) = 0;

	// SYNTHETIC: BETA10 0x1016b740
	// Tgl::Device::Device

	// SYNTHETIC: LEGO1 0x100a2350
	// SYNTHETIC: BETA10 0x1016b7b0
	// Tgl::Device::~Device

	// SYNTHETIC: LEGO1 0x100a28e0
	// SYNTHETIC: BETA10 0x1016bbc0
	// Tgl::Device::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dba28
// VTABLE: BETA10 0x101c32e0
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

	// SYNTHETIC: BETA10 0x1016b850
	// Tgl::View::View

	// SYNTHETIC: LEGO1 0x100a2430
	// SYNTHETIC: BETA10 0x1016b8c0
	// Tgl::View::~View

	// SYNTHETIC: LEGO1 0x100a2950
	// SYNTHETIC: BETA10 0x1016bc00
	// Tgl::View::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dbae8
// VTABLE: BETA10 0x101c3320
class Camera : public Object {
public:
	virtual Result SetTransformation(FloatMatrix4&) = 0;

	// SYNTHETIC: BETA10 0x1016b960
	// Tgl::Camera::Camera

	// SYNTHETIC: LEGO1 0x100a25f0
	// SYNTHETIC: BETA10 0x1016b9d0
	// Tgl::Camera::~Camera

	// SYNTHETIC: LEGO1 0x100a2a30
	// SYNTHETIC: BETA10 0x1016bc40
	// Tgl::Camera::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dbb08
// VTABLE: BETA10 0x101c32a0
class Light : public Object {
public:
	virtual Result SetTransformation(FloatMatrix4&) = 0;
	virtual Result SetColor(float r, float g, float b) = 0;

	// SYNTHETIC: BETA10 0x1016b630
	// Tgl::Light::Light

	// SYNTHETIC: LEGO1 0x100a26d0
	// SYNTHETIC: BETA10 0x1016b6a0
	// Tgl::Light::~Light

	// SYNTHETIC: LEGO1 0x100a2aa0
	// SYNTHETIC: BETA10 0x1016bb80
	// Tgl::Light::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dbbb0
// VTABLE: BETA10 0x101c3360
class Mesh : public Object {
public:
	virtual Result SetColor(float r, float g, float b, float a) = 0;
	virtual Result SetTexture(const Texture*) = 0;
	virtual Result GetTexture(Texture*&) = 0;

	virtual Result SetTextureMappingMode(TextureMappingMode) = 0;
	virtual Result SetShadingModel(ShadingModel) = 0;

	// Clone data in underlying group
	virtual Mesh* DeepClone(MeshBuilder*) = 0;

	// Just get another Group pointing to the same underlying data
	virtual Mesh* ShallowClone(MeshBuilder*) = 0;

	// SYNTHETIC: BETA10 0x1016fad0
	// Tgl::Mesh::Mesh

	// SYNTHETIC: LEGO1 0x100a3e10
	// SYNTHETIC: BETA10 0x1016fb40
	// Tgl::Mesh::~Mesh

	// SYNTHETIC: LEGO1 0x100a3e60
	// SYNTHETIC: BETA10 0x1016fbe0
	// Tgl::Mesh::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dbaa0
// VTABLE: BETA10 0x101c3188
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
	virtual Result Bounds(D3DVECTOR*, D3DVECTOR*) = 0;

	// SYNTHETIC: BETA10 0x1016a300
	// Tgl::Group::Group

	// SYNTHETIC: LEGO1 0x100a2510
	// SYNTHETIC: BETA10 0x1016a370
	// Tgl::Group::~Group

	// SYNTHETIC: LEGO1 0x100a29c0
	// SYNTHETIC: BETA10 0x1016a3d0
	// Tgl::Group::`scalar deleting destructor'
};

// Don't know what this is. Seems like another Tgl object which
// was not in the leaked Tgl code. My suspicion is that it's
// some kind of builder class for creating meshes.
// VTABLE: LEGO1 0x100dbb30
// VTABLE: BETA10 0x101c3330
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
	virtual Result GetBoundingBox(float min[3], float max[3]) const = 0;
	virtual MeshBuilder* Clone() = 0;

	// SYNTHETIC: BETA10 0x1016ba70
	// Tgl::MeshBuilder::MeshBuilder

	// SYNTHETIC: LEGO1 0x100a27b0
	// SYNTHETIC: BETA10 0x1016bae0
	// Tgl::MeshBuilder::~MeshBuilder

	// SYNTHETIC: LEGO1 0x100a2b10
	// SYNTHETIC: BETA10 0x1016bc80
	// Tgl::MeshBuilder::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dbb68
// VTABLE: BETA10 0x101c3280
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

	// SYNTHETIC: BETA10 0x1016b520
	// Tgl::Texture::Texture

	// SYNTHETIC: LEGO1 0x100a2890
	// SYNTHETIC: BETA10 0x1016b590
	// Tgl::Texture::~Texture

	// SYNTHETIC: LEGO1 0x100a2b80
	// SYNTHETIC: BETA10 0x1016bb40
	// Tgl::Texture::`scalar deleting destructor'
};

} // namespace Tgl

#endif /* _tgl_h */
