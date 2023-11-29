
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
	IDirect3D* m_pDirect3D;
	IDirect3DDevice* m_pDirect3DDevice;
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
class Something;

// VTABLE 0x100db980
class Object {
public:
	virtual ~Object() {}

	virtual void* ImplementationDataPtr() = 0;
};

// VTABLE 0x100db948
class Renderer : public Object {
public:
	// vtable+0x08
	virtual Device* CreateDevice(const DeviceDirect3DCreateData&) = 0;
	virtual Device* CreateDevice(const DeviceDirectDrawCreateData&) = 0;

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
	virtual Light* CreateLight(LightType, float p_r, float p_g, float p_b) = 0;
	virtual Group* CreateGroup(const Group* p_parent = 0) = 0;

	// vtable+0x20
	virtual Something* CreateSomething() = 0;
	virtual Texture* CreateTexture() = 0;
	virtual Texture* CreateTexture(
		int p_width,
		int p_height,
		int p_bitsPerTexel,
		const void* p_pTexels,
		int p_pTexelsArePersistent,
		int p_paletteEntryCount,
		const PaletteEntry* p_pEntries
	) = 0;
	virtual Result SetTextureDefaultShadeCount(unsigned long) = 0;

	// vtable+0x30
	virtual Result SetTextureDefaultColorCount(unsigned long) = 0;
};

Renderer* CreateRenderer();

// VTABLE 0x100db9b8
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
};

// VTABLE 0x100dba28
class View : public Object {
public:
	virtual Result Add(const Light*) = 0;
	virtual Result Remove(const Light*) = 0;

	// vtable+0x10
	virtual Result SetCamera(const Camera*) = 0;
	virtual Result SetProjection(ProjectionType) = 0;
	virtual Result SetFrustrum(float p_frontClippingDistance, float p_backClippingDistance, float p_degrees) = 0;
	virtual Result SetBackgroundColor(float p_r, float p_g, float p_b) = 0;

	// vtable+0x20
	virtual Result GetBackgroundColor(float* p_r, float* p_g, float* p_b) = 0;
	virtual Result Clear() = 0;
	virtual Result Render(const Light*) = 0;
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
};

// VTABLE 0x100dbae8
class Camera : public Object {
public:
	virtual Result SetTransformation(const FloatMatrix&) = 0;
};

// VTABLE 0x100dbb08
class Light : public Object {
public:
	virtual Result SetTransformation(const FloatMatrix&) = 0;
	virtual Result SetColor(float p_r, float p_g, float p_b) = 0;
};

// VTABLE 0x100dbbb0
class Mesh : public Object {
public:
	virtual Result SetColor(float p_r, float p_g, float p_b, float p_a) = 0;
	virtual Result SetTexture(const Texture*) = 0;
	virtual Result GetTexture(Texture*&) = 0;

	virtual Result SetTextureMappingMode(ProjectionType) = 0;
	virtual Result SetShadingModel(ShadingModel) = 0;

	// Clone data in underlying group
	virtual Mesh* DeepClone(Something*) = 0;

	// Just get another Group pointing to the same underlying data
	virtual Mesh* ShallowClone(Something*) = 0;
};

// VTABLE 0x100dbaa0
class Group : public Object {
public:
	virtual Result SetTransformation(const FloatMatrix&) = 0;
	virtual Result SetColor(float p_r, float p_g, float p_b, float p_a) = 0;
	virtual Result SetTexture(const Texture*) = 0;
	virtual Result GetTexture(Texture*&) = 0;
	virtual Result SetMaterialMode(MaterialMode) = 0;
	virtual Result Add(const Group*) = 0;
	virtual Result Add(const Mesh*) = 0;
	virtual Result Remove(const Group*) = 0;
	virtual Result Remove(const Mesh*) = 0;
	virtual Result RemoveAll() = 0;

	// This is TransformLocalToWorld in the leak, however it seems
	// to have been replaced by something else in the shipped code.
	virtual Result Unknown() = 0;
};

// Don't know what this is. Seems like another Tgl object which
// was not in the leaked Tgl code. My suspicion is that it's
// some kind of builder class for creating meshes.
// VTABLE 0x100dbb30
class Something : public Object {
public:
	virtual Result SetMeshData(
		unsigned long p_faceCount,
		unsigned long p_vertexCount,
		const float (*p_positions)[3],
		const float (*p_normals)[3],
		const float (*p_textureCoordinates)[2],
		unsigned long p_vertexPerFaceCount,
		unsigned long* p_faceData
	) = 0;
	virtual Result GetBoundingBox(float p_min[3], float p_max[3]) = 0;
	virtual Something* Clone() = 0;
};

// VTABLE 0x100dbb68
class Texture : public Object {
public:
	// vtable+0x08
	virtual Result SetTexels(int p_width, int p_height, int p_bitsPerTexel, void* p_texels) = 0;
	virtual void FillRowsOfTexture(int p_y, int p_height, void* p_buffer) = 0;

	// vtable+0x10
	virtual Result Changed(int p_texelsChanged, int p_paletteChanged) = 0;
	virtual Result GetBufferAndPalette(
		int* p_width,
		int* p_height,
		int* p_depth,
		void** p_buffer,
		int* p_paletteSize,
		PaletteEntry** p_palette
	) = 0;
	virtual Result SetPalette(int p_entryCount, PaletteEntry* p_entries) = 0;
};

} // namespace Tgl

#endif /* _tgl_h */
