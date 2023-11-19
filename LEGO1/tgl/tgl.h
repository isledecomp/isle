#ifndef TGL_H
#define TGL_H

#ifdef _WIN32

#define NOMINMAX // to avoid conflict with STL
#include <d3d.h>
#include <ddraw.h>
#include <windows.h> // HWND

#endif /* _WIN32 */

#include "tglVector.h"

namespace Tgl
{

// ???
enum ColorModel {
	Ramp,
	RGB
};

// ???
enum ShadingModel {
	Wireframe,
	UnlitFlat,
	Flat,
	Gouraud,
	Phong
};

// ?????
enum LightType {
	Ambient,
	Point,
	Spot,
	Directional,
	ParallelPoint
};

// ???
enum ProjectionType {
	Perspective,
	Orthographic
};

enum TextureMappingMode {
	Linear,
	PerspectiveCorrect
};

struct PaletteEntry {
	unsigned char m_red;
	unsigned char m_green;
	unsigned char m_blue;
};

#ifdef _WIN32

struct DeviceDirectDrawCreateData {
	const GUID* m_driverGUID;
	HWND m_hWnd; // ??? derive from m_pDirectDraw
	IDirectDraw* m_pDirectDraw;
	IDirectDrawSurface* m_pFrontBuffer; // ??? derive from m_pDirectDraw
	IDirectDrawSurface* m_pBackBuffer;
	IDirectDrawPalette* m_pPalette; // ??? derive from m_pDirectDraw
	int m_isFullScreen;             // ??? derive from m_pDirectDraw
};

struct DeviceDirect3DCreateData {
	IDirect3D* m_pDirect3D;
	IDirect3DDevice* m_pDirect3DDevice;
};

#else

struct DeviceDirectDrawCreateData {};

#endif

//////////////////////////////////////////////////////////////////////////////
//
// Result (return value type)

enum Result {
	Error = 0,
	Success = 1
};

inline int Succeeded(Result result)
{
	return (result == Success);
}

//////////////////////////////////////////////////////////////////////////////
//
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

//////////////////////////////////////////////////////////////////////////////
//
// Object

class Object {
public:
	virtual ~Object() {}

	// returns pointer to implementation data
	virtual void* ImplementationDataPtr() = 0;
};

//////////////////////////////////////////////////////////////////////////////
//
// Renderer

// ??? for now until we figured out how an app should pass the Renderer around
Renderer* CreateRenderer();

class Renderer : public Object {
public:
	virtual Device* CreateDevice(const DeviceDirectDrawCreateData&) = 0;
	virtual Device* CreateDevice(const DeviceDirect3DCreateData&) = 0;
	virtual View* CreateView(
		const Device*,
		const Camera*,
		unsigned long x,
		unsigned long y,
		unsigned long width,
		unsigned long height
	) = 0;
	virtual Camera* CreateCamera() = 0;
	virtual Light* CreateLight(LightType, double r, double g, double b) = 0;
	virtual Group* CreateGroup(const Group* pParent = 0) = 0;

	// pTextureCoordinates is pointer to array of vertexCount elements
	//  (each element being two floats), or NULL
	// pFaceData is faceCount tuples, each of format
	//  [vertex1index, ... vertexNindex], where N = vertexPerFaceCount
	virtual Mesh* CreateMesh(
		unsigned long vertexCount,
		const float (*pVertices)[3],
		const float (*pTextureCoordinates)[2],
		unsigned long faceCount,
		unsigned long vertexPerFaceCount,
		unsigned long* pFaceData
	) = 0;
	// pTextureCoordinates is pointer to array of vertexCount elements
	//  (each element being two floats), or NULL
	// pFaceData is:
	//  [face1VertexCount face1Vertex1index, ... face1VertexMindex
	//   face2VertexCount face2Vertex1index, ... face2VertexNindex
	//   ...
	//   0]
	virtual Mesh* CreateMesh(
		unsigned long vertexCount,
		const float (*pVertices)[3],
		const float (*pTextureCoordinates)[2],
		unsigned long* pFaceData
	) = 0;
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
	virtual Result SetTextureDefaultColorCount(unsigned long) = 0;
};

//////////////////////////////////////////////////////////////////////////////
//
// Device

class Device : public Object {
public:
	virtual unsigned long GetWidth() = 0;
	virtual unsigned long GetHeight() = 0;
	virtual Result SetColorModel(ColorModel) = 0;
	virtual Result SetShadingModel(ShadingModel) = 0;
	virtual Result SetShadeCount(unsigned long) = 0;
	virtual Result SetDither(int) = 0;
	virtual Result Update() = 0;

	// ??? should this be handled by app ???
	// ??? this needs to be called when the window on which the device is ...
	// is being activated
	virtual void HandleActivate(int bActivate) = 0;

	// ??? this needs to be called when the window on which this device is based
	// needs to be repainted
	virtual void HandlePaint(void*) = 0;

#ifdef _DEBUG
	virtual unsigned long GetDrawnTriangleCount() = 0;
#endif
};

//////////////////////////////////////////////////////////////////////////////
//
// View

class View : public Object {
public:
	virtual Result Add(const Light*) = 0;
	virtual Result Remove(const Light*) = 0;

	virtual Result SetCamera(const Camera*) = 0;
	virtual Result SetProjection(ProjectionType) = 0;
	virtual Result SetFrustrum(double frontClippingDistance, double backClippingDistance, double degrees) = 0;
	virtual Result SetBackgroundColor(double r, double g, double b) = 0;

	virtual Result Clear() = 0;
	virtual Result Render(const Group*) = 0;
	// ??? needed for fine grain control when using DirectDraw/D3D ???
	virtual Result ForceUpdate(unsigned long x, unsigned long y, unsigned long width, unsigned long height) = 0;

	// ??? for now: used by Mesh Cost calculation
	virtual Result TransformWorldToScreen(const double world[3], double screen[4]) = 0;

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

//////////////////////////////////////////////////////////////////////////////
//
// Camera

class Camera : public Object {
public:
#if 0
    virtual Result  SetPosition(const double[3]) = 0;
    virtual Result  SetOrientation(const double direction[3],
                                   const double up[3]) = 0;
#endif
	virtual Result SetTransformation(const FloatMatrix4&) = 0;
};

//////////////////////////////////////////////////////////////////////////////
//
// Light

class Light : public Object {
public:
#if 0
    virtual Result  SetPosition(const double[3]) = 0;
    virtual Result  SetOrientation(const double direction[3],
                                   const double up[3]) = 0;
#endif
	virtual Result SetTransformation(const FloatMatrix4&) = 0;
};

//////////////////////////////////////////////////////////////////////////////
//
// Group

class Group : public Object {
public:
#if 0
    virtual Result  SetPosition(const double[3]) = 0;
    virtual Result  SetOrientation(const double direction[3],
                                   const double up[3]) = 0;
#endif
	// TODO: The type was changed from `FloatMatrix` to `Matrix` to make code in UpdateWorldData match.
	// However, this is unlikely to be correct and will have to be figured out at some point.
	virtual Result SetTransformation(const Matrix4&) = 0;

	// ??? not yet fully implemented
	virtual Result SetColor(double r, double g, double b) = 0;
	virtual Result SetTexture(const Texture*) = 0;

	virtual Result Add(const Group*) = 0;
	virtual Result Add(const Mesh*) = 0;

	virtual Result Remove(const Group*) = 0;
	virtual Result Remove(const Mesh*) = 0;

	virtual Result RemoveAll() = 0;

	// ??? for now: used by Mesh Cost calculation
	virtual Result TransformLocalToWorld(const double local[3], double world[3]) = 0;
};

//////////////////////////////////////////////////////////////////////////////
//
// Mesh

class Mesh : public Object {
public:
	// ??? also on Group
	virtual Result SetColor(double r, double g, double b) = 0;
	virtual Result SetTexture(const Texture*) = 0;
	virtual Result SetTextureMappingMode(TextureMappingMode) = 0;
	virtual Result SetShadingModel(ShadingModel) = 0;

#ifdef _DEBUG
	virtual Result GetBoundingBox(float min[3], float max[3]) = 0;
	virtual unsigned long GetFaceCount() = 0;
	virtual unsigned long GetVertexCount() = 0;
#endif
};

//////////////////////////////////////////////////////////////////////////////
//
// Texture

class Texture : public Object {
public:
	virtual Result SetTexels(
		int width,
		int height,
		int bitsPerTexel,
		const void* pTexels,
		int pTexelsArePersistent
	) = 0;
	virtual Result SetPalette(int entryCount, const PaletteEntry* pEntries) = 0;
};

//////////////////////////////////////////////////////////////////////////////

} // namespace Tgl

#endif // TGL_H
