#ifndef TGL_D3DRM_TGLIMPL_H
#define TGL_D3DRM_TGLIMPL_H

#include "compat.h"
#include "decomp.h"
#include "tgl/tgl.h"

#include <assert.h>
#include <d3drm.h>

#ifdef DIRECTX5_SDK
typedef DWORD LPD3DRM_APPDATA;
#else
typedef LPVOID LPD3DRM_APPDATA;
#endif

// Forward declare D3D types
struct IDirect3DRM2;
struct IDirect3DRMDevice2;
struct IDirect3DRMViewport;
struct IDirect3DRMFrame2;
struct IDirect3DRMMesh;
struct IDirect3DRMMeshBuilder;
struct IDirect3DRMTexture;

namespace TglImpl
{

using namespace Tgl;

// Forward declare implementations
class RendererImpl;
class DeviceImpl;
class ViewImpl;
class LightImpl;
class CameraImpl;
class GroupImpl;
class MeshImpl;
class TextureImpl;
class MeshBuilderImpl;

// Helper implementations live in tglrl40.h; the method bodies below only
// need their prototypes. BETA10 places every assert of these helpers in
// tglRL40.h and every assert of the Impl methods in tglImpl.h.
Result RendererCreateDevice(IDirect3DRM2*, const DeviceDirect3DCreateData&, IDirect3DRMDevice2*&);
Result RendererCreateDevice(IDirect3DRM2*, const DeviceDirectDrawCreateData&, IDirect3DRMDevice2*&);
Result
RendererCreateView(IDirect3DRM2*, const IDirect3DRMDevice2*, const IDirect3DRMFrame2*, unsigned long x, unsigned long y, unsigned long width, unsigned long height, IDirect3DRMViewport*&);
Result RendererCreateGroup(IDirect3DRM2*, const IDirect3DRMFrame2*, IDirect3DRMFrame2*&);
Result RendererCreateCamera(IDirect3DRM2*, IDirect3DRMFrame2*&);
Result RendererCreateLight(IDirect3DRM2*, LightType, float r, float g, float b, IDirect3DRMFrame2*&);
Result RendererCreateMeshBuilder(IDirect3DRM2*, IDirect3DRMMesh*&);
Result
RendererCreateTexture(IDirect3DRM2*, int width, int height, int bytesPerPixel, void* pBuffer, int useBuffer, int paletteSize, PaletteEntry* pEntries, IDirect3DRMTexture*&);
Result RendererCreateTexture(IDirect3DRM2*, IDirect3DRMTexture*&);
Result RendererSetTextureDefaultShadeCount(IDirect3DRM2*, unsigned long);
Result RendererSetTextureDefaultColorCount(IDirect3DRM2*, unsigned long);
void RendererDestroy(IDirect3DRM2*);
unsigned long DeviceGetWidth(IDirect3DRMDevice2*);
unsigned long DeviceGetHeight(IDirect3DRMDevice2*);
Result DeviceSetColorModel(IDirect3DRMDevice2*, ColorModel);
Result DeviceSetShadingModel(IDirect3DRMDevice2*, ShadingModel);
Result DeviceSetShadeCount(IDirect3DRMDevice2*, unsigned long);
Result DeviceSetDither(IDirect3DRMDevice2*, int);
void DeviceHandleActivate(IDirect3DRMDevice2*, WORD);
void DeviceHandlePaint(IDirect3DRMDevice2*, void*);
Result DeviceUpdate(IDirect3DRMDevice2*);
unsigned long DeviceGetTrianglesDrawn(IDirect3DRMDevice2*);
void DeviceDestroy(IDirect3DRMDevice2*);
Result ViewAddLight(IDirect3DRMViewport*, const IDirect3DRMFrame*);
Result ViewRemoveLight(IDirect3DRMViewport*, const IDirect3DRMFrame*);
Result ViewSetCamera(IDirect3DRMViewport*, const IDirect3DRMFrame2*);
Result ViewSetProjection(IDirect3DRMViewport*, ProjectionType);
Result ViewSetFrustrum(IDirect3DRMViewport*, float frontClippingDistance, float backClippingDistance, float degrees);
Result ViewSetBackgroundColor(IDirect3DRMViewport*, float r, float g, float b);
Result ViewGetBackgroundColor(IDirect3DRMViewport*, float* r, float* g, float* b);
Result ViewClear(IDirect3DRMViewport*);
Result ViewRender(IDirect3DRMViewport*, const IDirect3DRMFrame2*);
Result ViewForceUpdate(
	IDirect3DRMViewport*,
	unsigned long x,
	unsigned long y,
	unsigned long width,
	unsigned long height
);
Result ViewTransformWorldToScreen(IDirect3DRMViewport*, const float world[3], float screen[4]);
Result ViewTransformScreenToWorld(IDirect3DRMViewport*, const float screen[4], float world[3]);
void ViewDestroy(IDirect3DRMViewport*);
Result CameraSetTransformation(IDirect3DRMFrame2*, FloatMatrix4&);
void CameraDestroy(IDirect3DRMFrame2*);
Result LightSetTransformation(IDirect3DRMFrame2*, FloatMatrix4&);
Result LightSetColor(IDirect3DRMFrame2*, float r, float g, float b);
void LightDestroy(IDirect3DRMFrame2*);
Result GroupSetTransformation(IDirect3DRMFrame2*, FloatMatrix4&);
Result GroupSetColor(IDirect3DRMFrame2*, float r, float g, float b, float a);
Result GroupSetTexture(IDirect3DRMFrame2*, IDirect3DRMTexture*);
Result GroupGetTexture(IDirect3DRMFrame2*, IDirect3DRMTexture**);
Result GroupSetMaterialMode(IDirect3DRMFrame2*, MaterialMode);
Result GroupAddGroup(IDirect3DRMFrame2*, const IDirect3DRMFrame*);
Result GroupAddMeshBuilder(IDirect3DRMFrame2*, const IDirect3DRMMesh*);
Result GroupRemoveGroup(IDirect3DRMFrame2*, const IDirect3DRMFrame*);
Result GroupRemoveMeshBuilder(IDirect3DRMFrame2*, const IDirect3DRMMesh*);
Result GroupRemoveAll(IDirect3DRMFrame2*);
Result GroupBounds(IDirect3DRMFrame2*, D3DVECTOR* p_min, D3DVECTOR* p_max);
void GroupDestroy(IDirect3DRMFrame2*);
Result MeshBuilderGetBoundingBox(IDirect3DRMMesh*, float min[3], float max[3]);
void MeshBuilderDestroy(IDirect3DRMMesh*);
Result TextureSetTexels(
	IDirect3DRMTexture*,
	int width,
	int height,
	int bitsPerTexel,
	void* pTexels,
	int pTexelsArePersistent
);
Result TextureFillRowsOfTexture(IDirect3DRMTexture*, int y, int height, void* pBuffer);
Result TextureChanged(IDirect3DRMTexture*, int texelsChanged, int paletteChanged);
Result TextureGetBufferAndPalette(
	IDirect3DRMTexture*,
	int* width,
	int* height,
	int* depth,
	void** pBuffer,
	int* paletteSize,
	unsigned char (*pEntries)[3]
);
Result TextureSetPalette(IDirect3DRMTexture*, int entryCount, PaletteEntry* pEntries);
void TextureDestroy(IDirect3DRMTexture*);

} /* namespace TglImpl */

// Global scope like the viewport destroy callback, matching the 1997 manglings.
Tgl::Result ViewportPickImpl(
	IDirect3DRMViewport*,
	int x,
	int y,
	const TglImpl::GroupImpl** ppGroupsToPickFrom,
	int groupsToPickFromCount,
	const Tgl::Group**& rppPickedGroups,
	int& rPickedGroupCount
);

namespace TglImpl
{

// VTABLE: LEGO1 0x100db910
// VTABLE: BETA10 0x101c30d8
class RendererImpl : public Renderer {
public:
	// FUNCTION: BETA10 0x10169a20
	RendererImpl() : m_data(0) {}

	// FUNCTION: BETA10 0x10169d20
	~RendererImpl() override { Destroy(); }

	void* ImplementationDataPtr() override;

	// vtable+0x08
	Device* CreateDevice(const DeviceDirectDrawCreateData&) override;
	Device* CreateDevice(const DeviceDirect3DCreateData&) override;

	// vtable+0x10
	View* CreateView(
		const Device*,
		const Camera*,
		unsigned long x,
		unsigned long y,
		unsigned long width,
		unsigned long height
	) override;
	Camera* CreateCamera() override;
	Light* CreateLight(LightType, float r, float g, float b) override;
	Group* CreateGroup(const Group* pParent) override;

	// vtable+0x20
	MeshBuilder* CreateMeshBuilder() override;
	Texture* CreateTexture(
		int width,
		int height,
		int bitsPerTexel,
		const void* pTexels,
		int pTexelsArePersistent,
		int paletteEntryCount,
		const PaletteEntry* pEntries
	) override;
	Texture* CreateTexture() override;

	Result SetTextureDefaultShadeCount(unsigned long) override;

	// vtable+0x30
	Result SetTextureDefaultColorCount(unsigned long) override;

	HRESULT CreateTextureFromSurface(LPDIRECTDRAWSURFACE pSurface, LPDIRECT3DRMTEXTURE2* pTexture2)
	{
		return m_data->CreateTextureFromSurface(pSurface, pTexture2);
	}

	typedef IDirect3DRM2* RendererDataType;

	const RendererDataType& ImplementationData() const { return m_data; }

	// FUNCTION: BETA10 0x10174c10
	RendererDataType& ImplementationData() { return m_data; }

public:
	inline Result Create();
	inline void Destroy();
	inline Result CreateLight(LightType type, float r, float g, float b, LightImpl& rLight);
	inline Result CreateGroup(const GroupImpl* pParentGroup, GroupImpl& rpGroup);
	inline Result CreateView(
		const DeviceImpl& rDevice,
		const CameraImpl& rCamera,
		unsigned long x,
		unsigned long y,
		unsigned long width,
		unsigned long height,
		ViewImpl& rView
	);
	inline Result CreateMeshBuilder(MeshBuilderImpl& rMesh);
	inline Result CreateCamera(CameraImpl& rCamera);
	inline Result CreateTexture(TextureImpl& rTexture);
	inline Result CreateTexture(
		TextureImpl& rTexture,
		int width,
		int height,
		int bitsPerTexel,
		const void* pTexels,
		int texelsArePersistent,
		int paletteEntryCount,
		const PaletteEntry* pEntries
	);
	inline Result CreateDevice(const DeviceDirect3DCreateData& rCreateData, DeviceImpl& rDevice);
	inline Result CreateDevice(const DeviceDirectDrawCreateData& rCreateData, DeviceImpl& rDevice);

private:
	RendererDataType m_data;
};

// The 1997 name of this global is preserved in the BETA10 assert at
// tglRL40.h L313: (g_pTheRenderer->AddRef(), g_pTheRenderer->Release()) == 1
extern IDirect3DRM2* g_pTheRenderer;

// VTABLE: LEGO1 0x100db988
// VTABLE: BETA10 0x101c31f0
class DeviceImpl : public Device {
public:
	// FUNCTION: BETA10 0x1016b2e0
	DeviceImpl() : m_data(0) {}

	// FUNCTION: BETA10 0x1016dd80
	~DeviceImpl() override { Destroy(); }

	void* ImplementationDataPtr() override;

	// vtable+0x08
	unsigned long GetWidth() override;
	unsigned long GetHeight() override;

	// vtable+0x10
	Result SetColorModel(ColorModel) override;
	Result SetShadingModel(ShadingModel) override;
	Result SetShadeCount(unsigned long) override;
	Result SetDither(int) override;

	// vtable+0x20
	Result Update() override;
	void HandleActivate(WORD) override;
	void HandlePaint(void*) override;

	// FUNCTION: BETA10 0x1016e490
	// Not in retail: nothing calls it, so /Gy dropped it. BETA10 places it at
	// tglImpl.h L643 with its assert(m_data) at L646, directly after Update
	// (L636). Non-virtual -- a virtual would have been kept alive by the vtable.
	unsigned long GetTrianglesDrawn();

	typedef IDirect3DRMDevice2* DeviceDataType;

	// FUNCTION: BETA10 0x101708e0
	const DeviceDataType& ImplementationData() const { return m_data; }

	// FUNCTION: BETA10 0x100d9540
	DeviceDataType& ImplementationData() { return m_data; }

	void SetImplementationData(IDirect3DRMDevice2* device) { m_data = device; }

	inline void Destroy();

	friend class RendererImpl;

private:
	DeviceDataType m_data;
};

// VTABLE: LEGO1 0x100db9e8
// VTABLE: BETA10 0x101c3220
class ViewImpl : public View {
public:
	// FUNCTION: BETA10 0x1016b360
	ViewImpl() : m_data(0) {}

	// FUNCTION: BETA10 0x1016e5d0
	~ViewImpl() override { Destroy(); }

	void* ImplementationDataPtr() override;

	// vtable+0x08
	Result Add(const Light*) override;
	Result Remove(const Light*) override;

	// vtable+0x10
	Result SetCamera(const Camera*) override;
	Result SetProjection(ProjectionType) override;
	Result SetFrustrum(float frontClippingDistance, float backClippingDistance, float degrees) override;
	Result SetBackgroundColor(float r, float g, float b) override;

	// vtable+0x20
	Result GetBackgroundColor(float* r, float* g, float* b) override;
	Result Clear() override;
	Result Render(const Group*) override;
	Result ForceUpdate(unsigned long x, unsigned long y, unsigned long width, unsigned long height) override;

	// vtable+0x30
	Result TransformWorldToScreen(const float world[3], float screen[4]) override;
	Result TransformScreenToWorld(const float screen[4], float world[3]) override;
	Result Pick(
		unsigned long x,
		unsigned long y,
		const Group** ppGroupsToPickFrom,
		int groupsToPickFromCount,
		const Group**& rppPickedGroups,
		int& rPickedGroupCount
	) override;

	typedef IDirect3DRMViewport* ViewDataType;

	const ViewDataType& ImplementationData() const { return m_data; }

	// FUNCTION: BETA10 0x101711c0
	ViewDataType& ImplementationData() { return m_data; }

	void SetImplementationData(IDirect3DRMViewport* viewport) { m_data = viewport; }

	static Result ViewportCreateAppData(IDirect3DRM2*, IDirect3DRMViewport*, IDirect3DRMFrame2*);

	inline void Destroy();
	Result Add(const LightImpl& rLight);
	Result Remove(const LightImpl& rLight);
	Result SetCamera(const CameraImpl& rCamera);
	Result Render(const GroupImpl& rScene);
	Result Pick(
		unsigned long x,
		unsigned long y,
		const GroupImpl** ppGroupsToPickFrom,
		int groupsToPickFromCount,
		const Group**& rppPickedGroups,
		int& rPickedGroupCount
	);

	friend class RendererImpl;

private:
	ViewDataType m_data;
};

// VTABLE: LEGO1 0x100dbad8
// VTABLE: BETA10 0x101c3260
class CameraImpl : public Camera {
public:
	// FUNCTION: BETA10 0x1016b3e0
	CameraImpl() : m_data(0) {}

	// FUNCTION: BETA10 0x1016f200
	~CameraImpl() override { Destroy(); }

	void* ImplementationDataPtr() override;

	// vtable+0x08
	Result SetTransformation(FloatMatrix4&) override;

	typedef IDirect3DRMFrame2* CameraDataType;

	// FUNCTION: BETA10 0x10170960
	const CameraDataType& ImplementationData() const { return m_data; }

	// FUNCTION: BETA10 0x10170980
	CameraDataType& ImplementationData() { return m_data; }

	inline void Destroy();

	friend class RendererImpl;

private:
	CameraDataType m_data;
};

// VTABLE: LEGO1 0x100dbaf8
// VTABLE: BETA10 0x101c3270
class LightImpl : public Light {
public:
	// FUNCTION: BETA10 0x1016b460
	LightImpl() : m_data(0) {}

	// FUNCTION: BETA10 0x1016f5c0
	~LightImpl() override { Destroy(); }

	void* ImplementationDataPtr() override;

	// vtable+0x08
	Result SetTransformation(FloatMatrix4&) override;
	Result SetColor(float r, float g, float b) override;

	typedef IDirect3DRMFrame2* LightDataType;

	// FUNCTION: BETA10 0x10171b90
	const LightDataType& ImplementationData() const { return m_data; }

	// FUNCTION: BETA10 0x10171240
	LightDataType& ImplementationData() { return m_data; }

	inline void Destroy();

	friend class RendererImpl;

private:
	LightDataType m_data;
};

// VTABLE: LEGO1 0x100dba68
// VTABLE: BETA10 0x101c3150
class GroupImpl : public Group {
public:
	// FUNCTION: BETA10 0x1016a240
	GroupImpl() : m_data(0) {}

	// FUNCTION: BETA10 0x1016a410
	~GroupImpl() override { Destroy(); }

	void* ImplementationDataPtr() override;

	// vtable+0x08
	Result SetTransformation(FloatMatrix4&) override;
	Result SetColor(float r, float g, float b, float a) override;

	// vtable+0x10
	Result SetTexture(const Texture*) override;
	Result GetTexture(Texture*&) override;
	Result SetMaterialMode(MaterialMode) override;
	Result Add(const Group*) override;

	// vtable+0x20
	Result Add(const MeshBuilder*) override;
	Result Remove(const Group*) override;
	Result Remove(const MeshBuilder*) override;
	Result RemoveAll() override;

	// vtable+0x30
	Result Bounds(D3DVECTOR* p_min, D3DVECTOR* p_max) override;

	typedef IDirect3DRMFrame2* GroupDataType;

	// FUNCTION: BETA10 0x1016fc20
	const GroupDataType& ImplementationData() const { return m_data; }

	// FUNCTION: BETA10 0x1016fce0
	GroupDataType& ImplementationData() { return m_data; }

	inline void Destroy();
	inline Result SetTexture(const TextureImpl* pTexture);
	inline Result GetTexture(TextureImpl** ppTexture);
	inline Result Add(const GroupImpl& rGroup);
	inline Result Add(const MeshBuilderImpl& rMesh);
	inline Result Remove(const GroupImpl& rGroup);
	inline Result Remove(const MeshBuilderImpl& rMesh);

	friend class RendererImpl;

private:
	GroupDataType m_data;
};

// VTABLE: LEGO1 0x100dbb18
// VTABLE: BETA10 0x101c31e0
class MeshBuilderImpl : public MeshBuilder {
public:
	// FUNCTION: BETA10 0x1016b260
	MeshBuilderImpl() : m_data(0) {}

	// FUNCTION: BETA10 0x1016c7e0
	~MeshBuilderImpl() override { Destroy(); }

	void* ImplementationDataPtr() override;

	// vtable+0x08
	Mesh* CreateMesh(
		unsigned long faceCount,
		unsigned long vertexCount,
		float (*pPositions)[3],
		float (*pNormals)[3],
		float (*pTextureCoordinates)[2],
		unsigned long (*pFaceIndices)[3],
		unsigned long (*pTextureIndices)[3],
		ShadingModel shadingModel
	) override;
	Result GetBoundingBox(float min[3], float max[3]) const override;

	// vtable+0x10
	MeshBuilder* Clone() override;

	typedef IDirect3DRMMesh* MeshBuilderDataType;

	// FUNCTION: BETA10 0x10170420
	const MeshBuilderDataType& ImplementationData() const { return m_data; }

	// FUNCTION: BETA10 0x10170440
	MeshBuilderDataType& ImplementationData() { return m_data; }

	inline void Destroy();

	friend class RendererImpl;

private:
	inline Result CreateMeshImpl(
		MeshImpl& p_elem,
		unsigned long faceCount,
		unsigned long vertexCount,
		float (*pPositions)[3],
		float (*pNormals)[3],
		float (*pTextureCoordinates)[2],
		unsigned long (*pFaceIndices)[3],
		unsigned long (*pTextureIndices)[3],
		ShadingModel shadingModel
	);

	MeshBuilderDataType m_data;
};

// VTABLE: LEGO1 0x100dbb88
// VTABLE: BETA10 0x101c3340
class MeshImpl : public Mesh {
public:
	// FUNCTION: BETA10 0x1016f970
	MeshImpl() : m_data(0) {}

	// FUNCTION: BETA10 0x10170460
	~MeshImpl() override { Destroy(); }

	void* ImplementationDataPtr() override;

	// vtable+0x08
	Result SetColor(float r, float g, float b, float a) override;
	Result SetTexture(const Texture*) override;

	// vtable+0x10
	Result GetTexture(Texture*&) override;
	Result SetTextureMappingMode(TextureMappingMode) override;
	Result SetShadingModel(ShadingModel) override;
	Mesh* DeepClone(MeshBuilder*) override;

	// vtable+0x20
	Mesh* ShallowClone(MeshBuilder*) override;

	struct MeshData {
		IDirect3DRMMesh* groupMesh;
		D3DRMGROUPINDEX groupIndex;
	};

	typedef MeshData* MeshDataType;

	const MeshDataType& ImplementationData() const { return m_data; }

	// FUNCTION: BETA10 0x10171b70
	MeshDataType& ImplementationData() { return m_data; }

	inline void Destroy();
	inline Mesh* DeepClone(const MeshBuilderImpl& rMesh);
	inline Result GetTexture(TextureImpl** ppTexture);
	inline Result SetTexture(const TextureImpl* pTexture);
	inline Mesh* ShallowClone(const MeshBuilderImpl& rMesh);

	friend class RendererImpl;

private:
	MeshDataType m_data;
};

// These helpers take MeshImpl::MeshData, so their prototypes can only
// follow the MeshImpl declaration. Bodies in tglrl40.h.
Result CreateMesh(
	IDirect3DRMMesh*,
	unsigned long p_numFaces,
	unsigned long p_numVertices,
	float(*p_positions),
	float(*p_normals),
	float(*p_textureCoordinates),
	unsigned long (*p_faceIndices)[3],
	unsigned long (*p_textureIndices)[3],
	ShadingModel shadingModel,
	MeshImpl::MeshDataType& rpMesh
);
Result MeshSetColor(MeshImpl::MeshData*, float r, float g, float b, float a);
Result MeshSetTexture(MeshImpl::MeshData*, IDirect3DRMTexture*);
Result MeshSetTextureMappingMode(MeshImpl::MeshData*, TextureMappingMode);
Result MeshSetShadingModel(MeshImpl::MeshData*, ShadingModel);
Result MeshDeepClone(MeshImpl::MeshData*, MeshImpl::MeshData*&, IDirect3DRMMesh*);
Result MeshShallowClone(MeshImpl::MeshData*, MeshImpl::MeshData*&, IDirect3DRMMesh*);
Result MeshGetTexture(MeshImpl::MeshData*, IDirect3DRMTexture**);
void MeshDestroy(MeshImpl::MeshDataType);

// No vtable, this is just a simple wrapper around D3DRMIMAGE
class TglD3DRMIMAGE {
public:
	TglD3DRMIMAGE(
		int width,
		int height,
		int depth,
		void* pBuffer,
		int useBuffer,
		int paletteSize,
		PaletteEntry* pEntries
	);
	~TglD3DRMIMAGE();

	Result CreateBuffer(int width, int height, int depth, void* pBuffer, int useBuffer);
	void Destroy();
	Result FillRowsOfTexture(int y, int height, char* content);
	Result InitializePalette(int paletteSize, PaletteEntry* pEntries);

	D3DRMIMAGE m_image;
	int m_texelsAllocatedByClient;

	// SYNTHETIC: BETA10 0x1016abb0
	// TglImpl::TglD3DRMIMAGE::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dbb48
// VTABLE: BETA10 0x101c31c0
class TextureImpl : public Texture {
public:
	// FUNCTION: BETA10 0x1016b1e0
	TextureImpl() : m_data(0) {}

	// FUNCTION: BETA10 0x1016c2d0
	~TextureImpl() override { Destroy(); }

	void* ImplementationDataPtr() override;

	// vtable+0x08
	Result SetTexels(int width, int height, int bitsPerTexel, void* pTexels, int pTexelsArePersistent) override;
	void FillRowsOfTexture(int y, int height, void* pBuffer) override;

	// vtable+0x10
	Result Changed(int texelsChanged, int paletteChanged) override;
	Result GetBufferAndPalette(
		int* pWidth,
		int* pHeight,
		int* pDepth,
		void** ppBuffer,
		int* ppPaletteSize,
		unsigned char (*pEntries)[3]
	) override;
	Result SetPalette(int entryCount, PaletteEntry* entries) override;

	typedef IDirect3DRMTexture* TextureDataType;

	// FUNCTION: BETA10 0x1016fd60
	const TextureDataType& ImplementationData() const { return m_data; }

	// FUNCTION: BETA10 0x1016fe20
	TextureDataType& ImplementationData() { return m_data; }

	void SetImplementation(IDirect3DRMTexture* pData) { m_data = pData; }

	inline void Destroy();

	friend class RendererImpl;

	static Result SetImage(IDirect3DRMTexture* pSelf, TglD3DRMIMAGE* pImage);

private:
	TextureDataType m_data;
};

// The inline method bodies below follow the 1997 tglImpl.h layout: BETA10
// records every assert with its tglImpl.h line number, which fixes both the
// order of the definitions and the file they lived in. Impl-level overloads
// come first within each interface family, then the public (vtable) methods.

// FUNCTION: BETA10 0x1016cf40
inline Result RendererImpl::CreateDevice(const DeviceDirectDrawCreateData& rCreateData, DeviceImpl& rDevice)
{
	assert(m_data);
	assert(!rDevice.ImplementationData());

	return RendererCreateDevice(m_data, rCreateData, rDevice.ImplementationData());
}

// FUNCTION: BETA10 0x1016ce60
inline Result RendererImpl::CreateDevice(const DeviceDirect3DCreateData& rCreateData, DeviceImpl& rDevice)
{
	assert(m_data);
	assert(!rDevice.ImplementationData());

	return RendererCreateDevice(m_data, rCreateData, rDevice.ImplementationData());
}

// FUNCTION: BETA10 0x1016d0b0
inline Result RendererImpl::CreateView(
	const DeviceImpl& rDevice,
	const CameraImpl& rCamera,
	unsigned long x,
	unsigned long y,
	unsigned long width,
	unsigned long height,
	ViewImpl& rView
)
{
	assert(m_data);
	assert(rDevice.ImplementationData());
	assert(rCamera.ImplementationData());
	assert(!rView.ImplementationData());

	return RendererCreateView(
		m_data,
		rDevice.ImplementationData(),
		rCamera.ImplementationData(),
		x,
		y,
		width,
		height,
		rView.ImplementationData()
	);
}

// FUNCTION: BETA10 0x1016d280
inline Result RendererImpl::CreateGroup(const GroupImpl* pParentGroup, GroupImpl& rGroup)
{
	assert(m_data);
	assert(!pParentGroup || pParentGroup->ImplementationData());
	assert(!rGroup.ImplementationData());

	return RendererCreateGroup(
		m_data,
		pParentGroup ? pParentGroup->ImplementationData() : NULL,
		rGroup.ImplementationData()
	);
}

// FUNCTION: BETA10 0x1016d420
inline Result RendererImpl::CreateCamera(CameraImpl& rCamera)
{
	assert(m_data);
	assert(!rCamera.ImplementationData());

	return RendererCreateCamera(m_data, rCamera.ImplementationData());
}

// FUNCTION: BETA10 0x1016d4e0
inline Result RendererImpl::CreateLight(LightType type, float r, float g, float b, LightImpl& rLight)
{
	assert(m_data);
	assert(!rLight.ImplementationData());

	return RendererCreateLight(m_data, type, r, g, b, rLight.ImplementationData());
}

// FUNCTION: BETA10 0x1016dc20
inline Result RendererImpl::CreateTexture(TextureImpl& rTexture)
{
	assert(m_data);
	assert(!rTexture.ImplementationData());

	return RendererCreateTexture(m_data, rTexture.ImplementationData());
}

// FUNCTION: BETA10 0x1016d910
inline Result RendererImpl::CreateTexture(
	TextureImpl& rTexture,
	int width,
	int height,
	int bitsPerTexel,
	const void* pTexels,
	int texelsArePersistent,
	int paletteEntryCount,
	const PaletteEntry* pEntries
)
{
	assert(m_data);
	assert(!rTexture.ImplementationData());

	return RendererCreateTexture(
		m_data,
		width,
		height,
		bitsPerTexel,
		const_cast<void*>(pTexels),
		texelsArePersistent,
		paletteEntryCount,
		const_cast<PaletteEntry*>(pEntries),
		rTexture.ImplementationData()
	);
}

// FUNCTION: LEGO1 0x100a1900
// FUNCTION: BETA10 0x10169ea0
inline Device* RendererImpl::CreateDevice(const DeviceDirectDrawCreateData& data)
{
	assert(m_data);
	DeviceImpl* device = new DeviceImpl();

	if (!CreateDevice(data, *device)) {
		delete device;
		device = NULL;
	}

	return device;
}

// FUNCTION: LEGO1 0x100a1830
// FUNCTION: BETA10 0x10169d90
inline Device* RendererImpl::CreateDevice(const DeviceDirect3DCreateData& data)
{
	assert(m_data);
	DeviceImpl* device = new DeviceImpl();

	if (!CreateDevice(data, *device)) {
		delete device;
		device = NULL;
	}

	return device;
}

// FUNCTION: LEGO1 0x100a1a00
// FUNCTION: BETA10 0x10169fb0
inline View* RendererImpl::CreateView(
	const Device* pDevice,
	const Camera* pCamera,
	unsigned long x,
	unsigned long y,
	unsigned long width,
	unsigned long height
)
{
	assert(m_data);
	assert(pDevice);
	assert(pCamera);

	ViewImpl* view = new ViewImpl();
	if (!CreateView(
			*static_cast<const DeviceImpl*>(pDevice),
			*static_cast<const CameraImpl*>(pCamera),
			x,
			y,
			width,
			height,
			*view
		)) {
		delete view;
		view = NULL;
	}

	return view;
}

// FUNCTION: LEGO1 0x100a1c30
// FUNCTION: BETA10 0x1016a980
inline Camera* RendererImpl::CreateCamera()
{
	assert(m_data);
	CameraImpl* camera = new CameraImpl();

	if (!CreateCamera(*camera)) {
		delete camera;
		camera = NULL;
	}

	return camera;
}

// FUNCTION: LEGO1 0x100a1cf0
// FUNCTION: BETA10 0x1016aa90
inline Light* RendererImpl::CreateLight(LightType type, float r, float g, float b)
{
	assert(m_data);

	LightImpl* pLightImpl = new LightImpl;

	if (!CreateLight(type, r, g, b, *pLightImpl)) {
		delete pLightImpl;
		pLightImpl = 0;
	}

	return pLightImpl;
}

// FUNCTION: LEGO1 0x100a1e90
// FUNCTION: BETA10 0x1016abf0
inline MeshBuilder* RendererImpl::CreateMeshBuilder()
{
	assert(m_data);
	MeshBuilderImpl* meshBuilder = new MeshBuilderImpl();

	if (!CreateMeshBuilder(*static_cast<MeshBuilderImpl*>(meshBuilder))) {
		delete meshBuilder;
		meshBuilder = NULL;
	}

	return meshBuilder;
}

// FUNCTION: BETA10 0x1016d850
inline Result RendererImpl::CreateMeshBuilder(MeshBuilderImpl& rMesh)
{
	assert(m_data);
	assert(!rMesh.ImplementationData());

	return RendererCreateMeshBuilder(m_data, rMesh.ImplementationData());
}

// FUNCTION: LEGO1 0x100a1b20
// FUNCTION: BETA10 0x1016a130
inline Group* RendererImpl::CreateGroup(const Group* pParent)
{
	assert(m_data);

	GroupImpl* group = new GroupImpl();
	if (!CreateGroup(static_cast<const GroupImpl*>(pParent), *group)) {
		delete group;
		group = NULL;
	}
	return group;
}

// FUNCTION: LEGO1 0x100a20d0
// FUNCTION: BETA10 0x1016ae20
inline Texture* RendererImpl::CreateTexture()
{
	assert(m_data);

	TextureImpl* texture = new TextureImpl();
	if (!CreateTexture(*texture)) {
		delete texture;
		texture = NULL;
	}

	return texture;
}

// FUNCTION: LEGO1 0x100a1f50
// FUNCTION: BETA10 0x1016ad00
inline Texture* RendererImpl::CreateTexture(
	int width,
	int height,
	int bitsPerTexel,
	const void* pTexels,
	int texelsArePersistent,
	int paletteEntryCount,
	const PaletteEntry* pEntries
)
{
	assert(m_data);

	TextureImpl* texture = new TextureImpl();
	if (!CreateTexture(
			*texture,
			width,
			height,
			bitsPerTexel,
			const_cast<void*>(pTexels),
			texelsArePersistent,
			paletteEntryCount,
			const_cast<PaletteEntry*>(pEntries)
		)) {
		delete texture;
		texture = NULL;
	}
	return texture;
}

// FUNCTION: LEGO1 0x100a2270
// FUNCTION: BETA10 0x1016af30
inline Result RendererImpl::SetTextureDefaultShadeCount(unsigned long shadeCount)
{
	assert(m_data);

	return RendererSetTextureDefaultShadeCount(m_data, shadeCount);
}

// FUNCTION: LEGO1 0x100a2290
// FUNCTION: BETA10 0x1016afc0
inline Result RendererImpl::SetTextureDefaultColorCount(unsigned long colorCount)
{
	assert(m_data);

	return RendererSetTextureDefaultColorCount(m_data, colorCount);
}

// FUNCTION: LEGO1 0x100a22b0
// FUNCTION: BETA10 0x1016b050
inline void* RendererImpl::ImplementationDataPtr()
{
	assert(m_data);

	return reinterpret_cast<void*>(&m_data);
}

// FUNCTION: LEGO1 0x100a2c20
// FUNCTION: BETA10 0x1016df40
inline Result DeviceImpl::SetColorModel(ColorModel p_model)
{
	assert(m_data);

	return DeviceSetColorModel(m_data, p_model);
}

// FUNCTION: LEGO1 0x100a2c30
// FUNCTION: BETA10 0x1016dfc0
inline Result DeviceImpl::SetShadingModel(ShadingModel model)
{
	assert(m_data);

	return DeviceSetShadingModel(m_data, model);
}

// FUNCTION: LEGO1 0x100a2ca0
// FUNCTION: BETA10 0x1016e0e0
inline Result DeviceImpl::SetShadeCount(unsigned long shadeCount)
{
	assert(m_data);

	return DeviceSetShadeCount(m_data, shadeCount);
}

// FUNCTION: LEGO1 0x100a2cc0
// FUNCTION: BETA10 0x1016e170
inline Result DeviceImpl::SetDither(int dither)
{
	assert(m_data);

	return DeviceSetDither(m_data, dither);
}

// FUNCTION: LEGO1 0x100a2c00
// FUNCTION: BETA10 0x1016de40
inline unsigned long DeviceImpl::GetWidth()
{
	assert(m_data);

	return DeviceGetWidth(m_data);
}

// FUNCTION: LEGO1 0x100a2c10
// FUNCTION: BETA10 0x1016dec0
inline unsigned long DeviceImpl::GetHeight()
{
	assert(m_data);

	return DeviceGetHeight(m_data);
}

// FUNCTION: LEGO1 0x100a2ce0
// FUNCTION: BETA10 0x1016e200
inline void DeviceImpl::HandleActivate(WORD wParam)
{
	assert(m_data);

	DeviceHandleActivate(m_data, wParam);
}

// FUNCTION: LEGO1 0x100a2d20
// FUNCTION: BETA10 0x1016e300
inline void DeviceImpl::HandlePaint(void* p_data)
{
	assert(m_data);

	DeviceHandlePaint(m_data, p_data);
}

// FUNCTION: LEGO1 0x100a2d60
// FUNCTION: BETA10 0x1016e400
inline Result DeviceImpl::Update()
{
	assert(m_data);

	return DeviceUpdate(m_data);
}

// FUNCTION: BETA10 0x1016e490
inline unsigned long DeviceImpl::GetTrianglesDrawn()
{
	assert(m_data);

	return DeviceGetTrianglesDrawn(m_data);
}

// FUNCTION: LEGO1 0x100a2bf0
// FUNCTION: BETA10 0x1016ddf0
inline void* DeviceImpl::ImplementationDataPtr()
{
	assert(m_data);

	return reinterpret_cast<void*>(&m_data);
}

// FUNCTION: BETA10 0x101709a0
inline Result ViewImpl::Add(const LightImpl& rLight)
{
	assert(m_data);
	assert(rLight.ImplementationData());

	return ViewAddLight(m_data, rLight.ImplementationData());
}

// FUNCTION: BETA10 0x10170b10
inline Result ViewImpl::Remove(const LightImpl& rLight)
{
	assert(m_data);
	assert(rLight.ImplementationData());

	return ViewRemoveLight(m_data, rLight.ImplementationData());
}

// FUNCTION: BETA10 0x10170c20
inline Result ViewImpl::SetCamera(const CameraImpl& rCamera)
{
	assert(m_data);
	assert(rCamera.ImplementationData());

	return ViewSetCamera(m_data, rCamera.ImplementationData());
}

// FUNCTION: BETA10 0x10170d90
inline Result ViewImpl::Render(const GroupImpl& rScene)
{
	assert(m_data);
	assert(rScene.ImplementationData());

	return ViewRender(m_data, rScene.ImplementationData());
}

// FUNCTION: BETA10 0x101710f0
inline Result ViewImpl::Pick(
	unsigned long x,
	unsigned long y,
	const GroupImpl** ppGroupsToPickFrom,
	int groupsToPickFromCount,
	const Group**& rppPickedGroups,
	int& rPickedGroupCount
)
{
	assert(m_data);

	return ViewportPickImpl(
		m_data,
		x,
		y,
		ppGroupsToPickFrom,
		groupsToPickFromCount,
		rppPickedGroups,
		rPickedGroupCount
	);
}

// FUNCTION: LEGO1 0x100a2e70
// FUNCTION: BETA10 0x1016e810
inline Result ViewImpl::SetProjection(ProjectionType type)
{
	assert(m_data);

	return ViewSetProjection(m_data, type);
}

// FUNCTION: LEGO1 0x100a2eb0
// FUNCTION: BETA10 0x1016e8b0
inline Result ViewImpl::SetFrustrum(float frontClippingDistance, float backClippingDistance, float degrees)
{
	assert(m_data);

	return ViewSetFrustrum(m_data, frontClippingDistance, backClippingDistance, degrees);
}

// FUNCTION: LEGO1 0x100a2f30
// FUNCTION: BETA10 0x1016ea00
inline Result ViewImpl::SetBackgroundColor(float r, float g, float b)
{
	assert(m_data);

	return ViewSetBackgroundColor(m_data, r, g, b);
}

// FUNCTION: LEGO1 0x100a2f80
// FUNCTION: BETA10 0x1016eb60
inline Result ViewImpl::GetBackgroundColor(float* r, float* g, float* b)
{
	assert(m_data);

	return ViewGetBackgroundColor(m_data, r, g, b);
}

// FUNCTION: LEGO1 0x100a2fb0
// FUNCTION: BETA10 0x1016ec50
inline Result ViewImpl::Clear()
{
	assert(m_data);

	return ViewClear(m_data);
}

// FUNCTION: LEGO1 0x100a2d90
// FUNCTION: BETA10 0x1016e690
inline Result ViewImpl::Add(const Light* pLight)
{
	assert(m_data);
	assert(pLight);

	return Add(*static_cast<const LightImpl*>(pLight));
}

// FUNCTION: LEGO1 0x100a2dc0
// FUNCTION: BETA10 0x1016e710
inline Result ViewImpl::Remove(const Light* pLight)
{
	assert(m_data);
	assert(pLight);

	return Remove(*static_cast<const LightImpl*>(pLight));
}

// FUNCTION: LEGO1 0x100a2df0
// FUNCTION: BETA10 0x1016e790
inline Result ViewImpl::SetCamera(const Camera* pCamera)
{
	assert(m_data);
	assert(pCamera);

	return SetCamera(*static_cast<const CameraImpl*>(pCamera));
}

// FUNCTION: LEGO1 0x100a2fd0
// FUNCTION: BETA10 0x1016ece0
inline Result ViewImpl::Render(const Group* pGroup)
{
	assert(m_data);
	assert(pGroup);

	return Render(*static_cast<const GroupImpl*>(pGroup));
}

// FUNCTION: LEGO1 0x100a3080
// FUNCTION: BETA10 0x1016ed60
inline Result ViewImpl::ForceUpdate(unsigned long x, unsigned long y, unsigned long width, unsigned long height)
{
	assert(m_data);

	return ViewForceUpdate(m_data, x, y, width, height);
}

// FUNCTION: LEGO1 0x100a30c0
// FUNCTION: BETA10 0x1016ee10
inline Result ViewImpl::Pick(
	unsigned long x,
	unsigned long y,
	const Group** ppGroupsToPickFrom,
	int groupsToPickFromCount,
	const Group**& rppPickedGroups,
	int& rPickedGroupCount
)
{
	assert(m_data);

	return Pick(
		x,
		y,
		reinterpret_cast<const GroupImpl**>(ppGroupsToPickFrom),
		groupsToPickFromCount,
		rppPickedGroups,
		rPickedGroupCount
	);
}

// FUNCTION: LEGO1 0x100a30f0
// FUNCTION: BETA10 0x1016ef90
inline Result ViewImpl::TransformWorldToScreen(const float world[3], float screen[4])
{
	assert(m_data);

	return ViewTransformWorldToScreen(m_data, world, screen);
}

// FUNCTION: LEGO1 0x100a3160
// FUNCTION: BETA10 0x1016f070
inline Result ViewImpl::TransformScreenToWorld(const float screen[4], float world[3])
{
	assert(m_data);

	return ViewTransformScreenToWorld(m_data, screen, world);
}

// FUNCTION: LEGO1 0x100a2d80
// FUNCTION: BETA10 0x1016e640
inline void* ViewImpl::ImplementationDataPtr()
{
	assert(m_data);

	return reinterpret_cast<void*>(&m_data);
}

// FUNCTION: LEGO1 0x100a3700
// FUNCTION: BETA10 0x1016f330
inline Result CameraImpl::SetTransformation(FloatMatrix4& matrix)
{
	assert(m_data);

	return CameraSetTransformation(m_data, matrix);
}

// FUNCTION: LEGO1 0x100a36f0
// FUNCTION: BETA10 0x1016f2e0
inline void* CameraImpl::ImplementationDataPtr()
{
	assert(m_data);

	return reinterpret_cast<void*>(&m_data);
}

// FUNCTION: LEGO1 0x100a3780
// FUNCTION: BETA10 0x1016f680
inline Result LightImpl::SetTransformation(FloatMatrix4& matrix)
{
	assert(m_data);

	return LightSetTransformation(m_data, matrix);
}

// FUNCTION: LEGO1 0x100a37e0
// FUNCTION: BETA10 0x1016f7f0
inline Result LightImpl::SetColor(float r, float g, float b)
{
	assert(m_data);

	return LightSetColor(m_data, r, g, b);
}

// FUNCTION: LEGO1 0x100a3770
// FUNCTION: BETA10 0x1016f630
inline void* LightImpl::ImplementationDataPtr()
{
	assert(m_data);

	return reinterpret_cast<void*>(&m_data);
}

// FUNCTION: BETA10 0x1016bcc0
inline Result GroupImpl::SetTexture(const TextureImpl* pTexture)
{
	assert(m_data);
	assert(!pTexture || pTexture->ImplementationData());

	IDirect3DRMTexture* pD3DTexture = pTexture ? pTexture->ImplementationData() : NULL;
	return GroupSetTexture(m_data, pD3DTexture);
}

// FUNCTION: BETA10 0x1016beb0
inline Result GroupImpl::GetTexture(TextureImpl** ppTexture)
{
	assert(m_data);
	assert(ppTexture);

	TextureImpl* pTextureImpl = new TextureImpl();
	assert(pTextureImpl);

	Result result = GroupGetTexture(m_data, &pTextureImpl->ImplementationData());

	*ppTexture = pTextureImpl;
	return result;
}

// FUNCTION: BETA10 0x1016c090
inline Result GroupImpl::Add(const GroupImpl& rGroup)
{
	assert(m_data);
	assert(rGroup.ImplementationData());

	return GroupAddGroup(m_data, rGroup.ImplementationData());
}

// FUNCTION: BETA10 0x1016bff0
inline Result GroupImpl::Add(const MeshBuilderImpl& rMesh)
{
	assert(m_data);
	assert(rMesh.ImplementationData());

	return GroupAddMeshBuilder(m_data, rMesh.ImplementationData());
}

// FUNCTION: BETA10 0x1016c1d0
inline Result GroupImpl::Remove(const GroupImpl& rGroup)
{
	assert(m_data);
	assert(rGroup.ImplementationData());

	return GroupRemoveGroup(m_data, rGroup.ImplementationData());
}

// FUNCTION: BETA10 0x1016c130
inline Result GroupImpl::Remove(const MeshBuilderImpl& rMesh)
{
	assert(m_data);
	assert(rMesh.ImplementationData());

	return GroupRemoveMeshBuilder(m_data, rMesh.ImplementationData());
}

// FUNCTION: LEGO1 0x100a34b0
// FUNCTION: BETA10 0x1016a8c0
inline Result GroupImpl::RemoveAll()
{
	assert(m_data);

	return GroupRemoveAll(m_data);
}

// FUNCTION: LEGO1 0x100a31e0
// FUNCTION: BETA10 0x1016a4d0
inline Result GroupImpl::SetTransformation(FloatMatrix4& matrix)
{
	assert(m_data);

	return GroupSetTransformation(m_data, matrix);
}

// FUNCTION: LEGO1 0x100a3240
// FUNCTION: BETA10 0x1016a530
inline Result GroupImpl::SetColor(float r, float g, float b, float a)
{
	assert(m_data);

	return GroupSetColor(m_data, r, g, b, a);
}

// FUNCTION: LEGO1 0x100a33c0
// FUNCTION: BETA10 0x1016a660
inline Result GroupImpl::SetMaterialMode(MaterialMode mode)
{
	assert(m_data);

	return GroupSetMaterialMode(m_data, mode);
}

// FUNCTION: LEGO1 0x100a32b0
// FUNCTION: BETA10 0x1016a5a0
inline Result GroupImpl::SetTexture(const Texture* pTexture)
{
	assert(m_data);

	return SetTexture(static_cast<const TextureImpl*>(pTexture));
}

// FUNCTION: LEGO1 0x100a32e0
// FUNCTION: BETA10 0x1016a600
inline Result GroupImpl::GetTexture(Texture*& pTexture)
{
	assert(m_data);

	return GetTexture(reinterpret_cast<TextureImpl**>(&pTexture));
}

// FUNCTION: LEGO1 0x100a3410
// FUNCTION: BETA10 0x1016a6c0
inline Result GroupImpl::Add(const Group* pGroup)
{
	assert(m_data);
	assert(pGroup);

	return Add(*static_cast<const GroupImpl*>(pGroup));
}

// FUNCTION: LEGO1 0x100a3430
// FUNCTION: BETA10 0x1016a740
inline Result GroupImpl::Add(const MeshBuilder* pMesh)
{
	assert(m_data);
	assert(pMesh);

	return Add(*static_cast<const MeshBuilderImpl*>(pMesh));
}

// FUNCTION: LEGO1 0x100a3480
// FUNCTION: BETA10 0x1016a840
inline Result GroupImpl::Remove(const Group* pGroup)
{
	assert(m_data);
	assert(pGroup);

	return Remove(*static_cast<const GroupImpl*>(pGroup));
}

// FUNCTION: LEGO1 0x100a3450
// FUNCTION: BETA10 0x1016a7c0
inline Result GroupImpl::Remove(const MeshBuilder* pMesh)
{
	assert(m_data);
	assert(pMesh);

	return Remove(*static_cast<const MeshBuilderImpl*>(pMesh));
}

// FUNCTION: LEGO1 0x100a31d0
// FUNCTION: BETA10 0x1016a480
inline void* GroupImpl::ImplementationDataPtr()
{
	assert(m_data);

	return reinterpret_cast<void*>(&m_data);
}

// FUNCTION: LEGO1 0x100a3540
// FUNCTION: BETA10 0x1016a920
inline Result GroupImpl::Bounds(D3DVECTOR* p_min, D3DVECTOR* p_max)
{
	assert(m_data);

	return GroupBounds(m_data, p_min, p_max);
}

// FUNCTION: LEGO1 0x100a3ae0
// FUNCTION: BETA10 0x1016ce00
inline Result MeshBuilderImpl::GetBoundingBox(float min[3], float max[3]) const
{
	assert(m_data);

	return MeshBuilderGetBoundingBox(m_data, min, max);
}

// FUNCTION: LEGO1 0x100a3830
// FUNCTION: BETA10 0x1016c9f0
inline void* MeshBuilderImpl::ImplementationDataPtr()
{
	assert(m_data);

	return reinterpret_cast<void*>(&m_data);
}

// FUNCTION: BETA10 0x1016fe40
inline Result MeshBuilderImpl::CreateMeshImpl(
	MeshImpl& p_elem,
	unsigned long faceCount,
	unsigned long vertexCount,
	float (*pPositions)[3],
	float (*pNormals)[3],
	float (*pTextureCoordinates)[2],
	unsigned long (*pFaceIndices)[3],
	unsigned long (*pTextureIndices)[3],
	ShadingModel shadingModel
)
{
	assert(m_data);
	assert(!p_elem.ImplementationData());

	return TglImpl::CreateMesh(
		m_data,
		faceCount,
		vertexCount,
		reinterpret_cast<float*>(pPositions),
		reinterpret_cast<float*>(pNormals),
		reinterpret_cast<float*>(pTextureCoordinates),
		pFaceIndices,
		pTextureIndices,
		shadingModel,
		p_elem.ImplementationData()
	);
}

// FUNCTION: LEGO1 0x100a3840
// FUNCTION: BETA10 0x1016ca40
inline Mesh* MeshBuilderImpl::CreateMesh(
	unsigned long faceCount,
	unsigned long vertexCount,
	float (*pPositions)[3],
	float (*pNormals)[3],
	float (*pTextureCoordinates)[2],
	unsigned long (*pFaceIndices)[3],
	unsigned long (*pTextureIndices)[3],
	ShadingModel shadingModel
)
{
	assert(m_data);

	MeshImpl* pMeshImpl = new MeshImpl;
	if (CreateMeshImpl(
			*pMeshImpl,
			faceCount,
			vertexCount,
			pPositions,
			pNormals,
			pTextureCoordinates,
			pFaceIndices,
			pTextureIndices,
			shadingModel
		) == Error) {
		delete pMeshImpl;
		pMeshImpl = NULL;
	}

	return pMeshImpl;
}

// FUNCTION: LEGO1 0x100a3b40
inline MeshBuilder* MeshBuilderImpl::Clone()
{
	MeshBuilderImpl* mesh = new MeshBuilderImpl();
	int ret = m_data->Clone(0, IID_IDirect3DRMMesh, (void**) &mesh->m_data);
	if (ret < 0) {
		delete mesh;
		mesh = NULL;
	}
	return mesh;
}

// FUNCTION: BETA10 0x10171260
inline Result MeshImpl::SetTexture(const TextureImpl* pTexture)
{
	assert(m_data);
	assert(!pTexture || pTexture->ImplementationData());

	IDirect3DRMTexture* pD3DTexture = pTexture ? pTexture->ImplementationData() : NULL;
	return MeshSetTexture(m_data, pD3DTexture);
}

// FUNCTION: LEGO1 0x100a3f80
// FUNCTION: BETA10 0x10170690
inline Result MeshImpl::SetTextureMappingMode(TextureMappingMode mode)
{
	assert(m_data);

	return MeshSetTextureMappingMode(m_data, mode);
}

// FUNCTION: LEGO1 0x100a3fc0
// FUNCTION: BETA10 0x101706f0
inline Result MeshImpl::SetShadingModel(ShadingModel model)
{
	assert(m_data);
	return MeshSetShadingModel(m_data, model);
}

// FUNCTION: LEGO1 0x100a3ee0
// FUNCTION: BETA10 0x10170520
inline Result MeshImpl::SetColor(float r, float g, float b, float a)
{
	assert(m_data);

	return MeshSetColor(m_data, r, g, b, a);
}

// FUNCTION: LEGO1 0x100a3f50
// FUNCTION: BETA10 0x10170630
inline Result MeshImpl::SetTexture(const Texture* pTexture)
{
	assert(m_data);

	return SetTexture(static_cast<const TextureImpl*>(pTexture));
}

// FUNCTION: LEGO1 0x100a3ed0
// FUNCTION: BETA10 0x101704d0
inline void* MeshImpl::ImplementationDataPtr()
{
	assert(m_data);

	return reinterpret_cast<void*>(&m_data);
}

// FUNCTION: LEGO1 0x100a4030
// FUNCTION: BETA10 0x101707a0
inline Mesh* MeshImpl::DeepClone(MeshBuilder* pMesh)
{
	assert(m_data);
	assert(pMesh);

	return DeepClone(*static_cast<MeshBuilderImpl*>(pMesh));
}

// FUNCTION: BETA10 0x10171360
inline Mesh* MeshImpl::DeepClone(const MeshBuilderImpl& rMesh)
{
	assert(m_data);
	assert(rMesh.ImplementationData());

	MeshImpl* clone = new MeshImpl();
	assert(!clone->ImplementationData());

	if (!MeshDeepClone(m_data, clone->ImplementationData(), rMesh.ImplementationData())) {
		delete clone;
		clone = NULL;
	}

	return clone;
}

// FUNCTION: BETA10 0x10171980
inline Result MeshImpl::GetTexture(TextureImpl** ppTexture)
{
	assert(m_data);
	assert(ppTexture);

	TextureImpl* pTextureImpl = new TextureImpl();
	assert(pTextureImpl);

	Result result = MeshGetTexture(m_data, &pTextureImpl->ImplementationData());

	*ppTexture = pTextureImpl;
	return result;
}

// FUNCTION: LEGO1 0x100a4330
// FUNCTION: BETA10 0x10170820
inline Result MeshImpl::GetTexture(Texture*& rpTexture)
{
	assert(m_data);

	return GetTexture(reinterpret_cast<TextureImpl**>(&rpTexture));
}

inline Mesh* MeshImpl::ShallowClone(const MeshBuilderImpl& rMesh)
{
	assert(m_data);
	assert(rMesh.ImplementationData());

	MeshImpl* clone = new MeshImpl();
	assert(!clone->ImplementationData());

	if (!MeshShallowClone(m_data, clone->ImplementationData(), rMesh.ImplementationData())) {
		delete clone;
		clone = NULL;
	}

	return clone;
}

// FUNCTION: LEGO1 0x100a4240
inline Mesh* MeshImpl::ShallowClone(MeshBuilder* pMeshBuilder)
{
	assert(m_data);
	assert(pMeshBuilder);

	return ShallowClone(*static_cast<MeshBuilderImpl*>(pMeshBuilder));
}

// FUNCTION: LEGO1 0x100a3c10
// FUNCTION: BETA10 0x1016c390
inline Result TextureImpl::SetTexels(int width, int height, int bitsPerTexel, void* pTexels, int pTexelsArePersistent)
{
	assert(m_data);

	return TextureSetTexels(m_data, width, height, bitsPerTexel, pTexels, pTexelsArePersistent);
}

// FUNCTION: LEGO1 0x100a3c60
// FUNCTION: BETA10 0x1016c490
inline void TextureImpl::FillRowsOfTexture(int y, int height, void* pBuffer)
{
	assert(m_data);

	TextureFillRowsOfTexture(m_data, y, height, pBuffer);
}

// FUNCTION: LEGO1 0x100a3c90
// FUNCTION: BETA10 0x1016c540
inline Result TextureImpl::Changed(int texelsChanged, int paletteChanged)
{
	assert(m_data);

	return TextureChanged(m_data, texelsChanged, paletteChanged);
}

// FUNCTION: LEGO1 0x100a3cc0
// FUNCTION: BETA10 0x1016c5d0
inline Result TextureImpl::GetBufferAndPalette(
	int* width,
	int* height,
	int* depth,
	void** pBuffer,
	int* paletteSize,
	unsigned char (*pEntries)[3]
)
{
	assert(m_data);

	return TextureGetBufferAndPalette(m_data, width, height, depth, pBuffer, paletteSize, pEntries);
}

// FUNCTION: LEGO1 0x100a3d40
// FUNCTION: BETA10 0x1016c6a0
inline Result TextureImpl::SetPalette(int entryCount, PaletteEntry* pEntries)
{
	assert(m_data);

	return TextureSetPalette(m_data, entryCount, pEntries);
}

// FUNCTION: LEGO1 0x100a3d70
// FUNCTION: BETA10 0x1016c760
inline void* TextureImpl::ImplementationDataPtr()
{
	assert(m_data);

	return reinterpret_cast<void*>(&m_data);
}

} /* namespace TglImpl */

// SYNTHETIC: LEGO1 0x100a16d0
// SYNTHETIC: BETA10 0x10169aa0
// TglImpl::RendererImpl::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100a22c0
// SYNTHETIC: BETA10 0x1016b700
// TglImpl::DeviceImpl::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100a23a0
// SYNTHETIC: BETA10 0x1016b810
// TglImpl::ViewImpl::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100a2480
// SYNTHETIC: BETA10 0x1016a2c0
// TglImpl::GroupImpl::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100a2560
// SYNTHETIC: BETA10 0x1016b920
// TglImpl::CameraImpl::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100a2640
// SYNTHETIC: BETA10 0x1016ba30
// TglImpl::LightImpl::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100a2720
// SYNTHETIC: BETA10 0x1016b5f0
// TglImpl::MeshBuilderImpl::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100a2800
// SYNTHETIC: BETA10 0x1016b4e0
// TglImpl::TextureImpl::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100a3d80
// SYNTHETIC: BETA10 0x1016fa90
// TglImpl::MeshImpl::`scalar deleting destructor'

// GLOBAL: LEGO1 0x100dd1e0
// IID_IDirect3DRMMeshBuilder

// GLOBAL: LEGO1 0x100dd1f0
// IID_IDirect3DRMMesh

#endif
