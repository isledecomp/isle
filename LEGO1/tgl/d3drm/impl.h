
#include "compat.h"
#include "decomp.h"
#include "tgl/tgl.h"

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

// Utility function used by implementations
// FUNCTION: BETA10 0x10169cf0
inline Result ResultVal(HRESULT result)
{
	return SUCCEEDED(result) ? Success : Error;
}

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

extern IDirect3DRM2* g_pD3DRM;

// FUNCTION: BETA10 0x1016dd20
inline void RendererDestroy(IDirect3DRM2* pRenderer)
{
	int refCount = pRenderer->Release();
	if (refCount <= 0) {
		g_pD3DRM = NULL;
	}
}

// Inlined only
// FUNCTION: BETA10 0x1016dce0
void RendererImpl::Destroy()
{
	if (m_data) {
		RendererDestroy(m_data);
		m_data = NULL;
	}
}

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
	void HandlePaint(HDC) override;

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

// FUNCTION: BETA10 0x101708c0
inline void DeviceDestroy(IDirect3DRMDevice2* pDevice)
{
	pDevice->Release();
}

// FUNCTION: BETA10 0x10170880
void DeviceImpl::Destroy()
{
	if (m_data) {
		DeviceDestroy(m_data);
		m_data = NULL;
	}
}

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

// FUNCTION: BETA10 0x101711a0
inline void ViewDestroy(IDirect3DRMViewport* pView)
{
	pView->Release();
}

// FUNCTION: BETA10 0x10171160
void ViewImpl::Destroy()
{
	if (m_data) {
		ViewDestroy(m_data);
		m_data = NULL;
	}
}

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

// FUNCTION: BETA10 0x10170940
inline void CameraDestroy(IDirect3DRMFrame2* pFrame)
{
	pFrame->Release();
}

// FUNCTION: BETA10 0x10170900
void CameraImpl::Destroy()
{
	if (m_data) {
		CameraDestroy(m_data);
		m_data = NULL;
	}
}

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

// FUNCTION: BETA10 0x10171220
inline void LightDestroy(IDirect3DRMFrame2* pLight)
{
	pLight->Release();
}

// FUNCTION: BETA10 0x101711e0
void LightImpl::Destroy()
{
	if (m_data) {
		LightDestroy(m_data);
		m_data = NULL;
	}
}

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

	friend class RendererImpl;

private:
	MeshDataType m_data;
};

// FUNCTION: BETA10 0x10171b40
inline void MeshDestroy(MeshImpl::MeshDataType pMesh)
{
	delete pMesh;
}

// FUNCTION: BETA10 0x10171b00
void MeshImpl::Destroy()
{
	if (m_data) {
		MeshDestroy(m_data);
		m_data = NULL;
	}
}

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

	friend class RendererImpl;

private:
	GroupDataType m_data;
};

// FUNCTION: BETA10 0x1016c2b0
inline void GroupDestroy(IDirect3DRMFrame2* pGroup)
{
	pGroup->Release();
}

// FUNCTION: BETA10 0x1016c270
void GroupImpl::Destroy()
{
	if (m_data) {
		GroupDestroy(m_data);
		m_data = NULL;
	}
}

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
		MeshImpl* pMeshImpl,
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

// FUNCTION: BETA10 0x10170390
inline void MeshBuilderDestroy(IDirect3DRMMesh* pMeshBuilder)
{
	pMeshBuilder->Release();
}

// FUNCTION: BETA10 0x10170350
void MeshBuilderImpl::Destroy()
{
	if (m_data) {
		MeshBuilderDestroy(m_data);
		m_data = NULL;
	}
}

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
	~TglD3DRMIMAGE() { Destroy(); }

	Result CreateBuffer(int width, int height, int depth, void* pBuffer, int useBuffer);
	void Destroy();
	Result FillRowsOfTexture(int y, int height, char* content);
	Result InitializePalette(int paletteSize, PaletteEntry* pEntries);

	D3DRMIMAGE m_image;
	int m_texelsAllocatedByClient;
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
	Result SetTexels(int width, int height, int bitsPerTexel, void* pTexels) override;
	void FillRowsOfTexture(int y, int height, void* pBuffer) override;

	// vtable+0x10
	Result Changed(int texelsChanged, int paletteChanged) override;
	Result GetBufferAndPalette(
		int* pWidth,
		int* pHeight,
		int* pDepth,
		void** ppBuffer,
		int* ppPaletteSize,
		PaletteEntry** ppPalette
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

// FUNCTION: BETA10 0x1016fd40
inline void TextureDestroy(IDirect3DRMTexture* pTexture)
{
	pTexture->Release();
}

// FUNCTION: BETA10 0x1016fd00
void TextureImpl::Destroy()
{
	if (m_data) {
		TextureDestroy(m_data);
		m_data = NULL;
	}
}

// Translation helpers
// FUNCTION: BETA10 0x1016fc40
inline D3DRMRENDERQUALITY Translate(ShadingModel tglShadingModel)
{
	D3DRMRENDERQUALITY renderQuality;

	switch (tglShadingModel) {
	case Wireframe:
		renderQuality = D3DRMRENDER_WIREFRAME;
		break;
	case UnlitFlat:
		renderQuality = D3DRMRENDER_UNLITFLAT;
		break;
	case Flat:
		renderQuality = D3DRMRENDER_FLAT;
		break;
	case Gouraud:
		renderQuality = D3DRMRENDER_GOURAUD;
		break;
	case Phong:
		renderQuality = D3DRMRENDER_PHONG;
		break;
	default:
		renderQuality = D3DRMRENDER_FLAT;
		break;
	}

	return renderQuality;
}

// FUNCTION: BETA10 0x101703b0
inline D3DRMPROJECTIONTYPE Translate(ProjectionType tglProjectionType)
{
	D3DRMPROJECTIONTYPE projectionType;
	switch (tglProjectionType) {
	case Perspective:
		projectionType = D3DRMPROJECT_PERSPECTIVE;
		break;
	case Orthographic:
		projectionType = D3DRMPROJECT_ORTHOGRAPHIC;
		break;
	default:
		projectionType = D3DRMPROJECT_PERSPECTIVE;
		break;
	}
	return projectionType;
}

// Yes this function serves no purpose, originally they intended it to
// convert from doubles to floats but ended up using floats throughout
// the software stack.
inline D3DRMMATRIX4D* Translate(FloatMatrix4& tglMatrix4x4, D3DRMMATRIX4D& rD3DRMMatrix4x4)
{
	for (int i = 0; i < (sizeof(rD3DRMMatrix4x4) / sizeof(rD3DRMMatrix4x4[0])); i++) {
		for (int j = 0; j < (sizeof(rD3DRMMatrix4x4[0]) / sizeof(rD3DRMMatrix4x4[0][0])); j++) {
			rD3DRMMatrix4x4[i][j] = D3DVAL(tglMatrix4x4[i][j]);
		}
	}
	return &rD3DRMMatrix4x4;
}

// FUNCTION: BETA10 0x1016fba0
inline D3DVECTOR* Translate(const float tglVector[3], D3DVECTOR& rD3DVector)
{
	rD3DVector.x = D3DVAL(tglVector[0]);
	rD3DVector.y = D3DVAL(tglVector[1]);
	rD3DVector.z = D3DVAL(tglVector[2]);

	return &rD3DVector;
}

// FUNCTION: BETA10 0x1016fd80
inline D3DRMLIGHTTYPE Translate(LightType tglLightType)
{
	D3DRMLIGHTTYPE lightType;

	// ??? use lookup table
	switch (tglLightType) {
	case Ambient:
		lightType = D3DRMLIGHT_AMBIENT;
		break;
	case Point:
		lightType = D3DRMLIGHT_POINT;
		break;
	case Spot:
		lightType = D3DRMLIGHT_SPOT;
		break;
	case Directional:
		lightType = D3DRMLIGHT_DIRECTIONAL;
		break;
	case ParallelPoint:
		lightType = D3DRMLIGHT_PARALLELPOINT;
		break;
	default:
		lightType = D3DRMLIGHT_AMBIENT;
		break;
	}

	return lightType;
}

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

// SYNTHETIC: BETA10 0x10169960
// ViewportAppData::`scalar deleting destructor'

// GLOBAL: LEGO1 0x100dd1e0
// IID_IDirect3DRMMeshBuilder

} /* namespace TglImpl */
