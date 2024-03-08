
#include "compat.h"
#include "decomp.h"
#include "tgl/tgl.h"

#include <d3drm.h>

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
class RendererImpl : public Renderer {
public:
	RendererImpl() : m_data(0) {}
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

	inline HRESULT CreateTextureFromSurface(LPDIRECTDRAWSURFACE pSurface, LPDIRECT3DRMTEXTURE2* pTexture2)
	{
		return m_data->CreateTextureFromSurface(pSurface, pTexture2);
	}

	inline IDirect3DRM2* ImplementationData() const { return m_data; }

public:
	inline Result Create();
	inline void Destroy();

private:
	IDirect3DRM2* m_data;
};

extern IDirect3DRM2* g_pD3DRM;

inline void RendererDestroy(IDirect3DRM2* pRenderer)
{
	int refCount = pRenderer->Release();
	if (refCount <= 0) {
		g_pD3DRM = NULL;
	}
}

// Inlined only
void RendererImpl::Destroy()
{
	if (m_data) {
		RendererDestroy(m_data);
		m_data = NULL;
	}
}

// VTABLE: LEGO1 0x100db988
class DeviceImpl : public Device {
public:
	DeviceImpl() : m_data(0) {}
	~DeviceImpl() override
	{
		if (m_data) {
			m_data->Release();
			m_data = NULL;
		}
	}

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
	void InitFromD3DDevice(Device*) override;
	void InitFromWindowsDevice(Device*) override;

	inline IDirect3DRMDevice2* ImplementationData() const { return m_data; }

	friend class RendererImpl;

private:
	IDirect3DRMDevice2* m_data;
};

// VTABLE: LEGO1 0x100db9e8
class ViewImpl : public View {
public:
	ViewImpl() : m_data(0) {}
	~ViewImpl() override
	{
		if (m_data) {
			m_data->Release();
			m_data = NULL;
		}
	}

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

	inline IDirect3DRMViewport* ImplementationData() const { return m_data; }

	static Result ViewportCreateAppData(IDirect3DRM2*, IDirect3DRMViewport*, IDirect3DRMFrame2*);

	friend class RendererImpl;

private:
	IDirect3DRMViewport* m_data;
};

// VTABLE: LEGO1 0x100dbad8
class CameraImpl : public Camera {
public:
	CameraImpl() : m_data(0) {}
	~CameraImpl() override
	{
		if (m_data) {
			m_data->Release();
			m_data = NULL;
		}
	}

	void* ImplementationDataPtr() override;

	// vtable+0x08
	Result SetTransformation(FloatMatrix4&) override;

	inline IDirect3DRMFrame2* ImplementationData() const { return m_data; }

	friend class RendererImpl;

private:
	IDirect3DRMFrame2* m_data;
};

// VTABLE: LEGO1 0x100dbaf8
class LightImpl : public Light {
public:
	LightImpl() : m_data(0) {}
	~LightImpl() override
	{
		if (m_data) {
			m_data->Release();
			m_data = NULL;
		}
	}

	void* ImplementationDataPtr() override;

	// vtable+0x08
	Result SetTransformation(FloatMatrix4&) override;
	Result SetColor(float r, float g, float b) override;

	inline IDirect3DRMFrame2* ImplementationData() const { return m_data; }

	friend class RendererImpl;

private:
	IDirect3DRMFrame2* m_data;
};

// VTABLE: LEGO1 0x100dbb88
class MeshImpl : public Mesh {
public:
	MeshImpl() : m_data(0) {}
	~MeshImpl() override
	{
		if (m_data) {
			delete m_data;
			m_data = NULL;
		}
	}

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

	inline const MeshDataType& ImplementationData() const { return m_data; }
	inline MeshDataType& ImplementationData() { return m_data; }

	friend class RendererImpl;

private:
	MeshDataType m_data;
};

// VTABLE: LEGO1 0x100dba68
class GroupImpl : public Group {
public:
	GroupImpl() : m_data(0) {}
	~GroupImpl() override
	{
		if (m_data) {
			m_data->Release();
			m_data = NULL;
		}
	}

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
	Result Add(const Mesh*) override;
	Result Remove(const Group*) override;
	Result Remove(const MeshBuilder*) override;
	Result RemoveAll() override;

	// vtable+0x30
	Result Unknown() override;

	inline IDirect3DRMFrame2* ImplementationData() const { return m_data; }

	friend class RendererImpl;

private:
	IDirect3DRMFrame2* m_data;
};

// VTABLE: LEGO1 0x100dbb18
class MeshBuilderImpl : public MeshBuilder {
public:
	MeshBuilderImpl() : m_data(0) {}
	~MeshBuilderImpl() override
	{
		if (m_data) {
			m_data->Release();
			m_data = NULL;
		}
	}

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
	Result GetBoundingBox(float min[3], float max[3]) override;

	// vtable+0x10
	MeshBuilder* Clone() override;

	inline IDirect3DRMMesh* ImplementationData() const { return m_data; }

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

	IDirect3DRMMesh* m_data;
};

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
	void FillRowsOfTexture(int y, int height, char* content);
	Result InitializePalette(int paletteSize, PaletteEntry* pEntries);

	D3DRMIMAGE m_image;
	int m_texelsAllocatedByClient;
};

// VTABLE: LEGO1 0x100dbb48
class TextureImpl : public Texture {
public:
	TextureImpl() : m_data(0) {}
	~TextureImpl() override
	{
		if (m_data) {
			m_data->Release();
			m_data = NULL;
		}
	}

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

	inline IDirect3DRMTexture* ImplementationData() const { return m_data; }
	inline void SetImplementation(IDirect3DRMTexture* pData) { m_data = pData; }

	friend class RendererImpl;

	static Result SetImage(IDirect3DRMTexture* pSelf, TglD3DRMIMAGE* pImage);

private:
	IDirect3DRMTexture* m_data;
};

// Translation helpers
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

// SYNTHETIC: LEGO1 0x100a16d0
// TglImpl::RendererImpl::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100a22c0
// TglImpl::DeviceImpl::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100a23a0
// TglImpl::ViewImpl::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100a2480
// TglImpl::GroupImpl::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100a2560
// TglImpl::CameraImpl::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100a2640
// TglImpl::LightImpl::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100a2720
// TglImpl::MeshBuilderImpl::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100a2800
// TglImpl::TextureImpl::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100a3d80
// TglImpl::MeshImpl::`scalar deleting destructor'

} /* namespace TglImpl */
