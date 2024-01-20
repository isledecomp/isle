
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
class UnkImpl;

// VTABLE: LEGO1 0x100db910
class RendererImpl : public Renderer {
public:
	RendererImpl() : m_data(0) {}
	~RendererImpl() { Destroy(); };

	virtual void* ImplementationDataPtr() override;

	// vtable+0x08
	virtual Device* CreateDevice(const DeviceDirectDrawCreateData&) override;
	virtual Device* CreateDevice(const DeviceDirect3DCreateData&) override;

	// vtable+0x10
	virtual View* CreateView(
		const Device*,
		const Camera*,
		unsigned long x,
		unsigned long y,
		unsigned long width,
		unsigned long height
	) override;
	virtual Camera* CreateCamera() override;
	virtual Light* CreateLight(LightType, float r, float g, float b) override;
	virtual Group* CreateGroup(const Group* pParent) override;

	// vtable+0x20
	virtual Unk* CreateUnk() override;
	virtual Texture* CreateTexture() override;
	virtual Texture* CreateTexture(
		int width,
		int height,
		int bitsPerTexel,
		const void* pTexels,
		int pTexelsArePersistent,
		int paletteEntryCount,
		const PaletteEntry* pEntries
	) override;
	virtual Result SetTextureDefaultShadeCount(unsigned long) override;

	// vtable+0x30
	virtual Result SetTextureDefaultColorCount(unsigned long) override;

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
	~DeviceImpl()
	{
		if (m_data) {
			m_data->Release();
			m_data = NULL;
		}
	}

	virtual void* ImplementationDataPtr();

	// vtable+0x08
	virtual unsigned long GetWidth();
	virtual unsigned long GetHeight();

	// vtable+0x10
	virtual Result SetColorModel(ColorModel);
	virtual Result SetShadingModel(ShadingModel);
	virtual Result SetShadeCount(unsigned long);
	virtual Result SetDither(int);

	// vtable+0x20
	virtual Result Update();
	virtual void InitFromD3DDevice(Device*);
	virtual void InitFromWindowsDevice(Device*);

	inline IDirect3DRMDevice2* ImplementationData() const { return m_data; }

	friend class RendererImpl;

private:
	IDirect3DRMDevice2* m_data;
};

// VTABLE: LEGO1 0x100db9e8
class ViewImpl : public View {
public:
	ViewImpl() : m_data(0) {}
	~ViewImpl()
	{
		if (m_data) {
			m_data->Release();
			m_data = NULL;
		}
	}

	virtual void* ImplementationDataPtr();

	// vtable+0x08
	virtual Result Add(const Light*);
	virtual Result Remove(const Light*);

	// vtable+0x10
	virtual Result SetCamera(const Camera*);
	virtual Result SetProjection(ProjectionType);
	virtual Result SetFrustrum(float frontClippingDistance, float backClippingDistance, float degrees);
	virtual Result SetBackgroundColor(float r, float g, float b);

	// vtable+0x20
	virtual Result GetBackgroundColor(float* r, float* g, float* b);
	virtual Result Clear();
	virtual Result Render(const Light*);
	virtual Result ForceUpdate(unsigned long x, unsigned long y, unsigned long width, unsigned long height);

	// vtable+0x30
	virtual Result TransformWorldToScreen(const float world[3], float screen[4]);
	virtual Result TransformScreenToWorld(const float screen[4], float world[3]);
	virtual Result Pick(
		unsigned long x,
		unsigned long y,
		const Group** ppGroupsToPickFrom,
		int groupsToPickFromCount,
		const Group**& rppPickedGroups,
		int& rPickedGroupCount
	);

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
	~CameraImpl()
	{
		if (m_data) {
			m_data->Release();
			m_data = NULL;
		}
	}

	virtual void* ImplementationDataPtr();

	// vtable+0x08
	virtual Result SetTransformation(FloatMatrix4&);

	inline IDirect3DRMFrame2* ImplementationData() const { return m_data; }

	friend class RendererImpl;

private:
	IDirect3DRMFrame2* m_data;
};

// VTABLE: LEGO1 0x100dbaf8
class LightImpl : public Light {
public:
	LightImpl() : m_data(0) {}
	~LightImpl()
	{
		if (m_data) {
			m_data->Release();
			m_data = NULL;
		}
	}

	virtual void* ImplementationDataPtr();

	// vtable+0x08
	virtual Result SetTransformation(FloatMatrix4&);
	virtual Result SetColor(float r, float g, float b);

	inline IDirect3DRMFrame2* ImplementationData() const { return m_data; }

	friend class RendererImpl;

private:
	IDirect3DRMFrame2* m_data;
};

// VTABLE: LEGO1 0x100dbb88
class MeshImpl : public Mesh {
public:
	MeshImpl() : m_data(0) {}
	~MeshImpl()
	{
		if (m_data) {
			delete m_data;
			m_data = NULL;
		}
	}

	virtual void* ImplementationDataPtr();

	// vtable+0x08
	virtual Result SetColor(float r, float g, float b, float a);
	virtual Result SetTexture(const Texture*);

	// vtable+0x10
	virtual Result GetTexture(Texture*&);
	virtual Result SetTextureMappingMode(ProjectionType);
	virtual Result SetShadingModel(ShadingModel);
	virtual Mesh* DeepClone(Unk*);

	// vtable+0x20
	virtual Mesh* ShallowClone(Unk*);

	struct MeshData {
		IDirect3DRMMesh* groupMesh;
		int groupIndex;
	};

	inline MeshData* ImplementationData() const { return m_data; }

	friend class RendererImpl;

private:
	MeshData* m_data;
};

// VTABLE: LEGO1 0x100dba68
class GroupImpl : public Group {
public:
	GroupImpl() : m_data(0) {}
	~GroupImpl()
	{
		if (m_data) {
			m_data->Release();
			m_data = NULL;
		}
	}

	virtual void* ImplementationDataPtr();

	// vtable+0x08
	virtual Result SetTransformation(FloatMatrix4&);
	virtual Result SetColor(float r, float g, float b, float a);

	// vtable+0x10
	virtual Result SetTexture(const Texture*);
	virtual Result GetTexture(Texture*&);
	virtual Result SetMaterialMode(MaterialMode);
	virtual Result Add(const Group*);

	// vtable+0x20
	virtual Result Add(const Mesh*);
	virtual Result Remove(const Group*);
	virtual Result Remove(const Mesh*);
	virtual Result RemoveAll();

	// vtable+0x30
	virtual Result Unknown();

	friend class RendererImpl;

private:
	IDirect3DRMFrame2* m_data;
};

// VTABLE: LEGO1 0x100dbb18
class UnkImpl : public Unk {
public:
	UnkImpl() : m_data(0) {}
	~UnkImpl()
	{
		if (m_data) {
			m_data->Release();
			m_data = NULL;
		}
	}

	virtual void* ImplementationDataPtr();

	// vtable+0x08
	virtual Result SetMeshData(
		unsigned long faceCount,
		unsigned long vertexCount,
		const float (*pPositions)[3],
		const float (*pNormals)[3],
		const float (*pTextureCoordinates)[2],
		unsigned long vertexPerFaceCount,
		unsigned long* pFaceData
	);
	virtual Result GetBoundingBox(float min[3], float max[3]);

	// vtable+0x10
	virtual Unk* Clone();

	inline IDirect3DRMMesh* ImplementationData() const { return m_data; }

	friend class RendererImpl;

private:
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
	~TextureImpl()
	{
		if (m_data) {
			m_data->Release();
			m_data = NULL;
		}
	}

	virtual void* ImplementationDataPtr();

	// vtable+0x08
	virtual Result SetTexels(int width, int height, int bitsPerTexel, void* pTexels);
	virtual void FillRowsOfTexture(int y, int height, void* pBuffer);

	// vtable+0x10
	virtual Result Changed(int texelsChanged, int paletteChanged);
	virtual Result GetBufferAndPalette(
		int* pWidth,
		int* pHeight,
		int* pDepth,
		void** ppBuffer,
		int* ppPaletteSize,
		PaletteEntry** ppPalette
	);
	virtual Result SetPalette(int entryCount, PaletteEntry* entries);

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
// TglImpl::UnkImpl::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100a2800
// TglImpl::TextureImpl::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100a3d80
// TglImpl::MeshImpl::`scalar deleting destructor'

} /* namespace TglImpl */
