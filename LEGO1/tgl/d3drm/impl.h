
#include "../../decomp.h"
#include "../tgl.h"

#include <d3drm.h>

// Forward declare D3D types
struct IDirect3DRM;
struct IDirect3DRMDevice;
struct IDirect3DRMViewport;
struct IDirect3DRMFrame;
struct IDirect3DRMMesh;
struct IDirect3DRMMeshBuilder;
struct IDirect3DRMTexture;

namespace TglImpl
{

using namespace Tgl;

// Utility function used by implementations
inline Result ResultVal(HRESULT p_result)
{
	return SUCCEEDED(p_result) ? Success : Error;
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

// VTABLE 0x100db910
class RendererImpl : public Renderer {
public:
	RendererImpl() : m_data(0) {}
	~RendererImpl() { Destroy(); };

	virtual void* ImplementationDataPtr();

	// vtable+0x08
	virtual Device* CreateDevice(const DeviceDirect3DCreateData&);
	virtual Device* CreateDevice(const DeviceDirectDrawCreateData&);

	// vtable+0x10
	virtual View* CreateView(
		const Device*,
		const Camera*,
		unsigned long p_x,
		unsigned long p_y,
		unsigned long p_width,
		unsigned long p_height
	);
	virtual Camera* CreateCamera();
	virtual Light* CreateLight(LightType, float p_r, float p_g, float p_b);
	virtual Group* CreateGroup(const Group* p_parent);

	// vtable+0x20
	virtual Something* CreateSomething();
	virtual Texture* CreateTexture();
	virtual Texture* CreateTexture(
		int p_width,
		int p_height,
		int p_bitsPerTexel,
		const void* p_pTexels,
		int p_pTexelsArePersistent,
		int p_paletteEntryCount,
		const PaletteEntry* p_pEntries
	);
	virtual Result SetTextureDefaultShadeCount(unsigned long);

	// vtable+0x30
	virtual Result SetTextureDefaultColorCount(unsigned long);

public:
	inline Result Create();
	inline void Destroy();

private:
	IDirect3DRM* m_data;
};

// VTABLE 0x100db988
class DeviceImpl : public Device {
public:
	DeviceImpl() : m_data(0) {}
	~DeviceImpl();

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

	inline IDirect3DRMDevice* ImplementationData() const { return m_data; }

	friend class RendererImpl;

private:
	IDirect3DRMDevice* m_data;
};

// VTABLE 0x100db9e8
class ViewImpl : public View {
public:
	ViewImpl() : m_data(0) {}
	~ViewImpl();

	virtual void* ImplementationDataPtr();

	// vtable+0x08
	virtual Result Add(const Light*);
	virtual Result Remove(const Light*);

	// vtable+0x10
	virtual Result SetCamera(const Camera*);
	virtual Result SetProjection(ProjectionType);
	virtual Result SetFrustrum(float p_frontClippingDistance, float p_backClippingDistance, float p_degrees);
	virtual Result SetBackgroundColor(float p_r, float p_g, float p_b);

	// vtable+0x20
	virtual Result GetBackgroundColor(float* p_r, float* p_g, float* p_b);
	virtual Result Clear();
	virtual Result Render(const Light*);
	virtual Result ForceUpdate(unsigned long x, unsigned long y, unsigned long width, unsigned long height);

	// vtable+0x30
	virtual Result TransformWorldToScreen(const float world[3], float screen[4]);
	virtual Result TransformScreenToWorld(const float screen[4], float world[3]);
	virtual Result Pick(
		unsigned long p_x,
		unsigned long p_y,
		const Group** p_ppGroupsToPickFrom,
		int p_groupsToPickFromCount,
		const Group**& p_rppPickedGroups,
		int& p_rPickedGroupCount
	);

	inline IDirect3DRMViewport* ImplementationData() const { return m_data; }

	static Result ViewportCreateAppData(IDirect3DRM*, IDirect3DRMViewport*, IDirect3DRMFrame*);

	friend class RendererImpl;

private:
	IDirect3DRMViewport* m_data;
};

// VTABLE 0x100dbad8
class CameraImpl : public Camera {
public:
	CameraImpl() : m_data(0) {}
	~CameraImpl();

	virtual void* ImplementationDataPtr();

	// vtable+0x08
	virtual Result SetTransformation(const FloatMatrix4&);

	inline IDirect3DRMFrame* ImplementationData() const { return m_data; }

	friend class RendererImpl;

private:
	IDirect3DRMFrame* m_data;
};

// VTABLE 0x100dbaf8
class LightImpl : public Light {
public:
	LightImpl() : m_data(0) {}
	~LightImpl();

	virtual void* ImplementationDataPtr();

	// vtable+0x08
	virtual Result SetTransformation(const FloatMatrix4&);
	virtual Result SetColor(float p_r, float p_g, float p_b);

	inline IDirect3DRMFrame* ImplementationData() const { return m_data; }

	friend class RendererImpl;

private:
	IDirect3DRMFrame* m_data;
};

// VTABLE 0x100dbb88
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
	virtual Result SetColor(float p_r, float p_g, float p_b, float p_a);
	virtual Result SetTexture(const Texture*);

	// vtable+0x10
	virtual Result GetTexture(Texture*&);
	virtual Result SetTextureMappingMode(ProjectionType);
	virtual Result SetShadingModel(ShadingModel);
	virtual Mesh* DeepClone(Something*);

	// vtable+0x20
	virtual Mesh* ShallowClone(Something*);

	struct MeshData {
		IDirect3DRMMesh* groupMesh;
		int groupIndex;
	};

	inline MeshData* ImplementationData() const { return m_data; }

	friend class RendererImpl;

private:
	MeshData* m_data;
};

// VTABLE 0x100dba68
class GroupImpl : public Group {
public:
	GroupImpl() : m_data(0) {}
	~GroupImpl();

	virtual void* ImplementationDataPtr();

	// vtable+0x08
	virtual Result SetTransformation(const FloatMatrix4&);
	virtual Result SetColor(float p_r, float p_g, float p_b, float p_a);

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
	IDirect3DRMFrame* m_data;
};

// VTABLE 0x100dbb18
class SomethingImpl : public Something {
public:
	SomethingImpl() : m_data(0) {}
	~SomethingImpl();

	virtual void* ImplementationDataPtr();

	// vtable+0x08
	virtual Result SetMeshData(
		unsigned long p_faceCount,
		unsigned long p_vertexCount,
		const float (*p_positions)[3],
		const float (*p_normals)[3],
		const float (*p_textureCoordinates)[2],
		unsigned long p_vertexPerFaceCount,
		unsigned long* p_faceData
	);
	virtual Result GetBoundingBox(float p_min[3], float p_max[3]);

	// vtable+0x10
	virtual Something* Clone();

	inline IDirect3DRMMesh* ImplementationData() const { return m_data; }

	friend class RendererImpl;

private:
	IDirect3DRMMesh* m_data;
};

// No vtable, this is just a simple wrapper around D3DRMIMAGE
class TglD3DRMIMAGE {
public:
	TglD3DRMIMAGE(
		int p_width,
		int p_height,
		int p_depth,
		void* p_buffer,
		int p_useBuffer,
		int p_paletteSize,
		PaletteEntry* p_palette
	);
	~TglD3DRMIMAGE() { Destroy(); }

	Result CreateBuffer(int p_width, int p_height, int p_depth, void* p_buffer, int p_useBuffer);
	void Destroy();
	void FillRowsOfTexture(int p_y, int p_height, char* p_content);
	Result InitializePalette(int p_paletteSize, PaletteEntry* p_palette);

	D3DRMIMAGE m_image;
	int m_texelsAllocatedByClient;
};

// VTABLE 0x100dbb48
class TextureImpl : public Texture {
public:
	TextureImpl() : m_data(0) {}
	~TextureImpl();

	virtual void* ImplementationDataPtr();

	// vtable+0x08
	virtual Result SetTexels(int p_width, int p_height, int p_bitsPerTexel, void* p_texels);
	virtual void FillRowsOfTexture(int p_y, int p_height, void* p_buffer);

	// vtable+0x10
	virtual Result Changed(int p_texelsChanged, int p_paletteChanged);
	virtual Result GetBufferAndPalette(
		int* p_width,
		int* p_height,
		int* p_depth,
		void** p_buffer,
		int* p_paletteSize,
		PaletteEntry** p_palette
	);
	virtual Result SetPalette(int p_entryCount, PaletteEntry* p_entries);

	inline IDirect3DRMTexture* ImplementationData() const { return m_data; }
	inline void SetImplementation(IDirect3DRMTexture* data) { m_data = data; }

	friend class RendererImpl;

	static Result SetImage(IDirect3DRMTexture* p_self, TglD3DRMIMAGE* p_image);

private:
	IDirect3DRMTexture* m_data;
};

// Translation helpers
inline D3DRMRENDERQUALITY Translate(ShadingModel p_tglShadingModel)
{
	D3DRMRENDERQUALITY renderQuality;

	switch (p_tglShadingModel) {
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

inline D3DRMPROJECTIONTYPE Translate(ProjectionType p_tglProjectionType)
{
	D3DRMPROJECTIONTYPE projectionType;
	switch (p_tglProjectionType) {
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
inline D3DRMMATRIX4D* Translate(const FloatMatrix4& tglMatrix4x4, D3DRMMATRIX4D& rD3DRMMatrix4x4)
{
	for (int i = 0; i < (sizeof(rD3DRMMatrix4x4) / sizeof(rD3DRMMatrix4x4[0])); i++) {
		for (int j = 0; j < (sizeof(rD3DRMMatrix4x4[0]) / sizeof(rD3DRMMatrix4x4[0][0])); j++) {
			rD3DRMMatrix4x4[i][j] = D3DVAL(tglMatrix4x4[i][j]);
		}
	}
	return &rD3DRMMatrix4x4;
}

} /* namespace TglImpl */
