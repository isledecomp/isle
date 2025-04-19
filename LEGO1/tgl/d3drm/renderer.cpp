#include "impl.h"

#include <assert.h>

using namespace TglImpl;

// FUNCTION: LEGO1 0x100a15e0
Renderer* Tgl::CreateRenderer()
{
	RendererImpl* renderer = new RendererImpl();
	if (!renderer->Create()) {
		delete renderer;
		renderer = NULL;
	}
	return renderer;
}

namespace TglImpl
{
// GLOBAL: LEGO1 0x1010103c
IDirect3DRM2* g_pD3DRM = NULL;
} // namespace TglImpl

// Inlined only
Result RendererImpl::Create()
{
	if (g_pD3DRM) {
		g_pD3DRM->AddRef();
	}
	else {
		LPDIRECT3DRM handle;
		Direct3DRMCreate(&handle);
		handle->QueryInterface(IID_IDirect3DRM2, (LPVOID*) &g_pD3DRM);
	}
	m_data = g_pD3DRM;
	return (m_data != NULL) ? Success : Error;
}

// FUNCTION: LEGO1 0x100a1830
Device* RendererImpl::CreateDevice(const DeviceDirect3DCreateData& data)
{
	DeviceImpl* device = new DeviceImpl();
	HRESULT result = m_data->CreateDeviceFromD3D(data.m_pDirect3D, data.m_pDirect3DDevice, &device->m_data);
	if (!SUCCEEDED(result)) {
		delete device;
		device = NULL;
	}
	return device;
}

// FUNCTION: LEGO1 0x100a1900
Device* RendererImpl::CreateDevice(const DeviceDirectDrawCreateData& data)
{
	// at LEGO1 0x10101040, needs no annotation
	static int g_SetBufferCount = 1;

	DeviceImpl* device = new DeviceImpl();
	HRESULT result = m_data->CreateDeviceFromSurface(
		const_cast<LPGUID>(data.m_driverGUID),
		data.m_pDirectDraw,
		data.m_pBackBuffer,
		&device->m_data
	);
	if (SUCCEEDED(result) && data.m_pBackBuffer && g_SetBufferCount) {
		device->m_data->SetBufferCount(2);
	}
	if (!SUCCEEDED(result)) {
		delete device;
		device = NULL;
	}
	return device;
}

// FUNCTION: BETA10 0x1016d1d0
inline Result RendererCreateView(
	IDirect3DRM2* pRenderer,
	const IDirect3DRMDevice2* pDevice,
	const IDirect3DRMFrame2* pCamera,
	unsigned long x,
	unsigned long y,
	unsigned long width,
	unsigned long height,
	IDirect3DRMViewport*& rpView
)
{
	Result result = ResultVal(pRenderer->CreateViewport(
		const_cast<IDirect3DRMDevice2*>(pDevice),
		const_cast<IDirect3DRMFrame2*>(pCamera),
		x,
		y,
		width,
		height,
		&rpView
	));

	if (Succeeded(result)) {
		result = ViewImpl::ViewportCreateAppData(pRenderer, rpView, const_cast<IDirect3DRMFrame2*>(pCamera));
		if (!Succeeded(result)) {
			rpView->Release();
			rpView = NULL;
		}
	}

	return result;
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

// FUNCTION: LEGO1 0x100a1a00
// FUNCTION: BETA10 0x10169fb0
View* RendererImpl::CreateView(
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

inline Result RendererCreateGroup(IDirect3DRM2* pRenderer, IDirect3DRMFrame2* pParent, IDirect3DRMFrame2*& rpGroup)
{
	Result result = ResultVal(pRenderer->CreateFrame(NULL, &rpGroup));
	if (Succeeded(result) && pParent) {
		result = ResultVal(pParent->AddVisual(rpGroup));
		if (!Succeeded(result)) {
			rpGroup->Release();
			rpGroup = NULL;
		}
	}
	return result;
}

// FUNCTION: LEGO1 0x100a1b20
Group* RendererImpl::CreateGroup(const Group* pParent)
{
	GroupImpl* group = new GroupImpl();
	Result result =
		RendererCreateGroup(m_data, pParent ? static_cast<const GroupImpl*>(pParent)->m_data : NULL, group->m_data);
	if (!result) {
		delete group;
		group = NULL;
	}
	return group;
}

// FUNCTION: LEGO1 0x100a1c30
Camera* RendererImpl::CreateCamera()
{
	CameraImpl* camera = new CameraImpl();
	if (FAILED(m_data->CreateFrame(NULL, &camera->m_data))) {
		delete camera;
		camera = NULL;
	}
	return camera;
}

// FUNCTION: BETA10 0x1016d580
inline Result RendererCreateLight(
	IDirect3DRM2* pD3DRM,
	LightType type,
	float r,
	float g,
	float b,
	IDirect3DRMFrame2*& rpLight
)
{
	D3DRMLIGHTTYPE lightType = Translate(type);
	IDirect3DRMFrame2* pLightFrame;
	IDirect3DRMLight* pLight;
	Result result;

	result = ResultVal(pD3DRM->CreateFrame(NULL, &pLightFrame));
	assert(Succeeded(result));
	if (!Succeeded(result)) {
		return result;
	}
	// pLightFrame ref count is now 1
	assert((pLightFrame->AddRef(), pLightFrame->Release()) == 1);

	result = ResultVal(pD3DRM->CreateLightRGB(lightType, D3DVAL(r), D3DVAL(g), D3DVAL(b), &pLight));
	assert(Succeeded(result));
	if (!Succeeded(result)) {
		pLightFrame->Release();
		return result;
	}
	// pLight ref count is now 1
	assert((pLight->AddRef(), pLight->Release()) == 1);

	result = ResultVal(pLightFrame->AddLight(pLight));
	assert(Succeeded(result));
	if (!Succeeded(result)) {
		pLightFrame->Release();
		pLight->Release();
		return result;
	}
	// pLightFrame ref count is still 1
	assert((pLightFrame->AddRef(), pLightFrame->Release()) == 1);

	// pLight ref count is now 2
	assert((pLight->AddRef(), pLight->Release()) == 2);

	// Release() pLight so it gets deleted when pLightFrame is Release()
	pLight->Release();

	rpLight = pLightFrame;

	return result;
}

// FUNCTION: BETA10 0x1016d4e0
inline Result RendererImpl::CreateLight(LightType type, float r, float g, float b, LightImpl& rLight)
{
	assert(m_data);
	assert(!rLight.ImplementationData());

	return RendererCreateLight(m_data, type, r, g, b, rLight.ImplementationData());
}

// FUNCTION: LEGO1 0x100a1cf0
// FUNCTION: BETA10 0x1016aa90
Light* RendererImpl::CreateLight(LightType type, float r, float g, float b)
{
	assert(m_data);

	LightImpl* pLightImpl = new LightImpl;

	if (!CreateLight(type, r, g, b, *pLightImpl)) {
		delete pLightImpl;
		pLightImpl = 0;
	}

	return pLightImpl;
}

// FUNCTION: BETA10 0x1016d8e0
inline Result RendererCreateMeshBuilder(IDirect3DRM2* pD3DRM, IDirect3DRMMesh*& rpMesh)
{
	return ResultVal(pD3DRM->CreateMesh(&rpMesh));
}

// FUNCTION: BETA10 0x1016d850
inline Result RendererImpl::CreateMeshBuilder(MeshBuilderImpl& rMesh)
{
	assert(m_data);
	assert(!rMesh.ImplementationData());

	return RendererCreateMeshBuilder(m_data, rMesh.ImplementationData());
}

// FUNCTION: LEGO1 0x100a1e90
// FUNCTION: BETA10 0x1016abf0
MeshBuilder* RendererImpl::CreateMeshBuilder()
{
	assert(m_data);
	MeshBuilderImpl* meshBuilder = new MeshBuilderImpl();

	if (!CreateMeshBuilder(*static_cast<MeshBuilderImpl*>(meshBuilder))) {
		delete meshBuilder;
		meshBuilder = NULL;
	}

	return meshBuilder;
}

inline Result RendererCreateTexture(
	IDirect3DRM2* renderer,
	IDirect3DRMTexture*& texture,
	int width,
	int height,
	int bytesPerPixel,
	void* pBuffer,
	int useBuffer,
	int paletteSize,
	PaletteEntry* pEntries
)
{
	TglD3DRMIMAGE* image;
	Result result;

	image = new TglD3DRMIMAGE(width, height, bytesPerPixel, pBuffer, useBuffer, paletteSize, pEntries);
	// TODO: LPDIRECT3DRMTEXTURE2?
	result = ResultVal(renderer->CreateTexture(&image->m_image, (LPDIRECT3DRMTEXTURE2*) &texture));
	if (Succeeded(result)) {
		result = TextureImpl::SetImage(texture, image);
		if (!Succeeded(result)) {
			texture->Release();
			texture = NULL;
			delete image;
		}
	}
	else {
		delete image;
	}
	return result;
}

// FUNCTION: LEGO1 0x100a1f50
Texture* RendererImpl::CreateTexture(
	int width,
	int height,
	int bitsPerTexel,
	const void* pTexels,
	int texelsArePersistent,
	int paletteEntryCount,
	const PaletteEntry* pEntries
)
{
	TextureImpl* texture = new TextureImpl();
	if (!Succeeded(RendererCreateTexture(
			m_data,
			texture->m_data,
			width,
			height,
			bitsPerTexel,
			const_cast<void*>(pTexels),
			texelsArePersistent,
			paletteEntryCount,
			const_cast<PaletteEntry*>(pEntries)
		))) {
		delete texture;
		texture = NULL;
	}
	return texture;
}

// FUNCTION: LEGO1 0x100a20d0
Texture* RendererImpl::CreateTexture()
{
	TextureImpl* texture = new TextureImpl();
	if (!Succeeded(RendererCreateTexture(m_data, texture->m_data, 0, 0, 0, NULL, FALSE, 0, NULL))) {
		delete texture;
		texture = NULL;
	}
	return texture;
}

// FUNCTION: LEGO1 0x100a2270
Result RendererImpl::SetTextureDefaultShadeCount(unsigned long shadeCount)
{
	return ResultVal(m_data->SetDefaultTextureShades(shadeCount));
}

// FUNCTION: LEGO1 0x100a2290
Result RendererImpl::SetTextureDefaultColorCount(unsigned long colorCount)
{
	return ResultVal(m_data->SetDefaultTextureColors(colorCount));
}

// FUNCTION: LEGO1 0x100a22b0
// FUNCTION: BETA10 0x1016b050
void* RendererImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}
