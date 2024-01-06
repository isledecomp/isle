#include "impl.h"

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

// FUNCTION: LEGO1 0x100a1894
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

// GLOBAL: LEGO1 0x10101040
static int g_SetBufferCount = 1;

// FUNCTION: LEGO1 0x100a1900
Device* RendererImpl::CreateDevice(const DeviceDirectDrawCreateData& data)
{
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

inline Result RendererCreateView(
	IDirect3DRM2* pRenderer,
	IDirect3DRMDevice2* pDevice,
	IDirect3DRMFrame2* pCamera,
	IDirect3DRMViewport*& rpView,
	unsigned long x,
	unsigned long y,
	unsigned long width,
	unsigned long height
)
{
	Result result = ResultVal(pRenderer->CreateViewport(pDevice, pCamera, x, y, width, height, &rpView));
	if (Succeeded(result)) {
		result = ViewImpl::ViewportCreateAppData(pRenderer, rpView, pCamera);
		if (!Succeeded(result)) {
			rpView->Release();
			rpView = NULL;
		}
	}
	return result;
}

// FUNCTION: LEGO1 0x100a1a00
View* RendererImpl::CreateView(
	const Device* pDevice,
	const Camera* pCamera,
	unsigned long x,
	unsigned long y,
	unsigned long width,
	unsigned long height
)
{
	ViewImpl* view = new ViewImpl();
	Result result = RendererCreateView(
		m_data,
		static_cast<const DeviceImpl*>(pDevice)->m_data,
		static_cast<const CameraImpl*>(pCamera)->m_data,
		view->m_data,
		x,
		y,
		width,
		height
	);
	if (!result) {
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

// FUNCTION: LEGO1 0x100a1cf0
Light* RendererImpl::CreateLight(LightType type, float r, float g, float b)
{
	LightImpl* newLight = new LightImpl();
	D3DRMLIGHTTYPE translatedType;
	switch (type) {
	case Ambient:
		translatedType = D3DRMLIGHT_AMBIENT;
		break;
	case Point:
		translatedType = D3DRMLIGHT_POINT;
		break;
	case Spot:
		translatedType = D3DRMLIGHT_SPOT;
		break;
	case Directional:
		translatedType = D3DRMLIGHT_DIRECTIONAL;
		break;
	case ParallelPoint:
		translatedType = D3DRMLIGHT_PARALLELPOINT;
		break;
	default:
		translatedType = D3DRMLIGHT_AMBIENT;
	}

	LPDIRECT3DRMFRAME2 frame;
	Result result = ResultVal(m_data->CreateFrame(NULL, &frame));
	if (Succeeded(result)) {
		LPDIRECT3DRMLIGHT d3dLight;
		result = ResultVal(m_data->CreateLightRGB(translatedType, r, g, b, &d3dLight));
		if (!Succeeded(result)) {
			frame->Release();
		}
		else {
			result = ResultVal(frame->AddLight(d3dLight));
			if (!Succeeded(result)) {
				d3dLight->Release();
				frame->Release();
			}
			else {
				d3dLight->Release();
				newLight->m_data = frame;
			}
		}
	}
	if (!Succeeded(result)) {
		delete newLight;
		newLight = NULL;
	}
	return newLight;
}

// FUNCTION: LEGO1 0x100a1e90
Unk* RendererImpl::CreateUnk()
{
	// Note: I'm fairly certain that Unknown is not what Tgl calls a
	// "Mesh", because the methods on Mesh in the Tgl leak line up much
	// more closely with a different vtable than the one assigned in
	// this method (meaning this method is not creating a Mesh).
	// Maybe this method is something like CreateMeshBuilder where the
	// Mesh data type in the Tgl leak was split into builder/result?
	UnkImpl* unknown = new UnkImpl();
	if (FAILED(m_data->CreateMesh(&unknown->m_data))) {
		delete unknown;
		unknown = NULL;
	}
	return unknown;
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
void* RendererImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}
