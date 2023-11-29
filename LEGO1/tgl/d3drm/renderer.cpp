#include "impl.h"

using namespace TglImpl;

// OFFSET: LEGO1 0x100a15e0
Renderer* CreateRenderer()
{
	RendererImpl* renderer = new RendererImpl();
	if (!renderer->Create()) {
		delete renderer;
		renderer = NULL;
	}
	return renderer;
}

// OFFSET: LEGO1 0x1010103c
IDirect3DRM* g_pD3DRM = NULL;

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

// Inlined only
void RendererImpl::Destroy()
{
	if (m_data) {
		if (m_data->Release() == 0)
			g_pD3DRM = NULL;
		m_data = NULL;
	}
}

// OFFSET: LEGO1 0x100a22b0
void* RendererImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}

// OFFSET: LEGO1 0x100a1894
Device* RendererImpl::CreateDevice(const DeviceDirect3DCreateData& p_data)
{
	DeviceImpl* device = new DeviceImpl();
	HRESULT result = m_data->CreateDeviceFromD3D(p_data.m_pDirect3D, p_data.m_pDirect3DDevice, &device->m_data);
	if (!SUCCEEDED(result)) {
		delete device;
		device = NULL;
	}
	return device;
}

// OFFSET: LEGO1 0x10101040
static int gSetBufferCount = 1;

// OFFSET: LEGO1 0x100a1900
Device* RendererImpl::CreateDevice(const DeviceDirectDrawCreateData& p_data)
{
	DeviceImpl* device = new DeviceImpl();
	HRESULT result = m_data->CreateDeviceFromSurface(
		const_cast<LPGUID>(p_data.m_driverGUID),
		p_data.m_pDirectDraw,
		p_data.m_pBackBuffer,
		&device->m_data
	);
	if (SUCCEEDED(result) && p_data.m_pBackBuffer && gSetBufferCount) {
		device->m_data->SetBufferCount(2);
	}
	if (!SUCCEEDED(result)) {
		delete device;
		device = NULL;
	}
	return device;
}

inline Result RendererCreateView(
	IDirect3DRM* p_renderer,
	IDirect3DRMDevice* p_device,
	IDirect3DRMFrame* p_camera,
	IDirect3DRMViewport*& p_view,
	unsigned long p_x,
	unsigned long p_y,
	unsigned long p_width,
	unsigned long p_height
)
{
	Result result = ResultVal(p_renderer->CreateViewport(p_device, p_camera, p_x, p_y, p_width, p_height, &p_view));
	if (Succeeded(result)) {
		result = ViewImpl::ViewportCreateAppData(p_renderer, p_view, p_camera);
		if (!Succeeded(result)) {
			p_view->Release();
			p_view = NULL;
		}
	}
	return result;
}

// OFFSET: LEGO1 0x100a1a00
View* RendererImpl::CreateView(
	const Device* p_device,
	const Camera* p_camera,
	unsigned long p_x,
	unsigned long p_y,
	unsigned long p_width,
	unsigned long p_height
)
{
	ViewImpl* view = new ViewImpl();
	Result result = RendererCreateView(
		m_data,
		static_cast<const DeviceImpl*>(p_device)->m_data,
		static_cast<const CameraImpl*>(p_camera)->m_data,
		view->m_data,
		p_x,
		p_y,
		p_width,
		p_height
	);
	if (!result) {
		delete view;
		view = NULL;
	}
	return view;
}

// OFFSET: LEGO1 0x100a1c30
Camera* RendererImpl::CreateCamera()
{
	CameraImpl* camera = new CameraImpl();
	if (FAILED(m_data->CreateFrame(NULL, &camera->m_data))) {
		delete camera;
		camera = NULL;
	}
	return camera;
}

// OFFSET: LEGO1 0x100a1cf0
Light* RendererImpl::CreateLight(LightType p_type, float p_r, float p_g, float p_b)
{
	LightImpl* newLight = new LightImpl();
	D3DRMLIGHTTYPE translatedType;
	switch (p_type) {
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

	LPDIRECT3DRMFRAME frame;
	Result result = ResultVal(m_data->CreateFrame(NULL, &frame));
	if (Succeeded(result)) {
		LPDIRECT3DRMLIGHT d3dLight;
		result = ResultVal(m_data->CreateLightRGB(translatedType, p_r, p_g, p_b, &d3dLight));
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

inline Result RendererCreateGroup(IDirect3DRM* p_renderer, IDirect3DRMFrame* p_parent, IDirect3DRMFrame*& p_group)
{
	Result result = ResultVal(p_renderer->CreateFrame(NULL, &p_group));
	if (Succeeded(result) && p_parent) {
		result = ResultVal(p_parent->AddVisual(p_group));
		if (!Succeeded(result)) {
			p_group->Release();
			p_group = NULL;
		}
	}
	return result;
}

// OFFSET: LEGO1 0x100a1b20
Group* RendererImpl::CreateGroup(const Group* p_parent)
{
	GroupImpl* group = new GroupImpl();
	Result result =
		RendererCreateGroup(m_data, p_parent ? static_cast<const GroupImpl*>(p_parent)->m_data : NULL, group->m_data);
	if (!result) {
		delete group;
		group = NULL;
	}
	return group;
}

// OFFSET: LEGO1 0x100a1e90
Something* RendererImpl::CreateSomething()
{
	// Note: I'm fairly certain that Something is not what Tgl calls a
	// "Mesh", because the methods on Mesh in the Tgl leak line up much
	// more closely with a different vtable than the one assigned in
	// this method (meaning this method is not creating a Mesh).
	// Maybe this method is something like CreateMeshBuilder where the
	// Mesh data type in the Tgl leak was split into builder/result?
	SomethingImpl* something = new SomethingImpl();
	if (FAILED(m_data->CreateMesh(&something->m_data))) {
		delete something;
		something = NULL;
	}
	return something;
}

inline Result RendererCreateTexture(
	IDirect3DRM* p_renderer,
	IDirect3DRMTexture*& p_texture,
	int p_width,
	int p_height,
	int p_bytesPerPixel,
	void* p_buffer,
	int p_useBuffer,
	int p_paletteSize,
	PaletteEntry* p_palette
)
{
	TglD3DRMIMAGE* image;
	Result result;

	image = new TglD3DRMIMAGE(p_width, p_height, p_bytesPerPixel, p_buffer, p_useBuffer, p_paletteSize, p_palette);
	result = ResultVal(p_renderer->CreateTexture(&image->m_image, &p_texture));
	if (Succeeded(result)) {
		result = TextureImpl::SetImage(p_texture, image);
		if (!Succeeded(result)) {
			p_texture->Release();
			p_texture = NULL;
			delete image;
		}
	}
	else {
		delete image;
	}
	return result;
}

// OFFSET: LEGO1 0x100a20d0
Texture* RendererImpl::CreateTexture()
{
	TextureImpl* texture = new TextureImpl();
	if (!Succeeded(RendererCreateTexture(m_data, texture->m_data, 0, 0, 0, NULL, FALSE, 0, NULL))) {
		delete texture;
		texture = NULL;
	}
	return texture;
}

// OFFSET: LEGO1 0x100a1f50
Texture* RendererImpl::CreateTexture(
	int p_width,
	int p_height,
	int p_bitsPerTexel,
	const void* p_pTexels,
	int p_texelsArePersistent,
	int p_paletteEntryCount,
	const PaletteEntry* p_pEntries
)
{
	TextureImpl* texture = new TextureImpl();
	if (!Succeeded(RendererCreateTexture(
			m_data,
			texture->m_data,
			p_width,
			p_height,
			p_bitsPerTexel,
			const_cast<void*>(p_pTexels),
			p_texelsArePersistent,
			p_paletteEntryCount,
			const_cast<PaletteEntry*>(p_pEntries)
		))) {
		delete texture;
		texture = NULL;
	}
	return texture;
}

// OFFSET: LEGO1 0x100a2270
Result RendererImpl::SetTextureDefaultShadeCount(unsigned long p_shadeCount)
{
	return ResultVal(m_data->SetDefaultTextureShades(p_shadeCount));
}

// OFFSET: LEGO1 0x100a2290
Result RendererImpl::SetTextureDefaultColorCount(unsigned long p_colorCount)
{
	return ResultVal(m_data->SetDefaultTextureColors(p_colorCount));
}
