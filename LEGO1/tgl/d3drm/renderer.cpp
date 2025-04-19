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

// FUNCTION: BETA10 0x1016cf00
inline Result RendererCreateDevice(
	IDirect3DRM2* pD3DRM,
	const DeviceDirect3DCreateData& rCreateData,
	IDirect3DRMDevice2*& rpDevice
)
{
	Result result =
		ResultVal(pD3DRM->CreateDeviceFromD3D(rCreateData.m_pDirect3D, rCreateData.m_pDirect3DDevice, &rpDevice));
	return result;
}

// FUNCTION: BETA10 0x1016ce60
inline Result RendererImpl::CreateDevice(const DeviceDirect3DCreateData& rCreateData, DeviceImpl& rDevice)
{
	assert(m_data);
	assert(!rDevice.ImplementationData());

	return RendererCreateDevice(m_data, rCreateData, rDevice.ImplementationData());
}

// FUNCTION: LEGO1 0x100a1830
// FUNCTION: BETA10 0x10169d90
Device* RendererImpl::CreateDevice(const DeviceDirect3DCreateData& data)
{
	assert(m_data);
	DeviceImpl* device = new DeviceImpl();

	if (!CreateDevice(data, *device)) {
		delete device;
		device = NULL;
	}

	return device;
}

// FUNCTION: BETA10 0x1016cfe0
inline Result RendererCreateDevice(
	IDirect3DRM2* pD3DRM,
	const DeviceDirectDrawCreateData& rCreateData,
	IDirect3DRMDevice2*& rpDevice
)
{
	Result result = ResultVal(pD3DRM->CreateDeviceFromSurface(
		const_cast<GUID*>(rCreateData.m_driverGUID),
		rCreateData.m_pDirectDraw,
		rCreateData.m_pBackBuffer,
		&rpDevice
	));

	if (Succeeded(result)) {
		if (rCreateData.m_pBackBuffer) {
			// LEGO1 0x10101040
			// GLOBAL: BETA10 0x102055f4
			static int g_setBufferCount = 1;
			if (g_setBufferCount) {
				Result result2 = ResultVal(rpDevice->SetBufferCount(2));
				assert(Succeeded(result));
			}
		}
	}

	return result;
}

// FUNCTION: BETA10 0x1016cf40
inline Result RendererImpl::CreateDevice(const DeviceDirectDrawCreateData& rCreateData, DeviceImpl& rDevice)
{
	assert(m_data);
	assert(!rDevice.ImplementationData());

	return RendererCreateDevice(m_data, rCreateData, rDevice.ImplementationData());
}

// FUNCTION: LEGO1 0x100a1900
// FUNCTION: BETA10 0x10169ea0
Device* RendererImpl::CreateDevice(const DeviceDirectDrawCreateData& data)
{
	assert(m_data);
	DeviceImpl* device = new DeviceImpl();

	if (!CreateDevice(data, *device)) {
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

// FUNCTION: BETA10 0x1016d4b0
inline Result RendererCreateCamera(IDirect3DRM2* pD3DRM, IDirect3DRMFrame2*& rpCamera)
{
	return ResultVal(pD3DRM->CreateFrame(NULL, &rpCamera));
}

// FUNCTION: BETA10 0x1016d420
inline Result RendererImpl::CreateCamera(CameraImpl& rCamera)
{
	assert(m_data);
	assert(!rCamera.ImplementationData());

	return RendererCreateCamera(m_data, rCamera.ImplementationData());
}

// FUNCTION: LEGO1 0x100a1c30
// FUNCTION: BETA10 0x1016a980
Camera* RendererImpl::CreateCamera()
{
	assert(m_data);
	CameraImpl* camera = new CameraImpl();

	if (!CreateCamera(*camera)) {
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

// FUNCTION: BETA10 0x1016d9c0
inline Result RendererCreateTexture(
	IDirect3DRM2* pRenderer,
	int width,
	int height,
	int bytesPerPixel,
	void* pBuffer,
	int useBuffer,
	int paletteSize,
	PaletteEntry* pEntries,
	IDirect3DRMTexture*& rpTexture
)
{
	Result result;

	TglD3DRMIMAGE* pImage = new TglD3DRMIMAGE(width, height, bytesPerPixel, pBuffer, useBuffer, paletteSize, pEntries);
	assert(pImage);

	// TODO: LPDIRECT3DRMTEXTURE2?
	result = ResultVal(pRenderer->CreateTexture(&pImage->m_image, (LPDIRECT3DRMTEXTURE2*) &rpTexture));
	assert(Succeeded(result));
	assert((rpTexture->AddRef(), rpTexture->Release()) == 1);

	if (Succeeded(result)) {
		result = TextureImpl::SetImage(rpTexture, pImage);
		assert(Succeeded(result));

		if (!Succeeded(result)) {
			rpTexture->Release();
			rpTexture = NULL;
			delete pImage;
		}
	}
	else {
		delete pImage;
	}

	return result;
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

// FUNCTION: LEGO1 0x100a1f50
// FUNCTION: BETA10 0x1016ad00
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

// FUNCTION: BETA10 0x1016dcb0
inline Result RendererCreateTexture(IDirect3DRM2* pRenderer, IDirect3DRMTexture*& rpTexture)
{
	return RendererCreateTexture(pRenderer, 0, 0, 0, NULL, FALSE, 0, NULL, rpTexture);
}

// FUNCTION: BETA10 0x1016dc20
inline Result RendererImpl::CreateTexture(TextureImpl& rTexture)
{
	assert(m_data);
	assert(!rTexture.ImplementationData());

	return RendererCreateTexture(m_data, rTexture.ImplementationData());
}

// FUNCTION: LEGO1 0x100a20d0
// FUNCTION: BETA10 0x1016ae20
Texture* RendererImpl::CreateTexture()
{
	assert(m_data);

	TextureImpl* texture = new TextureImpl();
	if (!CreateTexture(*texture)) {
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
