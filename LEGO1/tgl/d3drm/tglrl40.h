#ifndef TGL_D3DRM_TGLRL40_H
#define TGL_D3DRM_TGLRL40_H

// Record carriers (scaffolding): 21 units seated ahead of tglImpl.h so the
// deferred inline bodies below land on the 1997 register schedule.
class MxUnkRecordTGH00;
class MxUnkRecordTGH01;
class MxUnkRecordTGH02;
class MxUnkRecordTGH03;
class MxUnkRecordTGH04;
class MxUnkRecordTGH05;
class MxUnkRecordTGH06;
class MxUnkRecordTGH07;
class MxUnkRecordTGH08;
class MxUnkRecordTGH09;
class MxUnkRecordTGH10;
class MxUnkRecordTGH11;
class MxUnkRecordTGH12;
class MxUnkRecordTGH13;
class MxUnkRecordTGH14;
class MxUnkRecordTGH15;
class MxUnkRecordTGH16;
class MxUnkRecordTGH17;
class MxUnkRecordTGH18;
class MxUnkRecordTGH19;
class MxUnkRecordTGH20;

class MxUnkRecordPre00;
class MxUnkRecordPre01;
class MxUnkRecordPre02;
class MxUnkRecordPre03;
class MxUnkRecordPre04;
#include "tglimpl.h"

#include <d3drmwin.h>

// The D3D Retained Mode 4.0 implementation layer. BETA10 stores every assert
// of these helpers with the file name tglRL40.h and a line number; the bodies
// below follow that line order. The companion translation unit is tglrl40.cpp.

// Global scope: legovideomanager.h forward-declares ViewportAppData and
// legovideomanager.cpp links against ::ViewportDestroyCallback, matching the
// unqualified 1997 manglings.
struct ViewportAppData {
	ViewportAppData(IDirect3DRM2* pRenderer);
	~ViewportAppData();

	IDirect3DRMFrame2* m_pLightFrame;
	IDirect3DRMFrame2* m_pCamera;
	IDirect3DRMFrame2* m_pLastRenderedFrame;
	float m_backgroundColorRed;
	float m_backgroundColorGreen;
	float m_backgroundColorBlue;

	// SYNTHETIC: BETA10 0x10169960
	// ViewportAppData::`scalar deleting destructor'
};

// Forward declare to satisfy order check
void ViewportDestroyCallback(IDirect3DRMObject* pObject, void* pArg);
void TextureDestroyCallback(IDirect3DRMObject* pObject, void* pArg);

namespace TglImpl
{

// Utility function used by implementations
// FUNCTION: BETA10 0x10169cf0
inline Result ResultVal(HRESULT result)
{
	return SUCCEEDED(result) ? Success : Error;
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
// FUNCTION: BETA10 0x1016fa10
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

// FUNCTION: BETA10 0x101702e0
inline D3DRMMATERIALMODE Translate(MaterialMode mode)
{
	D3DRMMATERIALMODE d3dMode;
	switch (mode) {
	case FromParent:
		d3dMode = D3DRMMATERIAL_FROMPARENT;
		break;
	case FromFrame:
		d3dMode = D3DRMMATERIAL_FROMFRAME;
		break;
	case FromMesh:
		d3dMode = D3DRMMATERIAL_FROMMESH;
		break;
	}
	return d3dMode;
}

// Used by both Mesh and MeshBuilder
// FUNCTION: BETA10 0x10170270
inline Result MeshSetTextureMappingMode(MeshImpl::MeshData* pMesh, TextureMappingMode mode)
{
	if (mode == PerspectiveCorrect) {
		return ResultVal(pMesh->groupMesh->SetGroupMapping(pMesh->groupIndex, D3DRMMAP_PERSPCORRECT));
	}
	else {
		return ResultVal(pMesh->groupMesh->SetGroupMapping(pMesh->groupIndex, 0));
	}
}

// Forward declare to satisfy order check
inline IDirect3DRMFrame* ViewportGetLightFrame(IDirect3DRMViewport* pViewport);
inline Result ViewPrepareFrameForRender(
	IDirect3DRMFrame* pFrame,
	IDirect3DRMFrame* pCamera,
	IDirect3DRMFrame* pLightFrame,
	float backgroundRed,
	float backgroundGreen,
	float backgroundBlue
);
inline Result ViewRestoreFrameAfterRender(
	IDirect3DRMFrame* pFrame,
	IDirect3DRMFrame* pCamera,
	IDirect3DRMFrame* pLightFrame
);

// BETA10 asserts place this member at tglRL40.h L312-L313, including the
// original name of the renderer singleton: assert((g_pTheRenderer->AddRef(),
// g_pTheRenderer->Release()) == 1). The Succeeded(result) capture that feeds
// the L312 assert does not survive NDEBUG cleanly, so the asserts are not
// restored here yet.
inline Result RendererImpl::Create()
{
	if (g_pTheRenderer) {
		g_pTheRenderer->AddRef();
	}
	else {
		LPDIRECT3DRM handle;
		Direct3DRMCreate(&handle);
		handle->QueryInterface(IID_IDirect3DRM2, (LPVOID*) &g_pTheRenderer);
	}
	m_data = g_pTheRenderer;
	return (m_data != NULL) ? Success : Error;
}

// FUNCTION: BETA10 0x1016dd20
inline void RendererDestroy(IDirect3DRM2* pRenderer)
{
	int refCount = pRenderer->Release();
	assert(refCount == 0);
	if (refCount <= 0) {
		g_pTheRenderer = NULL;
	}
}

// FUNCTION: BETA10 0x1016dce0
inline void RendererImpl::Destroy()
{
	if (m_data) {
		RendererDestroy(m_data);
		m_data = NULL;
	}
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
			// annotated below
			static int g_setBufferCount = 1;
			if (g_setBufferCount) {
				Result result2 = ResultVal(rpDevice->SetBufferCount(2));
				assert(Succeeded(result));
			}
		}
	}

	return result;
}

// GLOBAL: LEGO1 0x10101040
// GLOBAL: BETA10 0x102055f4
// ?g_setBufferCount@?3??RendererCreateDevice@@YA?AW4Result@Tgl@@PAUIDirect3DRM2@@ABUDeviceDirectDrawCreateData@3@AAPAUIDirect3DRMDevice2@@@Z@4HA

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

// FUNCTION: BETA10 0x1016d380
inline Result RendererCreateGroup(
	IDirect3DRM2* pRenderer,
	const IDirect3DRMFrame2* pParent,
	IDirect3DRMFrame2*& rpGroup
)
{
	Result result = ResultVal(pRenderer->CreateFrame(NULL, &rpGroup));
	if (Succeeded(result) && pParent) {
		result = ResultVal(const_cast<IDirect3DRMFrame2*>(pParent)->AddVisual(rpGroup));
		if (!Succeeded(result)) {
			rpGroup->Release();
			rpGroup = NULL;
		}
	}
	return result;
}

// FUNCTION: BETA10 0x1016d4b0
inline Result RendererCreateCamera(IDirect3DRM2* pD3DRM, IDirect3DRMFrame2*& rpCamera)
{
	return ResultVal(pD3DRM->CreateFrame(NULL, &rpCamera));
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

// FUNCTION: BETA10 0x1016d8e0
inline Result RendererCreateMeshBuilder(IDirect3DRM2* pD3DRM, IDirect3DRMMesh*& rpMesh)
{
	return ResultVal(pD3DRM->CreateMesh(&rpMesh));
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

	Image* pImage = new Image(width, height, bytesPerPixel, pBuffer, useBuffer, paletteSize, pEntries);
	assert(pImage);

	// TODO: LPDIRECT3DRMTEXTURE2?
	result = ResultVal(pRenderer->CreateTexture(pImage, (LPDIRECT3DRMTEXTURE2*) &rpTexture));
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

// FUNCTION: BETA10 0x1016dcb0
inline Result RendererCreateTexture(IDirect3DRM2* pRenderer, IDirect3DRMTexture*& rpTexture)
{
	return RendererCreateTexture(pRenderer, 0, 0, 0, NULL, FALSE, 0, NULL, rpTexture);
}

// FUNCTION: BETA10 0x1016af90
inline Result RendererSetTextureDefaultShadeCount(IDirect3DRM2* pRenderer, unsigned long shadeCount)
{
	return ResultVal(pRenderer->SetDefaultTextureShades(shadeCount));
}

// FUNCTION: BETA10 0x1016b020
inline Result RendererSetTextureDefaultColorCount(IDirect3DRM2* pRenderer, unsigned long colorCount)
{
	return ResultVal(pRenderer->SetDefaultTextureColors(colorCount));
}

// FUNCTION: BETA10 0x1016dfa0
inline Result DeviceSetColorModel(IDirect3DRMDevice2* pDevice, ColorModel)
{
	return Success;
}

// FUNCTION: BETA10 0x1016e020
inline Result DeviceSetShadingModel(IDirect3DRMDevice2* pDevice, ShadingModel model)
{
	D3DRMRENDERQUALITY renderQuality = Translate(model);
	return ResultVal(pDevice->SetQuality(renderQuality));
}

// FUNCTION: BETA10 0x1016e140
inline Result DeviceSetShadeCount(IDirect3DRMDevice2* pDevice, unsigned long shadeCount)
{
	return ResultVal(pDevice->SetShades(shadeCount));
}

// FUNCTION: BETA10 0x1016e1d0
inline Result DeviceSetDither(IDirect3DRMDevice2* pDevice, int dither)
{
	return ResultVal(pDevice->SetDither(dither));
}

// FUNCTION: BETA10 0x1016dea0
inline unsigned long DeviceGetWidth(IDirect3DRMDevice2* pDevice)
{
	return pDevice->GetWidth();
}

// FUNCTION: BETA10 0x1016df20
inline unsigned long DeviceGetHeight(IDirect3DRMDevice2* pDevice)
{
	return pDevice->GetHeight();
}

// FUNCTION: BETA10 0x1016e460
inline Result DeviceUpdate(IDirect3DRMDevice2* pDevice)
{
	return ResultVal(pDevice->Update());
}

// FUNCTION: BETA10 0x1016e4f0
// BETA10 places this at tglRL40.h L688-L697. The two asserts it records at
// L692 and L697 are both assert(Succeeded(result)): one status check after
// fetching the Direct3D device and one after reading the stats.
inline unsigned long DeviceGetTrianglesDrawn(IDirect3DRMDevice2* pDevice)
{
	IDirect3DDevice2* pD3DDevice;
	Result result = ResultVal(pDevice->GetDirect3DDevice2(&pD3DDevice));
	assert(Succeeded(result));

	D3DSTATS stats;
	memset(&stats, 0, sizeof(stats));
	stats.dwSize = sizeof(stats);
	result = ResultVal(pD3DDevice->GetStats(&stats));
	assert(Succeeded(result));

	pD3DDevice->Release();

	return stats.dwTrianglesDrawn;
}

// FUNCTION: BETA10 0x1016e260
inline void DeviceHandleActivate(IDirect3DRMDevice2* pDevice, WORD wParam)
{
	IDirect3DRMWinDevice* winDevice;

	Result result = ResultVal(pDevice->QueryInterface(IID_IDirect3DRMWinDevice, (LPVOID*) &winDevice));
	if (Succeeded(result)) {
		winDevice->HandleActivate(wParam);
		int refCount = winDevice->Release();
		assert(refCount == 1);
	}
}

// GLOBAL: LEGO1 0x100dd1d0
// GLOBAL: BETA10 0x101c30b0
// IID_IDirect3DRMWinDevice

// FUNCTION: BETA10 0x1016e360
inline void DeviceHandlePaint(IDirect3DRMDevice2* pDevice, void* p_data)
{
	IDirect3DRMWinDevice* winDevice;

	Result result = ResultVal(pDevice->QueryInterface(IID_IDirect3DRMWinDevice, (LPVOID*) &winDevice));
	if (Succeeded(result)) {
		HDC hdc = (HDC) p_data;
		winDevice->HandlePaint(hdc);
		int refCount = winDevice->Release();
		assert(refCount == 1);
	}
}

// FUNCTION: BETA10 0x101708c0
inline void DeviceDestroy(IDirect3DRMDevice2* pDevice)
{
	pDevice->Release();
}

// FUNCTION: BETA10 0x10170880
inline void DeviceImpl::Destroy()
{
	if (m_data) {
		DeviceDestroy(m_data);
		m_data = NULL;
	}
}

// FUNCTION: BETA10 0x1016e870
inline Result ViewSetProjection(IDirect3DRMViewport* pViewport, ProjectionType type)
{
	D3DRMPROJECTIONTYPE projectionType = Translate(type);

	return ResultVal(pViewport->SetProjection(projectionType));
}

// FUNCTION: BETA10 0x1016e920
inline Result ViewSetFrustrum(
	IDirect3DRMViewport* pViewport,
	float frontClippingDistance,
	float backClippingDistance,
	float degrees
)
{
	float field = frontClippingDistance * tan(DegreesToRadians(degrees / 2));
	Result result;
	result = ResultVal(pViewport->SetFront(frontClippingDistance));
	if (Succeeded(result)) {
		result = ResultVal(pViewport->SetBack(backClippingDistance));
	}
	if (Succeeded(result)) {
		result = ResultVal(pViewport->SetField(field));
	}

	return result;
}

// FUNCTION: BETA10 0x1016ea70
inline Result ViewSetBackgroundColor(IDirect3DRMViewport* pViewport, float r, float g, float b)
{
	Result result = Success;

	ViewportAppData* pViewportAppData = reinterpret_cast<ViewportAppData*>(pViewport->GetAppData());
	assert(pViewportAppData);

	pViewportAppData->m_backgroundColorRed = r;
	pViewportAppData->m_backgroundColorGreen = g;
	pViewportAppData->m_backgroundColorBlue = b;

	if (pViewportAppData->m_pLastRenderedFrame) {
		result = ResultVal(pViewportAppData->m_pLastRenderedFrame->SetSceneBackgroundRGB(r, g, b));
		assert(Succeeded(result));
	}

	return result;
}

// FUNCTION: BETA10 0x1016ebd0
inline Result ViewGetBackgroundColor(IDirect3DRMViewport* pViewport, float* r, float* g, float* b)
{
	ViewportAppData* pViewportAppData = reinterpret_cast<ViewportAppData*>(pViewport->GetAppData());
	assert(pViewportAppData);

	*r = pViewportAppData->m_backgroundColorRed;
	*g = pViewportAppData->m_backgroundColorGreen;
	*b = pViewportAppData->m_backgroundColorBlue;

	return Success;
}

// FUNCTION: BETA10 0x10170cc0
inline Result ViewSetCamera(IDirect3DRMViewport* pViewport, const IDirect3DRMFrame2* pCamera)
{
	ViewportAppData* pViewportAppData;
	Result result;

	pViewportAppData = reinterpret_cast<ViewportAppData*>(pViewport->GetAppData());
	assert(pViewportAppData);

	result = ViewRestoreFrameAfterRender(
		pViewportAppData->m_pLastRenderedFrame,
		pViewportAppData->m_pCamera,
		pViewportAppData->m_pLightFrame
	);
	assert(Succeeded(result));
	pViewportAppData->m_pCamera = const_cast<IDirect3DRMFrame2*>(pCamera);
	pViewportAppData->m_pLastRenderedFrame = 0;

	return ResultVal(pViewport->SetCamera(const_cast<IDirect3DRMFrame2*>(pCamera)));
}

// FUNCTION: BETA10 0x10170a40
inline Result ViewAddLight(IDirect3DRMViewport* pViewport, const IDirect3DRMFrame* pLight)
{
	IDirect3DRMFrame* pLightFrame = ViewportGetLightFrame(pViewport);

	assert(pLightFrame);
	return ResultVal(pLightFrame->AddChild(const_cast<IDirect3DRMFrame*>(pLight)));
}

// FUNCTION: BETA10 0x10170bb0
inline Result ViewRemoveLight(IDirect3DRMViewport* pViewport, const IDirect3DRMFrame* pLight)
{
	IDirect3DRMFrame* pLightFrame = ViewportGetLightFrame(pViewport);

	assert(pLightFrame);
	return ResultVal(pLightFrame->DeleteChild(const_cast<IDirect3DRMFrame*>(pLight)));
}

// FUNCTION: BETA10 0x10170e30
inline Result ViewRender(IDirect3DRMViewport* pViewport, const IDirect3DRMFrame2* pGroup)
{
	ViewportAppData* pViewportAppData;
	Result result;

	pViewportAppData = reinterpret_cast<ViewportAppData*>(pViewport->GetAppData());
	assert(pViewportAppData);

	if (pViewportAppData->m_pLastRenderedFrame != pGroup) {
		result = ViewRestoreFrameAfterRender(
			pViewportAppData->m_pLastRenderedFrame,
			pViewportAppData->m_pCamera,
			pViewportAppData->m_pLightFrame
		);

		assert(Succeeded(result));

		pViewportAppData->m_pLastRenderedFrame = const_cast<IDirect3DRMFrame2*>(pGroup);

		result = ViewPrepareFrameForRender(
			pViewportAppData->m_pLastRenderedFrame,
			pViewportAppData->m_pCamera,
			pViewportAppData->m_pLightFrame,
			pViewportAppData->m_backgroundColorRed,
			pViewportAppData->m_backgroundColorGreen,
			pViewportAppData->m_backgroundColorBlue
		);

		assert(Succeeded(result));
	}

	result = ResultVal(pViewport->Render(const_cast<IDirect3DRMFrame2*>(pGroup)));
	assert(Succeeded(result));

	return result;
}

// FUNCTION: BETA10 0x1016ecb0
inline Result ViewClear(IDirect3DRMViewport* pViewport)
{
	return ResultVal(pViewport->Clear());
}

// FUNCTION: BETA10 0x1016edd0
inline Result ViewForceUpdate(
	IDirect3DRMViewport* pViewport,
	unsigned long x,
	unsigned long y,
	unsigned long width,
	unsigned long height
)
{
	return ResultVal(pViewport->ForceUpdate(x, y, x + width - 1, y + height - 1));
}

// FUNCTION: BETA10 0x1016eff0
inline Result ViewTransformWorldToScreen(IDirect3DRMViewport* pViewport, const float world[3], float screen[4])
{
	D3DRMVECTOR4D d3dRMScreen;
	D3DVECTOR d3dRMWorld;
	D3DVECTOR* pD3DRMWorld = Translate(world, d3dRMWorld);
	Result result;

	result = ResultVal(pViewport->Transform(&d3dRMScreen, pD3DRMWorld));

	if (Succeeded(result)) {
		screen[0] = d3dRMScreen.x;
		screen[1] = d3dRMScreen.y;
		screen[2] = d3dRMScreen.z;
		screen[3] = d3dRMScreen.w;
	}

	return result;
}

// FUNCTION: BETA10 0x1016f0d0
inline Result ViewTransformScreenToWorld(IDirect3DRMViewport* pViewport, const float screen[4], float world[3])
{
	D3DVECTOR d3dRMWorld;
	D3DRMVECTOR4D d3dScreen;
	d3dScreen.x = screen[0];
	d3dScreen.y = screen[1];
	d3dScreen.z = screen[2];
	d3dScreen.w = screen[3];
	Result result;

	result = ResultVal(pViewport->InverseTransform(&d3dRMWorld, &d3dScreen));

	if (Succeeded(result)) {
		world[0] = d3dRMWorld.x;
		world[1] = d3dRMWorld.y;
		world[2] = d3dRMWorld.z;
	}

	return result;
}

inline ViewportAppData* ViewportGetData(IDirect3DRMViewport* pViewport)
{
	return reinterpret_cast<ViewportAppData*>(pViewport->GetAppData());
}

// FUNCTION: BETA10 0x10170ab0
inline IDirect3DRMFrame* ViewportGetLightFrame(IDirect3DRMViewport* pViewport)
{
	assert(pViewport->GetAppData());
	return reinterpret_cast<ViewportAppData*>(pViewport->GetAppData())->m_pLightFrame;
}

// FUNCTION: BETA10 0x10170fb0
inline Result ViewPrepareFrameForRender(
	IDirect3DRMFrame* pFrame,
	IDirect3DRMFrame* pCamera,
	IDirect3DRMFrame* pLightFrame,
	float backgroundRed,
	float backgroundGreen,
	float backgroundBlue
)
{
	Result result = Success;

	if (pFrame) {
		// set background color
		result = ResultVal(pFrame->SetSceneBackgroundRGB(backgroundRed, backgroundGreen, backgroundBlue));
		assert(Succeeded(result));

		// add camera to frame to be rendered
		result = ResultVal(pFrame->AddChild(pCamera));
		assert(Succeeded(result));

		// add light frame to frame to be rendered
		result = ResultVal(pFrame->AddChild(pLightFrame));
		assert(Succeeded(result));

		// increase ref count of frame to ensure it does not get deleted underneath us
		pFrame->AddRef();
	}

	return result;
}

// FUNCTION: BETA10 0x1016bd80
inline Result ViewRestoreFrameAfterRender(
	IDirect3DRMFrame* pFrame,
	IDirect3DRMFrame* pCamera,
	IDirect3DRMFrame* pLightFrame
)
{
	Result result = Success;
	if (pFrame) {
		// remove camera and light frame from frame that was rendered
		// this doesn't destroy the camera as it is still the camera of the viewport...
		result = ResultVal(pFrame->DeleteChild(pCamera));
		assert(Succeeded(result));
		assert((pCamera->AddRef(), pCamera->Release()) > 0);

		result = ResultVal(pFrame->DeleteChild(pLightFrame));
		assert(Succeeded(result));

		// decrease frame's ref count (it was increased in ViewPrepareFrameForRender())
		pFrame->Release();
	}
	return result;
}

// FUNCTION: BETA10 0x101711a0
inline void ViewDestroy(IDirect3DRMViewport* pView)
{
	pView->Release();
}

// FUNCTION: BETA10 0x10171160
inline void ViewImpl::Destroy()
{
	if (m_data) {
		ViewDestroy(m_data);
		m_data = NULL;
	}
}

// FUNCTION: BETA10 0x1016f390
inline Result CameraSetTransformation(IDirect3DRMFrame2* pCamera, FloatMatrix4& matrix)
{
	D3DRMMATRIX4D helper;
	D3DRMMATRIX4D* pTransformation = Translate(matrix, helper);

	D3DVECTOR position;
	Result result;
	Result result2;

	result2 = ResultVal(pCamera->GetPosition(0, &position));
	assert(Succeeded(result2));

	result = ResultVal(pCamera->AddTransform(D3DRMCOMBINE_REPLACE, *pTransformation));
	assert(Succeeded(result));

	result2 = ResultVal(pCamera->GetPosition(0, &position));
	assert(Succeeded(result2));

	return result;
}

// FUNCTION: BETA10 0x10170940
inline void CameraDestroy(IDirect3DRMFrame2* pFrame)
{
	pFrame->Release();
}

// FUNCTION: BETA10 0x10170900
inline void CameraImpl::Destroy()
{
	if (m_data) {
		CameraDestroy(m_data);
		m_data = NULL;
	}
}

// FUNCTION: BETA10 0x1016f6e0
inline Result LightSetTransformation(IDirect3DRMFrame2* pLight, FloatMatrix4& matrix)
{
	D3DRMMATRIX4D helper;
	D3DRMMATRIX4D* d3dMatrix = Translate(matrix, helper);
	return ResultVal(pLight->AddTransform(D3DRMCOMBINE_REPLACE, *d3dMatrix));
}

// FUNCTION: BETA10 0x1016f860
inline Result LightSetColor(IDirect3DRMFrame2* pLight, float r, float g, float b)
{
	IDirect3DRMLightArray* lights;
	IDirect3DRMLight* light;
	Result result = ResultVal(pLight->GetLights(&lights));
	assert(Succeeded(result));
	assert(lights->GetSize() == 1);

	result = ResultVal(lights->GetElement(0, &light));
	assert(Succeeded(result));

	return ResultVal(light->SetColorRGB(r, g, b));
}

// FUNCTION: BETA10 0x10171220
inline void LightDestroy(IDirect3DRMFrame2* pLight)
{
	pLight->Release();
}

// FUNCTION: BETA10 0x101711e0
inline void LightImpl::Destroy()
{
	if (m_data) {
		LightDestroy(m_data);
		m_data = NULL;
	}
}

// FUNCTION: BETA10 0x1016c340
inline Result GroupSetTransformation(IDirect3DRMFrame2* pGroup, FloatMatrix4& matrix)
{
	D3DRMMATRIX4D helper;
	D3DRMMATRIX4D* d3dMatrix = Translate(matrix, helper);
	return ResultVal(pGroup->AddTransform(D3DRMCOMBINE_REPLACE, *d3dMatrix));
}

// FUNCTION: BETA10 0x1016c400
inline Result GroupSetColor(IDirect3DRMFrame2* pGroup, float r, float g, float b, float a)
{
	if (a > 0) {
		D3DCOLOR color = D3DRMCreateColorRGBA(r, g, b, a);
		return ResultVal(pGroup->SetColor(color));
	}
	else {
		return ResultVal(pGroup->SetColorRGB(r, g, b));
	}
}

// FUNCTION: BETA10 0x1016c5a0
inline Result GroupSetTexture(IDirect3DRMFrame2* pGroup, IDirect3DRMTexture* pD3DTexture)
{
	return ResultVal(pGroup->SetTexture(pD3DTexture));
}

// FUNCTION: BETA10 0x1016c640
inline Result GroupGetTexture(IDirect3DRMFrame2* pGroup, IDirect3DRMTexture** pD3DTexture)
{
#ifdef BETA10
	return ResultVal(pGroup->GetTexture(pD3DTexture));
#else
	IDirect3DRMTexture* tex;
	Result result = ResultVal(pGroup->GetTexture(&tex));

	if (Succeeded(result)) {
		result = ResultVal(tex->QueryInterface(IID_IDirect3DRMTexture2, (LPVOID*) pD3DTexture));
	}

	return result;
#endif
}

// FUNCTION: BETA10 0x1016c500
inline Result GroupSetMaterialMode(IDirect3DRMFrame2* pGroup, MaterialMode mode)
{
	D3DRMMATERIALMODE d3dMode = Translate(mode);
	return ResultVal(pGroup->SetMaterialMode(d3dMode));
}

// FUNCTION: BETA10 0x1016c670
inline Result GroupAddGroup(IDirect3DRMFrame2* pGroup, const IDirect3DRMFrame* pChildGroup)
{
	return ResultVal(pGroup->AddVisual(const_cast<IDirect3DRMFrame*>(pChildGroup)));
}

// FUNCTION: BETA10 0x1016c700
inline Result GroupAddMeshBuilder(IDirect3DRMFrame2* pGroup, const IDirect3DRMMesh* pMesh)
{
	return ResultVal(pGroup->AddVisual(const_cast<IDirect3DRMMesh*>(pMesh)));
}

// FUNCTION: BETA10 0x1016c730
inline Result GroupRemoveGroup(IDirect3DRMFrame2* pGroup, const IDirect3DRMFrame* pChildGroup)
{
	return ResultVal(pGroup->DeleteVisual(const_cast<IDirect3DRMFrame*>(pChildGroup)));
}

// FUNCTION: BETA10 0x1016c7b0
inline Result GroupRemoveMeshBuilder(IDirect3DRMFrame2* pGroup, const IDirect3DRMMesh* pMesh)
{
	return ResultVal(pGroup->DeleteVisual(const_cast<IDirect3DRMMesh*>(pMesh)));
}

// FUNCTION: BETA10 0x1016c850
inline Result GroupRemoveAll(IDirect3DRMFrame2* pFrame)
{
	IDirect3DRMVisualArray* visuals;
	int refCount;

	Result result = ResultVal(pFrame->GetVisuals(&visuals));
	assert(Succeeded(result));

	if (Succeeded(result)) {
		for (int i = 0; i < (int) visuals->GetSize(); i++) {
			IDirect3DRMVisual* visual;

			result = ResultVal(visuals->GetElement(i, &visual));
			assert(Succeeded(result));

			result = ResultVal(pFrame->DeleteVisual(visual));
			assert(Succeeded(result));

			refCount = visual->Release();
		}

		refCount = visuals->Release();
		assert(refCount == 0);
	}

	return result;
}

// FUNCTION: BETA10 0x1016cb70
inline Result GroupBounds(IDirect3DRMFrame2* pFrame, D3DVECTOR* p_min, D3DVECTOR* p_max)
{
	D3DRMBOX size;
	int refCount;

	size.min.x = size.min.y = size.min.z = 88888.f;
	size.max.x = size.max.y = size.max.z = -88888.f;

	IDirect3DRMVisualArray* visuals;
	Result result = ResultVal(pFrame->GetVisuals(&visuals));
	assert(Succeeded(result));

	if (Succeeded(result)) {
		for (int i = 0; i < (int) visuals->GetSize(); i++) {
			IDirect3DRMVisual* visual;
			result = ResultVal(visuals->GetElement(i, &visual));
			assert(Succeeded(result));

			/*
			 * BUG: should be:
			 *  visual->QueryInterface(IID_IDirect3DRMMesh, (void**)&mesh));
			 */
			IDirect3DRMMesh* mesh;
			result = ResultVal(visual->QueryInterface(IID_IDirect3DRMMeshBuilder, (void**) &mesh));

			if (Succeeded(result)) {
				D3DRMBOX box;
				result = ResultVal(mesh->GetBox(&box));
				assert(Succeeded(result));

				if (box.min.x < size.min.x) {
					size.min.x = box.min.x;
				}
				if (box.min.y < size.min.y) {
					size.min.y = box.min.y;
				}
				if (box.min.z < size.min.z) {
					size.min.z = box.min.z;
				}
				if (size.max.x < box.max.x) {
					size.max.x = box.max.x;
				}
				if (size.max.y < box.max.y) {
					size.max.y = box.max.y;
				}
				if (size.max.z < box.max.z) {
					size.max.z = box.max.z;
				}

				mesh->Release();
			}

			refCount = visual->Release();
		}

		refCount = visuals->Release();
	}

	p_min->x = size.min.x;
	p_min->y = size.min.y;
	p_min->z = size.min.z;
	p_max->x = size.max.x;
	p_max->y = size.max.y;
	p_max->z = size.max.z;
	return result;
}

// FUNCTION: BETA10 0x1016c2b0
inline void GroupDestroy(IDirect3DRMFrame2* pGroup)
{
	pGroup->Release();
}

// FUNCTION: BETA10 0x1016c270
inline void GroupImpl::Destroy()
{
	if (m_data) {
		GroupDestroy(m_data);
		m_data = NULL;
	}
}

// FUNCTION: BETA10 0x1016e060
inline Result MeshBuilderGetBoundingBox(IDirect3DRMMesh* pMesh, float min[3], float max[3])
{
	D3DRMBOX box;
	Result result = ResultVal(pMesh->GetBox(&box));
	if (Succeeded(result)) {
		min[0] = box.min.x;
		min[1] = box.min.y;
		min[2] = box.min.z;
		max[0] = box.max.x;
		max[1] = box.max.y;
		max[2] = box.max.z;
	}
	return result;
}

// FUNCTION: BETA10 0x1016fef0
inline Result CreateMesh(
	IDirect3DRMMesh* pD3DRM,
	unsigned long p_numFaces,
	unsigned long p_numVertices,
	float(*p_positions),
	float(*p_normals),
	float(*p_textureCoordinates),
	unsigned long (*p_faceIndices)[3],
	unsigned long (*p_textureIndices)[3],
	ShadingModel shadingModel,
	MeshImpl::MeshDataType& rpMesh
)
{
	unsigned short* faceIndices = (unsigned short*) p_faceIndices;
	D3DRMGROUPINDEX groupIndex = 0;
	int faceCount = p_numFaces * 3;
	int count = 0;

	unsigned int* fData = new unsigned int[faceCount];

	D3DRMVERTEX* vertices = new D3DRMVERTEX[p_numVertices];
	memset(vertices, 0, sizeof(*vertices) * p_numVertices);

	rpMesh = new MeshImpl::MeshData;
	rpMesh->groupMesh = pD3DRM;

	for (int i = 0; i < faceCount; i++) {
		if (((faceIndices[2 * i + 1]) >> 0x0f) & 0x01) {
			unsigned long j = 3 * faceIndices[2 * i];
			vertices[count].position.x = p_positions[j];
			vertices[count].position.y = p_positions[j + 1];
			vertices[count].position.z = p_positions[j + 2];

			int k = 3 * (faceIndices[2 * i + 1] & MAXSHORT);
			vertices[count].normal.x = p_normals[k];
			vertices[count].normal.y = p_normals[k + 1];
			vertices[count].normal.z = p_normals[k + 2];

			if (p_textureIndices != NULL && p_textureCoordinates != NULL) {
				int kk = 2 * ((unsigned long*) p_textureIndices)[i];
				vertices[count].tu = p_textureCoordinates[kk];
				vertices[count].tv = p_textureCoordinates[kk + 1];
			}

			fData[i] = count;
			count++;
		}
		else {
			fData[i] = faceIndices[2 * i];
		}
	}

	assert(count == (int) p_numVertices);

	Result result;
	result = ResultVal(pD3DRM->AddGroup(p_numVertices, p_numFaces, 3, fData, &groupIndex));

	if (Succeeded(result)) {
		rpMesh->groupIndex = groupIndex;
		result = ResultVal(pD3DRM->SetVertices(groupIndex, 0, p_numVertices, vertices));
	}

	if (!Succeeded(result)) {
		if (rpMesh) {
			delete rpMesh;
		}
		rpMesh = NULL;
	}
	else {
		result = MeshSetTextureMappingMode(rpMesh, PerspectiveCorrect);
		assert(Succeeded(result));
	}

	if (fData != NULL) {
		delete[] fData;
	}

	if (vertices != NULL) {
		delete[] vertices;
	}

	return result;
}

// FUNCTION: BETA10 0x10170390
inline void MeshBuilderDestroy(IDirect3DRMMesh* pMeshBuilder)
{
	pMeshBuilder->Release();
}

// FUNCTION: BETA10 0x10170350
inline void MeshBuilderImpl::Destroy()
{
	if (m_data) {
		MeshBuilderDestroy(m_data);
		m_data = NULL;
	}
}

// FUNCTION: BETA10 0x10170590
inline Result MeshSetColor(MeshImpl::MeshData* pMesh, float r, float g, float b, float a)
{
	if (a > 0) {
		D3DCOLOR color = D3DRMCreateColorRGBA(r, g, b, a);
		return ResultVal(pMesh->groupMesh->SetGroupColor(pMesh->groupIndex, color));
	}
	else {
		return ResultVal(pMesh->groupMesh->SetGroupColorRGB(pMesh->groupIndex, r, g, b));
	}
}

// FUNCTION: BETA10 0x10171320
inline Result MeshSetTexture(MeshImpl::MeshData* pMesh, IDirect3DRMTexture* pD3DTexture)
{
	Result result = ResultVal(pMesh->groupMesh->SetGroupTexture(pMesh->groupIndex, pD3DTexture));
	return result;
}

// FUNCTION: BETA10 0x10170750
inline Result MeshSetShadingModel(MeshImpl::MeshData* pMesh, ShadingModel model)
{
	D3DRMRENDERQUALITY mode = Translate(model);
	return ResultVal(pMesh->groupMesh->SetGroupQuality(pMesh->groupIndex, mode));
}

// FUNCTION: BETA10 0x101714e0
inline Result MeshDeepClone(MeshImpl::MeshData* pSource, MeshImpl::MeshData*& rpTarget, IDirect3DRMMesh* pMesh)
{
	rpTarget = new MeshImpl::MeshData();
	rpTarget->groupMesh = pMesh;

	// Query information from old group
	DWORD dataSize;
	unsigned int vcount, fcount, vperface;

	Result result =
		ResultVal(pSource->groupMesh->GetGroup(pSource->groupIndex, &vcount, &fcount, &vperface, &dataSize, NULL));
	assert(Succeeded(result));

	unsigned int* faceBuffer = new unsigned int[dataSize];
	result =
		ResultVal(pSource->groupMesh->GetGroup(pSource->groupIndex, &vcount, &fcount, &vperface, &dataSize, faceBuffer)
		);
	assert(Succeeded(result));

	// We expect vertex to be sized 0x24, checked in tglrl40.cpp.
	D3DRMVERTEX* vertexBuffer = new D3DRMVERTEX[vcount];
	result = ResultVal(pSource->groupMesh->GetVertices(pSource->groupIndex, 0, vcount, vertexBuffer));
	assert(Succeeded(result));

	LPDIRECT3DRMTEXTURE textureRef;
	result = ResultVal(pSource->groupMesh->GetGroupTexture(pSource->groupIndex, &textureRef));
	assert(Succeeded(result));

	D3DRMMAPPING mapping = pSource->groupMesh->GetGroupMapping(pSource->groupIndex);
	D3DRMRENDERQUALITY quality = pSource->groupMesh->GetGroupQuality(pSource->groupIndex);
	D3DCOLOR color = pSource->groupMesh->GetGroupColor(pSource->groupIndex);

	// Push information to new group
	D3DRMGROUPINDEX index;
	result = ResultVal(pMesh->AddGroup(vcount, fcount, 3, faceBuffer, &index));
	assert(Succeeded(result));

	rpTarget->groupIndex = index;
	result = ResultVal(pMesh->SetVertices(index, 0, vcount, vertexBuffer));
	assert(Succeeded(result));

	result = ResultVal(pMesh->SetGroupTexture(index, textureRef));
	assert(Succeeded(result));

	result = ResultVal(pMesh->SetGroupMapping(index, mapping));
	assert(Succeeded(result));

	result = ResultVal(pMesh->SetGroupQuality(index, quality));
	assert(Succeeded(result));

	result = ResultVal(pMesh->SetGroupColor(index, color));
	assert(Succeeded(result));

	// Cleanup
	if (faceBuffer) {
		delete[] faceBuffer;
	}

	if (vertexBuffer) {
		delete[] vertexBuffer;
	}

	return result;
}

inline Result MeshShallowClone(MeshImpl::MeshData* pSource, MeshImpl::MeshData*& rpTarget, IDirect3DRMMesh* pMesh)
{
	Result result = Error;
	rpTarget = new MeshImpl::MeshData();

	if (rpTarget) {
		rpTarget->groupMesh = pMesh;
		rpTarget->groupIndex = pSource->groupIndex;
		result = Success;
	}

	return result;
}

// FUNCTION: BETA10 0x10171ac0
inline Result MeshGetTexture(MeshImpl::MeshData* pMesh, IDirect3DRMTexture** pD3DTexture)
{
#ifdef BETA10
	return ResultVal(pMesh->groupMesh->GetGroupTexture(pMesh->groupIndex, pD3DTexture));
#else
	IDirect3DRMTexture* tex;
	Result result = ResultVal(pMesh->groupMesh->GetGroupTexture(pMesh->groupIndex, &tex));

	if (Succeeded(result)) {
		result = ResultVal(tex->QueryInterface(IID_IDirect3DRMTexture2, (LPVOID*) pD3DTexture));
	}

	return result;
#endif
}

// FUNCTION: BETA10 0x10171b40
inline void MeshDestroy(MeshImpl::MeshDataType pMesh)
{
	delete pMesh;
}

// FUNCTION: BETA10 0x10171b00
inline void MeshImpl::Destroy()
{
	if (m_data) {
		MeshDestroy(m_data);
		m_data = NULL;
	}
}

// FUNCTION: BETA10 0x1016f9f0
inline Image* TextureGetImage(IDirect3DRMTexture* pTexture)
{
	return reinterpret_cast<Image*>(pTexture->GetAppData());
}

// FUNCTION: BETA10 0x1016ee80
inline Result TextureSetTexels(
	IDirect3DRMTexture* pTexture,
	int width,
	int height,
	int bitsPerTexel,
	void* pTexels,
	int pTexelsArePersistent
)
{
	Image* pImage = TextureGetImage(pTexture);
	assert(pImage);

	Result result = pImage->CreateBuffer(width, height, bitsPerTexel, pTexels, pTexelsArePersistent);
	assert(Succeeded(result));

	if (Succeeded(result)) {
		result = ResultVal(pTexture->Changed(TRUE, FALSE));
		assert(Succeeded(result));
	}

	return result;
}

// FUNCTION: BETA10 0x1016f160
inline Result TextureFillRowsOfTexture(IDirect3DRMTexture* pTexture, int y, int height, void* pBuffer)
{
	Image* pImage = TextureGetImage(pTexture);
	assert(pImage);

	Result result = pImage->FillRowsOfTexture(y, height, (char*) pBuffer);
	assert(Succeeded(result));

	return result;
}

// FUNCTION: BETA10 0x1016f270
inline Result TextureChanged(IDirect3DRMTexture* pTexture, int texelsChanged, int paletteChanged)
{
	Result result = ResultVal(pTexture->Changed(texelsChanged, paletteChanged));
	assert(Succeeded(result));
	return result;
}

// FUNCTION: BETA10 0x1016f4c0
inline Result TextureGetBufferAndPalette(
	IDirect3DRMTexture* pTexture,
	int* width,
	int* height,
	int* depth,
	void** pBuffer,
	int* paletteSize,
	unsigned char (*pEntries)[3]
)
{
	Image* pImage = TextureGetImage(pTexture);
	assert(pImage);

	*width = pImage->width;
	*height = pImage->height;
	*depth = pImage->depth;
	*pBuffer = pImage->buffer1;
	*paletteSize = pImage->palette_size;

	for (int i = 0; i < *paletteSize; i++) {
		pEntries[i][0] = pImage->palette[i].red;
		pEntries[i][1] = pImage->palette[i].green;
		pEntries[i][2] = pImage->palette[i].blue;
	}

	return Success;
}

// FUNCTION: BETA10 0x1016f730
inline Result TextureSetPalette(IDirect3DRMTexture* pTexture, int entryCount, PaletteEntry* pEntries)
{
	Image* pImage = TextureGetImage(pTexture);
	assert(pImage);

	pImage->InitializePalette(entryCount, pEntries);
	Result result = ResultVal(pTexture->Changed(FALSE, TRUE));
	assert(Succeeded(result));

	return Success;
}

// FUNCTION: BETA10 0x1016fd40
inline void TextureDestroy(IDirect3DRMTexture* pTexture)
{
	pTexture->Release();
}

// FUNCTION: BETA10 0x1016fd00
inline void TextureImpl::Destroy()
{
	if (m_data) {
		TextureDestroy(m_data);
		m_data = NULL;
	}
}

} /* namespace TglImpl */

class MxUnkRecordPost00;
class MxUnkRecordPost01;
class MxUnkRecordPost02;
class MxUnkRecordPost03;
class MxUnkRecordPost04;
class MxUnkRecordPost05;
class MxUnkRecordPost06;
class MxUnkRecordPost07;
class MxUnkRecordPost08;
class MxUnkRecordPost09;
class MxUnkRecordPost10;
class MxUnkRecordPost11;
class MxUnkRecordPost12;
class MxUnkRecordPost13;
class MxUnkRecordPost14;
class MxUnkRecordPost15;
class MxUnkRecordPost16;
class MxUnkRecordPost17;
#endif
