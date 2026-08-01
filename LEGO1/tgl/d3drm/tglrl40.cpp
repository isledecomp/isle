#include "tglrl40.h"

#include <assert.h>

using namespace TglImpl;

DECOMP_SIZE_ASSERT(Camera, 0x04);
DECOMP_SIZE_ASSERT(CameraImpl, 0x08);
DECOMP_SIZE_ASSERT(Light, 0x04);
DECOMP_SIZE_ASSERT(LightImpl, 0x08);
DECOMP_SIZE_ASSERT(MeshBuilder, 0x04);
DECOMP_SIZE_ASSERT(MeshBuilderImpl, 0x08);
DECOMP_SIZE_ASSERT(D3DRMVERTEX, 0x24);
DECOMP_SIZE_ASSERT(Mesh, 0x04);
DECOMP_SIZE_ASSERT(MeshImpl, 0x08);
DECOMP_SIZE_ASSERT(TglD3DRMIMAGE, 0x40);
DECOMP_SIZE_ASSERT(ViewportAppData, 0x18);

namespace TglImpl
{
// GLOBAL: LEGO1 0x1010103c
IDirect3DRM2* g_pTheRenderer = NULL;
} // namespace TglImpl

// FUNCTION: LEGO1 0x100a10b0
// FUNCTION: BETA10 0x10168920
ViewportAppData::ViewportAppData(IDirect3DRM2* pRenderer)
{
	Result result = ResultVal(pRenderer->CreateFrame(NULL, &m_pLightFrame));
	assert(Succeeded(result));

	m_pCamera = NULL;
	m_pLastRenderedFrame = NULL;
	m_backgroundColorRed = 0.0f;
	m_backgroundColorGreen = 0.0f;
	m_backgroundColorBlue = 0.0f;
}

// FUNCTION: LEGO1 0x100a10e0
// FUNCTION: BETA10 0x101689bd
ViewportAppData::~ViewportAppData()
{
	int refCount;
	IDirect3DRMFrameArray* pChildFrames;
	IDirect3DRMFrame* pChildFrame = NULL;
	Result result = ResultVal(m_pLightFrame->GetChildren(&pChildFrames));
	assert(Succeeded(result));

	for (int i = 0; i < (int) pChildFrames->GetSize(); i++) {
		result = ResultVal(pChildFrames->GetElement(i, &pChildFrame));
		assert(Succeeded(result));

		result = ResultVal(m_pLightFrame->DeleteChild(pChildFrame));
		assert(Succeeded(result));

		refCount = pChildFrame->Release(); // GetElement() does AddRef()
		assert(refCount >= 1);
	}

	refCount = pChildFrames->Release();
	assert(refCount == 0);

	refCount = m_pLightFrame->Release();
	assert(refCount == 0);
}

// FUNCTION: LEGO1 0x100a1160
// FUNCTION: BETA10 0x10168ba5
Result ViewImpl::ViewportCreateAppData(
	IDirect3DRM2* pDevice,
	IDirect3DRMViewport* pViewport,
	IDirect3DRMFrame2* pCamera
)
{
	ViewportAppData* pViewportAppData = new ViewportAppData(pDevice);
	assert(pViewportAppData);

	pViewportAppData->m_pCamera = pCamera;
	assert(!pViewport->GetAppData());

	Result result = ResultVal(pViewport->SetAppData(reinterpret_cast<LPD3DRM_APPDATA>(pViewportAppData)));
	assert(Succeeded(result));
	assert(reinterpret_cast<ViewportAppData*>(pViewport->GetAppData()) == pViewportAppData);

	if (Succeeded(result)) {
		result = ResultVal(pViewport->AddDestroyCallback(ViewportDestroyCallback, pViewportAppData));
		assert(Succeeded(result));
	}

	if (!Succeeded(result)) {
		delete pViewportAppData;
		pViewport->SetAppData(0);
	}

	return result;
}

// FUNCTION: LEGO1 0x100a1240
// FUNCTION: BETA10 0x10168dc9
void ViewportDestroyCallback(IDirect3DRMObject* pObject, void* pArg)
{
	ViewportAppData* pViewportAppData = reinterpret_cast<ViewportAppData*>(pArg);
	assert(static_cast<ViewImpl::ViewDataType>(pObject));
	assert(pViewportAppData);

	Result result = ViewRestoreFrameAfterRender(
		pViewportAppData->m_pLastRenderedFrame,
		pViewportAppData->m_pCamera,
		pViewportAppData->m_pLightFrame
	);

	assert(Succeeded(result));

	delete pViewportAppData;
}

// FUNCTION: LEGO1 0x100a1290
// FUNCTION: BETA10 0x10168eab
Result ViewportPickImpl(
	IDirect3DRMViewport* pViewport,
	int x,
	int y,
	const GroupImpl** ppGroupsToPickFrom,
	int groupsToPickFromCount,
	const Group**& rppPickedGroups,
	int& rPickedGroupCount
)
{
	// The BETA10 body (tglRL40.cpp L140-L230, asserts at L153/L171/L193)
	// walks the D3DRM pick array; left unimplemented in shipped game.
	return Error;
}

// FUNCTION: LEGO1 0x100a12a0
// FUNCTION: BETA10 0x10169113
Result TextureImpl::SetImage(IDirect3DRMTexture* pSelf, TglD3DRMIMAGE* pImage)
{
	Result result;
	void* appData;

	appData = pImage;
	assert(reinterpret_cast<TglD3DRMIMAGE*>(appData) == pImage);

	if (TextureGetImage(pSelf)) {
		assert(0);
	}

	result = ResultVal(pSelf->SetAppData((LPD3DRM_APPDATA) appData));
	assert(Succeeded(result));

	if (Succeeded(result) && pImage) {
		result = ResultVal(pSelf->AddDestroyCallback(TextureDestroyCallback, NULL));
		assert(Succeeded(result));

		if (!Succeeded(result)) {
			pSelf->SetAppData(0);
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100a1300
// FUNCTION: BETA10 0x10169278
void TextureDestroyCallback(IDirect3DRMObject* pObject, void* pArg)
{
	TglD3DRMIMAGE* pImage = reinterpret_cast<TglD3DRMIMAGE*>(pObject->GetAppData());
	assert(pImage);

	delete pImage;
	pObject->SetAppData(0);
}

// FUNCTION: LEGO1 0x100a1330
// FUNCTION: BETA10 0x101692e1
TglD3DRMIMAGE::TglD3DRMIMAGE(
	int width,
	int height,
	int depth,
	void* pBuffer,
	int useBuffer,
	int paletteSize,
	PaletteEntry* pEntries
)
{
	m_image.width = 0;
	m_image.height = 0;
	m_image.aspectx = 1;
	m_image.aspecty = 1;
	m_image.depth = 0;
	m_image.rgb = 0;
	m_image.bytes_per_line = 0;
	m_image.buffer1 = NULL;
	m_image.buffer2 = NULL;
	m_image.red_mask = 0xFF;
	m_image.green_mask = 0xFF;
	m_image.blue_mask = 0xFF;
	m_image.alpha_mask = 0xFF;
	m_image.palette_size = 0;
	m_image.palette = NULL;
	m_texelsAllocatedByClient = 0;

	Result result;
	if (pBuffer != NULL) {
		result = CreateBuffer(width, height, depth, pBuffer, useBuffer);
		assert(Succeeded(result));
	}

	if (pEntries != NULL) {
		result = InitializePalette(paletteSize, pEntries);
		assert(Succeeded(result));
	}
}

// FUNCTION: LEGO1 0x100a13b0
// FUNCTION: BETA10 0x1016944b
TglD3DRMIMAGE::~TglD3DRMIMAGE()
{
	if (m_texelsAllocatedByClient == 0) {
		delete[] ((char*) m_image.buffer1);
	}

	delete m_image.palette;
}

// FUNCTION: BETA10 0x101699a0
inline static int IsPowerOfTwo(int v)
{
	int m = 0;

	while (v > 2 && m == 0) {
		m = v % 2;
		v /= 2;
	}

	return v == 2 && m == 0;
}

// FUNCTION: LEGO1 0x100a13e0
// FUNCTION: BETA10 0x101694a4
Result TglD3DRMIMAGE::CreateBuffer(int width, int height, int depth, void* pBuffer, int useBuffer)
{
	int bytesPerScanline = width;

	assert(IsPowerOfTwo(width));
	assert(IsPowerOfTwo(height));
	assert((bytesPerScanline % 4) == 0);

	if (!(IsPowerOfTwo(width) && IsPowerOfTwo(height) && bytesPerScanline % 4 == 0)) {
		return Error;
	}

	assert(!m_image.buffer1 || (m_image.buffer1 == pBuffer));

	m_image.width = width;
	m_image.height = height;
	m_image.depth = depth;
	m_image.bytes_per_line = bytesPerScanline;

	if (!m_texelsAllocatedByClient) {
		delete[] ((char*) m_image.buffer1);
		m_image.buffer1 = NULL;
	}

	if (useBuffer) {
		m_image.buffer1 = (char*) pBuffer;
		m_texelsAllocatedByClient = 1;
	}
	else {
		int size = bytesPerScanline * height;
		m_image.buffer1 = new char[size];
		memcpy(m_image.buffer1, pBuffer, size);
		m_texelsAllocatedByClient = 0;
	}

	return Success;
}

// FUNCTION: LEGO1 0x100a1510
// FUNCTION: BETA10 0x1016969c
Result TglD3DRMIMAGE::FillRowsOfTexture(int destVOffset, int srcHeight, char* pTexels)
{
	assert(m_image.buffer1 && pTexels);
	assert((destVOffset + srcHeight) <= m_image.height);

	int size = srcHeight * m_image.bytes_per_line;
	char* pSrc = (char*) m_image.buffer1 + (destVOffset * m_image.bytes_per_line);
	memcpy(pSrc, pTexels, size);
	return Success;
}

// FUNCTION: LEGO1 0x100a1550
// FUNCTION: BETA10 0x10169758
Result TglD3DRMIMAGE::InitializePalette(int paletteSize, PaletteEntry* pEntries)
{
	if (m_image.palette_size != paletteSize) {
		if (m_image.palette != NULL) {
			delete m_image.palette;
			m_image.palette = NULL;
			m_image.palette_size = 0;
		}
		if (paletteSize > 0) {
			m_image.palette = new D3DRMPALETTEENTRY[paletteSize];
			m_image.palette_size = paletteSize;
		}
	}

	if (paletteSize > 0) {
		for (int i = 0; i < paletteSize; i++) {
			m_image.palette[i].red = pEntries[i].m_red;
			m_image.palette[i].green = pEntries[i].m_green;
			m_image.palette[i].blue = pEntries[i].m_blue;
			m_image.palette[i].flags = D3DRMPALETTE_READONLY;
		}
	}

	return Success;
}

// The BETA10 assert at tglRL40.cpp L497 preserves the 1997 local name:
// assert(pRenderer).
// FUNCTION: LEGO1 0x100a15e0
Renderer* Tgl::CreateRenderer()
{
	RendererImpl* pRenderer = new RendererImpl();
	assert(pRenderer);

	if (!pRenderer->Create()) {
		delete pRenderer;
		pRenderer = NULL;
	}
	return pRenderer;
}

class MxUnkRecordTG0;
class MxUnkRecordTG1;
