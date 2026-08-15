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
DECOMP_SIZE_ASSERT(Image, 0x40);
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
Result TextureImpl::SetImage(IDirect3DRMTexture* pSelf, Image* pImage)
{
	Result result;
	void* appData;

	appData = pImage;
	assert(reinterpret_cast<Image*>(appData) == pImage);

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
	Image* pImage = reinterpret_cast<Image*>(pObject->GetAppData());
	assert(pImage);

	delete pImage;
	pObject->SetAppData(0);
}
// FUNCTION: LEGO1 0x100a1330
// FUNCTION: BETA10 0x101692e1
Image::Image(int width, int height, int depth, void* pBuffer, int useBuffer, int paletteSize, PaletteEntry* pEntries)
{
	D3DRMIMAGE::width = 0;
	D3DRMIMAGE::height = 0;
	D3DRMIMAGE::aspectx = 1;
	D3DRMIMAGE::aspecty = 1;
	D3DRMIMAGE::depth = 0;
	D3DRMIMAGE::rgb = 0;
	D3DRMIMAGE::bytes_per_line = 0;
	D3DRMIMAGE::buffer1 = NULL;
	D3DRMIMAGE::buffer2 = NULL;
	D3DRMIMAGE::red_mask = 0xFF;
	D3DRMIMAGE::green_mask = 0xFF;
	D3DRMIMAGE::blue_mask = 0xFF;
	D3DRMIMAGE::alpha_mask = 0xFF;
	D3DRMIMAGE::palette_size = 0;
	D3DRMIMAGE::palette = NULL;
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
Image::~Image()
{
	if (m_texelsAllocatedByClient == 0) {
		delete[] ((char*) D3DRMIMAGE::buffer1);
	}

	delete D3DRMIMAGE::palette;
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
Result Image::CreateBuffer(int width, int height, int depth, void* pTexels, int useBuffer)
{
	int bytesPerScanline = width;

	assert(IsPowerOfTwo(width));
	assert(IsPowerOfTwo(height));
	assert((bytesPerScanline % 4) == 0);

	if (!(IsPowerOfTwo(width) && IsPowerOfTwo(height) && bytesPerScanline % 4 == 0)) {
		return Error;
	}

	assert(!D3DRMIMAGE::buffer1 || (D3DRMIMAGE::buffer1 == pTexels));

	D3DRMIMAGE::width = width;
	D3DRMIMAGE::height = height;
	D3DRMIMAGE::depth = depth;
	D3DRMIMAGE::bytes_per_line = bytesPerScanline;

	if (!m_texelsAllocatedByClient) {
		delete[] ((char*) D3DRMIMAGE::buffer1);
		D3DRMIMAGE::buffer1 = NULL;
	}

	if (useBuffer) {
		D3DRMIMAGE::buffer1 = (char*) pTexels;
		m_texelsAllocatedByClient = 1;
	}
	else {
		int size = bytesPerScanline * height;
		D3DRMIMAGE::buffer1 = new char[size];
		memcpy(D3DRMIMAGE::buffer1, pTexels, size);
		m_texelsAllocatedByClient = 0;
	}

	return Success;
}

// FUNCTION: LEGO1 0x100a1510
// FUNCTION: BETA10 0x1016969c
Result Image::FillRowsOfTexture(int destVOffset, int srcHeight, char* pTexels)
{
	assert(D3DRMIMAGE::buffer1 && pTexels);
	assert((destVOffset + srcHeight) <= D3DRMIMAGE::height);

	int size = srcHeight * D3DRMIMAGE::bytes_per_line;
	char* pSrc = (char*) D3DRMIMAGE::buffer1 + (destVOffset * D3DRMIMAGE::bytes_per_line);
	memcpy(pSrc, pTexels, size);
	return Success;
}

// FUNCTION: LEGO1 0x100a1550
// FUNCTION: BETA10 0x10169758
Result Image::InitializePalette(int paletteSize, PaletteEntry* pEntries)
{
	if (D3DRMIMAGE::palette_size != paletteSize) {
		if (D3DRMIMAGE::palette != NULL) {
			delete D3DRMIMAGE::palette;
			D3DRMIMAGE::palette = NULL;
			D3DRMIMAGE::palette_size = 0;
		}
		if (paletteSize > 0) {
			D3DRMIMAGE::palette = new D3DRMPALETTEENTRY[paletteSize];
			D3DRMIMAGE::palette_size = paletteSize;
		}
	}

	if (paletteSize > 0) {
		for (int i = 0; i < paletteSize; i++) {
			D3DRMIMAGE::palette[i].red = pEntries[i].m_red;
			D3DRMIMAGE::palette[i].green = pEntries[i].m_green;
			D3DRMIMAGE::palette[i].blue = pEntries[i].m_blue;
			D3DRMIMAGE::palette[i].flags = D3DRMPALETTE_READONLY;
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
