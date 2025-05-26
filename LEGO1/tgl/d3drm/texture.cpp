#include "impl.h"

#include <assert.h>

using namespace TglImpl;

DECOMP_SIZE_ASSERT(TglD3DRMIMAGE, 0x40);

// FUNCTION: BETA10 0x1016f9f0
inline TglD3DRMIMAGE* TextureGetImage(IDirect3DRMTexture* pTexture)
{
	return reinterpret_cast<TglD3DRMIMAGE*>(pTexture->GetAppData());
}

// Forward declare to satisfy order check
void TextureDestroyCallback(IDirect3DRMObject* pObject, void* pArg);

// FUNCTION: LEGO1 0x100a12a0
// FUNCTION: BETA10 0x10169113
Result TextureImpl::SetImage(IDirect3DRMTexture* pSelf, TglD3DRMIMAGE* pImage)
{
	void* appData;
	Result result;

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
	// This function is a 100% match if the PaletteEntry class is copied
	// into into the TglD3DRMIMAGE class instead of being a global struct.
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
	TglD3DRMIMAGE* pImage = TextureGetImage(pTexture);
	assert(pImage);

	Result result = pImage->CreateBuffer(width, height, bitsPerTexel, pTexels, pTexelsArePersistent);
	assert(Succeeded(result));

	if (Succeeded(result)) {
		result = ResultVal(pTexture->Changed(TRUE, FALSE));
		assert(Succeeded(result));
	}

	return result;
}

// FUNCTION: LEGO1 0x100a3c10
// FUNCTION: BETA10 0x1016c390
Result TextureImpl::SetTexels(int width, int height, int bitsPerTexel, void* pTexels, int pTexelsArePersistent)
{
	assert(m_data);

	return TextureSetTexels(m_data, width, height, bitsPerTexel, pTexels, pTexelsArePersistent);
}

// FUNCTION: BETA10 0x1016f160
inline Result TextureFillRowsOfTexture(IDirect3DRMTexture* pTexture, int y, int height, void* pBuffer)
{
	TglD3DRMIMAGE* pImage = TextureGetImage(pTexture);
	assert(pImage);

	Result result = pImage->FillRowsOfTexture(y, height, (char*) pBuffer);
	assert(Succeeded(result));

	return result;
}

// FUNCTION: LEGO1 0x100a3c60
// FUNCTION: BETA10 0x1016c490
void TextureImpl::FillRowsOfTexture(int y, int height, void* pBuffer)
{
	assert(m_data);

	TextureFillRowsOfTexture(m_data, y, height, pBuffer);
}

// FUNCTION: BETA10 0x1016f270
inline Result TextureChanged(IDirect3DRMTexture* pTexture, int texelsChanged, int paletteChanged)
{
	Result result = ResultVal(pTexture->Changed(texelsChanged, paletteChanged));
	assert(Succeeded(result));
	return result;
}

// FUNCTION: LEGO1 0x100a3c90
// FUNCTION: BETA10 0x1016c540
Result TextureImpl::Changed(int texelsChanged, int paletteChanged)
{
	assert(m_data);

	return TextureChanged(m_data, texelsChanged, paletteChanged);
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
	TglD3DRMIMAGE* pImage = TextureGetImage(pTexture);
	assert(pImage);

	*width = pImage->m_image.width;
	*height = pImage->m_image.height;
	*depth = pImage->m_image.depth;
	*pBuffer = pImage->m_image.buffer1;
	*paletteSize = pImage->m_image.palette_size;

	for (int i = 0; i < *paletteSize; i++) {
		pEntries[i][0] = pImage->m_image.palette[i].red;
		pEntries[i][1] = pImage->m_image.palette[i].green;
		pEntries[i][2] = pImage->m_image.palette[i].blue;
	}

	return Success;
}

// FUNCTION: LEGO1 0x100a3cc0
// FUNCTION: BETA10 0x1016c5d0
Result TextureImpl::GetBufferAndPalette(
	int* width,
	int* height,
	int* depth,
	void** pBuffer,
	int* paletteSize,
	unsigned char (*pEntries)[3]
)
{
	assert(m_data);

	return TextureGetBufferAndPalette(m_data, width, height, depth, pBuffer, paletteSize, pEntries);
}

// FUNCTION: BETA10 0x1016f730
inline Result TextureSetPalette(IDirect3DRMTexture* pTexture, int entryCount, PaletteEntry* pEntries)
{
	TglD3DRMIMAGE* pImage = TextureGetImage(pTexture);
	assert(pImage);

	pImage->InitializePalette(entryCount, pEntries);
	Result result = ResultVal(pTexture->Changed(FALSE, TRUE));
	assert(Succeeded(result));

	return Success;
}

// FUNCTION: LEGO1 0x100a3d40
// FUNCTION: BETA10 0x1016c6a0
Result TextureImpl::SetPalette(int entryCount, PaletteEntry* pEntries)
{
	assert(m_data);

	return TextureSetPalette(m_data, entryCount, pEntries);
}

// FUNCTION: LEGO1 0x100a3d70
// FUNCTION: BETA10 0x1016c760
void* TextureImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}
