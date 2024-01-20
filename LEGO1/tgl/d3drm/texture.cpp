#include "impl.h"

using namespace TglImpl;

DECOMP_SIZE_ASSERT(TglD3DRMIMAGE, 0x40);

inline TglD3DRMIMAGE* TextureGetImage(IDirect3DRMTexture* pTexture)
{
	return reinterpret_cast<TglD3DRMIMAGE*>(pTexture->GetAppData());
}

// Forward declare to satisfy order check
void TextureDestroyCallback(IDirect3DRMObject* pObject, void* pArg);

// FUNCTION: LEGO1 0x100a12a0
Result TextureImpl::SetImage(IDirect3DRMTexture* pSelf, TglD3DRMIMAGE* pImage)
{
	unsigned long appData;
	Result result;

	appData = reinterpret_cast<unsigned long>(pImage);

	// This is here because in the original code they asserted
	// on the return value being NULL.
	TextureGetImage(pSelf);

	result = ResultVal(pSelf->SetAppData(appData));
	if (Succeeded(result) && pImage) {
		result = ResultVal(pSelf->AddDestroyCallback(TextureDestroyCallback, NULL));
		if (!Succeeded(result)) {
			pSelf->SetAppData(0);
		}
	}
	return result;
}

// FUNCTION: LEGO1 0x100a1300
void TextureDestroyCallback(IDirect3DRMObject* pObject, void* pArg)
{
	TglD3DRMIMAGE* pImage = reinterpret_cast<TglD3DRMIMAGE*>(pObject->GetAppData());
	delete pImage;
	pObject->SetAppData(0);
}

// FUNCTION: LEGO1 0x100a1330
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
	m_image.aspectx = 1;
	m_image.aspecty = 1;
	m_image.width = 0;
	m_image.height = 0;
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
	if (pBuffer != NULL) {
		CreateBuffer(width, height, depth, pBuffer, useBuffer);
	}
	if (pEntries != NULL) {
		InitializePalette(paletteSize, pEntries);
	}
}

// FUNCTION: LEGO1 0x100a13b0
void TglD3DRMIMAGE::Destroy()
{
	if (m_texelsAllocatedByClient == 0) {
		delete m_image.buffer1;
	}
	delete m_image.palette;
}

// STUB: LEGO1 0x100a13e0
Result TglD3DRMIMAGE::CreateBuffer(int width, int height, int depth, void* pBuffer, int useBuffer)
{
	return Error;
}

// FUNCTION: LEGO1 0x100a1510
void TglD3DRMIMAGE::FillRowsOfTexture(int y, int height, char* pContent)
{
	// The purpose is clearly this but I can't get the assembly to line up.
	memcpy((char*) m_image.buffer1 + (y * m_image.bytes_per_line), pContent, height * m_image.bytes_per_line);
}

// FUNCTION: LEGO1 0x100a1550
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

// FUNCTION: LEGO1 0x100a3c10
Result TextureImpl::SetTexels(int width, int height, int bitsPerTexel, void* pTexels)
{
	TglD3DRMIMAGE* image = TextureGetImage(m_data);
	Result result = image->CreateBuffer(width, height, bitsPerTexel, pTexels, TRUE);
	if (Succeeded(result)) {
		result = ResultVal(m_data->Changed(TRUE, FALSE));
	}
	return result;
}

// FUNCTION: LEGO1 0x100a3c60
void TextureImpl::FillRowsOfTexture(int y, int height, void* pBuffer)
{
	TglD3DRMIMAGE* image = TextureGetImage(m_data);
	image->FillRowsOfTexture(y, height, (char*) pBuffer);
}

// FUNCTION: LEGO1 0x100a3c90
Result TextureImpl::Changed(int texelsChanged, int paletteChanged)
{
	return ResultVal(m_data->Changed(texelsChanged, paletteChanged));
}

// FUNCTION: LEGO1 0x100a3cc0
Result TextureImpl::GetBufferAndPalette(
	int* width,
	int* height,
	int* depth,
	void** pBuffer,
	int* paletteSize,
	PaletteEntry** pEntries
)
{
	// Something really doesn't match here, not sure what's up.
	TglD3DRMIMAGE* image = TextureGetImage(m_data);
	*width = image->m_image.width;
	*height = image->m_image.height;
	*depth = image->m_image.depth;
	*pBuffer = image->m_image.buffer1;
	*paletteSize = image->m_image.palette_size;
	for (int i = 0; i < image->m_image.palette_size; i++) {
		pEntries[i]->m_red = image->m_image.palette[i].red;
		pEntries[i]->m_green = image->m_image.palette[i].green;
		pEntries[i]->m_blue = image->m_image.palette[i].blue;
	}
	return Success;
}

// FUNCTION: LEGO1 0x100a3d40
Result TextureImpl::SetPalette(int entryCount, PaletteEntry* pEntries)
{
	// Not 100% confident this is supposed to directly be forwarding arguments,
	// but it probably is given FillRowsOfTexture matches doing that.
	TglD3DRMIMAGE* image = TextureGetImage(m_data);
	image->InitializePalette(entryCount, pEntries);
	m_data->Changed(FALSE, TRUE);
	return Success;
}

// FUNCTION: LEGO1 0x100a3d70
void* TextureImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}
