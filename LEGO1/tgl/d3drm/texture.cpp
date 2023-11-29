#include "impl.h"

using namespace TglImpl;

DECOMP_SIZE_ASSERT(TglD3DRMIMAGE, 0x40);

// OFFSET: LEGO1 0x100a1330
TglD3DRMIMAGE::TglD3DRMIMAGE(
	int p_width,
	int p_height,
	int p_depth,
	void* p_buffer,
	int p_useBuffer,
	int p_paletteSize,
	PaletteEntry* p_palette
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
	if (p_buffer != NULL) {
		CreateBuffer(p_width, p_height, p_depth, p_buffer, p_useBuffer);
	}
	if (p_palette != NULL) {
		InitializePalette(p_paletteSize, p_palette);
	}
}

// OFFSET: LEGO1 0x100a13e0 STUB
Result TglD3DRMIMAGE::CreateBuffer(int p_width, int p_height, int p_depth, void* p_buffer, int p_useBuffer)
{
	return Error;
}

// OFFSET: LEGO1 0x100a13b0
void TglD3DRMIMAGE::Destroy()
{
	if (m_texelsAllocatedByClient == 0) {
		free(m_image.buffer1);
	}
	free(m_image.palette);
}

// OFFSET: LEGO1 0x100a1510
void TglD3DRMIMAGE::FillRowsOfTexture(int p_y, int p_height, char* p_content)
{
	// The purpose is clearly this but I can't get the assembly to line up.
	memcpy((char*) m_image.buffer1 + (p_y * m_image.bytes_per_line), p_content, p_height * m_image.bytes_per_line);
}

// OFFSET: LEGO1 0x100a1550
Result TglD3DRMIMAGE::InitializePalette(int p_paletteSize, PaletteEntry* p_palette)
{
	// This function is a 100% match if the PaletteEntry class is copied
	// into into the TglD3DRMIMAGE class instead of being a global struct.
	if (m_image.palette_size != p_paletteSize) {
		if (m_image.palette != NULL) {
			free(m_image.palette);
			m_image.palette = NULL;
			m_image.palette_size = 0;
		}
		if (p_paletteSize > 0) {
			m_image.palette = (D3DRMPALETTEENTRY*) malloc(4 * p_paletteSize);
			m_image.palette_size = p_paletteSize;
		}
	}
	if (p_paletteSize > 0) {
		for (int i = 0; i < p_paletteSize; i++) {
			m_image.palette[i].red = p_palette[i].m_red;
			m_image.palette[i].green = p_palette[i].m_green;
			m_image.palette[i].blue = p_palette[i].m_blue;
			m_image.palette[i].flags = D3DRMPALETTE_READONLY;
		}
	}
	return Success;
}

// Inlined only
TextureImpl::~TextureImpl()
{
	if (m_data) {
		m_data->Release();
		m_data = NULL;
	}
}

// OFFSET: LEGO1 0x100a3d70
void* TextureImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}

inline TglD3DRMIMAGE* TextureGetImage(IDirect3DRMTexture* p_texture)
{
	return reinterpret_cast<TglD3DRMIMAGE*>(p_texture->GetAppData());
}

// OFFSET: LEGO1 0x100a3c10
Result TextureImpl::SetTexels(int p_width, int p_height, int p_bitsPerTexel, void* p_texels)
{
	TglD3DRMIMAGE* image = TextureGetImage(m_data);
	Result result = image->CreateBuffer(p_width, p_height, p_bitsPerTexel, p_texels, TRUE);
	if (Succeeded(result)) {
		result = ResultVal(m_data->Changed(TRUE, FALSE));
	}
	return result;
}

// OFFSET: LEGO1 0x100a3c60
void TextureImpl::FillRowsOfTexture(int p_y, int p_height, void* p_buffer)
{
	TglD3DRMIMAGE* image = TextureGetImage(m_data);
	image->FillRowsOfTexture(p_y, p_height, (char*) p_buffer);
}

// OFFSET: LEGO1 0x100a3c90
Result TextureImpl::Changed(int p_texelsChanged, int p_paletteChanged)
{
	return ResultVal(m_data->Changed(p_texelsChanged, p_paletteChanged));
}

// OFFSET: LEGO1 0x100a3d00
Result TextureImpl::GetBufferAndPalette(
	int* p_width,
	int* p_height,
	int* p_depth,
	void** p_buffer,
	int* p_paletteSize,
	PaletteEntry** p_palette
)
{
	// Something really doesn't match here, not sure what's up.
	TglD3DRMIMAGE* image = TextureGetImage(m_data);
	*p_width = image->m_image.width;
	*p_height = image->m_image.height;
	*p_depth = image->m_image.depth;
	*p_buffer = image->m_image.buffer1;
	*p_paletteSize = image->m_image.palette_size;
	for (int i = 0; i < image->m_image.palette_size; i++) {
		p_palette[i]->m_red = image->m_image.palette[i].red;
		p_palette[i]->m_green = image->m_image.palette[i].green;
		p_palette[i]->m_blue = image->m_image.palette[i].blue;
	}
	return Success;
}

// OFFSET: LEGO1 0x100a3d40
Result TextureImpl::SetPalette(int p_entryCount, PaletteEntry* p_entries)
{
	// Not 100% confident this is supposed to directly be forwarding arguments,
	// but it probably is given FillRowsOfTexture matches doing that.
	TglD3DRMIMAGE* image = TextureGetImage(m_data);
	image->InitializePalette(p_entryCount, p_entries);
	m_data->Changed(FALSE, TRUE);
	return Success;
}

// OFFSET: LEGO1 0x100a1300
void TextureDestroyCallback(IDirect3DRMObject* pObject, void* pArg)
{
	TglD3DRMIMAGE* pImage = reinterpret_cast<TglD3DRMIMAGE*>(pObject->GetAppData());
	delete pImage;
	pObject->SetAppData(0);
}

// OFFSET: LEGO1 0x100a12a0
Result TextureImpl::SetImage(IDirect3DRMTexture* p_self, TglD3DRMIMAGE* p_image)
{
	unsigned long appData;
	Result result;

	appData = reinterpret_cast<unsigned long>(p_image);

	// This is here because in the original code they asserted
	// on the return value being NULL.
	TextureGetImage(p_self);

	result = ResultVal(p_self->SetAppData(appData));
	if (Succeeded(result) && p_image) {
		result = ResultVal(p_self->AddDestroyCallback(TextureDestroyCallback, NULL));
		if (!Succeeded(result)) {
			p_self->SetAppData(0);
		}
	}
	return result;
}
