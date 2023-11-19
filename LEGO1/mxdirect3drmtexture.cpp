#include "mxdirect3drmtexture.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(IMxDirect3DRMTexture, 0x4);
DECOMP_SIZE_ASSERT(MxDirect3DRMTexture, 0x8);
DECOMP_SIZE_ASSERT(MxD3DRMIMAGE, 0x40);

// OFFSET: LEGO1 0x100a1330
MxD3DRMIMAGE::MxD3DRMIMAGE(
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
	m_extra = 0;
	if (p_buffer != NULL) {
		CreateBuffer(p_width, p_height, p_depth, p_buffer, p_useBuffer);
	}
	if (p_palette != NULL) {
		InitializePalette(p_paletteSize, p_palette);
	}
}

// OFFSET: LEGO1 0x100a13e0 STUB
int MxD3DRMIMAGE::CreateBuffer(int p_width, int p_height, int p_depth, void* p_buffer, int p_useBuffer)
{
	return 0;
}

// OFFSET: LEGO1 0x100a13b0
void MxD3DRMIMAGE::Destroy()
{
	if (m_extra == 0) {
		free(m_image.buffer1);
	}
	free(m_image.palette);
}

// OFFSET: LEGO1 0x100a1510
void MxD3DRMIMAGE::FillRowsOfTexture(int p_y, int p_height, char* p_content)
{
	// The purpose is clearly this but I can't get the assembly to line up.
	memcpy((char*) m_image.buffer1 + (p_y * m_image.bytes_per_line), p_content, p_height * m_image.bytes_per_line);
}

// OFFSET: LEGO1 0x100a1550
int MxD3DRMIMAGE::InitializePalette(int p_paletteSize, PaletteEntry* p_palette)
{
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
			m_image.palette[i].red = p_palette[i].r;
			m_image.palette[i].green = p_palette[i].g;
			m_image.palette[i].blue = p_palette[i].b;
			m_image.palette[i].flags = D3DRMPALETTE_READONLY;
		}
	}
	return TRUE;
}

// OFFSET: LEGO1 0x100a3d70
IUnknown** MxDirect3DRMTexture::GetHandle()
{
	return (IUnknown**) &m_pDirect3DRMTexture;
}

// OFFSET: LEGO1 0x100a3c10
int MxDirect3DRMTexture::SetBuffer(int p_width, int p_height, int p_depth, void* p_buffer)
{
	// Haven't tried very hard to get a very good match here yet, the control
	// flow for the result handling is a bit annoying.
	MxD3DRMIMAGE* image = GetImageData();
	int result = image->CreateBuffer(p_width, p_height, p_depth, p_buffer, TRUE);
	if (result == TRUE) {
		if (!SUCCEEDED(m_pDirect3DRMTexture->Changed(TRUE, FALSE))) {
			result = FALSE;
		}
	}
	return result;
}

// OFFSET: LEGO1 0x100a3c60
void MxDirect3DRMTexture::FillRowsOfTexture(int p_y, int p_height, void* p_buffer)
{
	MxD3DRMIMAGE* image = GetImageData();
	image->FillRowsOfTexture(p_y, p_height, (char*) p_buffer);
}

// OFFSET: LEGO1 0x100a3c90
int MxDirect3DRMTexture::Changed(int p_pixelsChanged, int p_paletteChanged)
{
	return SUCCEEDED(m_pDirect3DRMTexture->Changed(p_pixelsChanged, p_paletteChanged));
}

// OFFSET: LEGO1 0x100a3d00
int MxDirect3DRMTexture::GetBufferAndPalette(
	int* p_width,
	int* p_height,
	int* p_depth,
	void** p_buffer,
	int* p_paletteSize,
	MxD3DRMIMAGE::PaletteEntry** p_palette
)
{
	// Something really doesn't match here, not sure what's up.
	MxD3DRMIMAGE* image = GetImageData();
	*p_width = image->m_image.width;
	*p_height = image->m_image.height;
	*p_depth = image->m_image.depth;
	*p_buffer = image->m_image.buffer1;
	*p_paletteSize = image->m_image.palette_size;
	for (int i = 0; i < image->m_image.palette_size; i++) {
		p_palette[i]->r = image->m_image.palette[i].red;
		p_palette[i]->g = image->m_image.palette[i].green;
		p_palette[i]->b = image->m_image.palette[i].blue;
	}
	return TRUE;
}

// OFFSET: LEGO1 0x100a3d40
int MxDirect3DRMTexture::InitializePalette(int p_paletteSize, MxD3DRMIMAGE::PaletteEntry* p_palette)
{
	// Not 100% confident this is supposed to directly be forwarding arguments,
	// but it probably is given FillRowsOfTexture matches doing that.
	MxD3DRMIMAGE* image = GetImageData();
	image->InitializePalette(p_paletteSize, p_palette);
	m_pDirect3DRMTexture->Changed(FALSE, TRUE);
	return TRUE;
}

// OFFSET: LEGO1 0x100a1300
void MxDirect3DRMTexture::OnDestroyed()
{
	delete GetImageData();
	m_pDirect3DRMTexture->SetAppData(NULL);
}
