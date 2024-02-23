#include "legotextureinfo.h"

#include "legoomni.h"
#include "legovideomanager.h"
#include "misc/legoimage.h"
#include "misc/legotexture.h"
#include "tgl/d3drm/impl.h"

DECOMP_SIZE_ASSERT(LegoTextureInfo, 0x10);

// FUNCTION: LEGO1 0x10065bf0
LegoTextureInfo::LegoTextureInfo()
{
	m_name = NULL;
	m_surface = NULL;
	m_palette = NULL;
	m_texture = NULL;
}

// FUNCTION: LEGO1 0x10065c00
LegoTextureInfo::~LegoTextureInfo()
{
	if (m_name) {
		delete[] m_name;
		m_name = NULL;
	}

	if (m_palette) {
		m_palette->Release();
		m_palette = NULL;
	}

	if (m_surface) {
		m_surface->Release();
		m_surface = NULL;
	}

	if (m_texture) {
		m_texture->Release();
		m_texture = NULL;
	}
}

// FUNCTION: LEGO1 0x10065c60
LegoTextureInfo* LegoTextureInfo::Create(const char* p_name, LegoTexture* p_texture)
{
	LegoTextureInfo* texture = new LegoTextureInfo();

	if (p_name == NULL || p_texture == NULL) {
		return NULL;
	}

	if (p_name) {
		texture->m_name = new char[strlen(p_name) + 1];
		strcpy(texture->m_name, p_name);
	}

	LPDIRECTDRAW pDirectDraw = VideoManager()->GetDirect3D()->DirectDraw();
	LegoImage* image = p_texture->GetImage();

	DDSURFACEDESC desc;
	memset(&desc, 0, sizeof(desc));
	desc.dwSize = sizeof(desc);
	desc.dwFlags = DDSD_PIXELFORMAT | DDSD_WIDTH | DDSD_HEIGHT | DDSD_CAPS;
	desc.dwWidth = image->GetWidth();
	desc.dwHeight = image->GetHeight();
	desc.ddsCaps.dwCaps = DDCAPS_OVERLAYCANTCLIP | DDCAPS_OVERLAY;
	desc.ddpfPixelFormat.dwSize = sizeof(desc.ddpfPixelFormat);
	desc.ddpfPixelFormat.dwFlags = DDPF_RGB | DDPF_PALETTEINDEXED8;
	desc.ddpfPixelFormat.dwRGBBitCount = 8;

	MxS32 i;
	LegoU8* bits;
	MxU8* surface;

	if (pDirectDraw->CreateSurface(&desc, &texture->m_surface, NULL) != DD_OK) {
		goto done;
	}

	bits = image->GetBits();

	memset(&desc, 0, sizeof(desc));
	desc.dwSize = sizeof(desc);

	if (texture->m_surface->Lock(NULL, &desc, DDLOCK_SURFACEMEMORYPTR, NULL) != DD_OK) {
		goto done;
	}

	surface = (MxU8*) desc.lpSurface;
	if (desc.dwWidth == desc.lPitch) {
		memcpy(surface, bits, desc.dwWidth * desc.dwHeight);
	}
	else {
		for (i = 0; i < desc.dwHeight; i++) {
			*(MxU32*) surface = *(MxU32*) bits;
			surface += desc.lPitch;
			bits += desc.dwWidth;
		}
	}

	texture->m_surface->Unlock(desc.lpSurface);

	PALETTEENTRY entries[256];
	memset(entries, 0, sizeof(entries));

	for (i = 0; i < _countof(entries); i++) {
		if (i < image->GetCount()) {
			entries[i].peFlags = 0;
			entries[i].peRed = image->GetPaletteEntry(i).GetRed();
			entries[i].peGreen = image->GetPaletteEntry(i).GetGreen();
			entries[i].peBlue = image->GetPaletteEntry(i).GetBlue();
		}
		else {
			entries[i].peFlags = 0x80;
		}
	}

	if (pDirectDraw->CreatePalette(DDPCAPS_ALLOW256 | DDPCAPS_8BIT, entries, &texture->m_palette, NULL) != DD_OK) {
		goto done;
	}

	texture->m_surface->SetPalette(texture->m_palette);

	if (((TglImpl::RendererImpl*) VideoManager()->GetRenderer())
			->CreateTextureFromSurface(texture->m_surface, &texture->m_texture) != D3DRM_OK) {
		goto done;
	}

	texture->m_texture->SetAppData((DWORD) texture);
	return texture;

done:
	if (texture->m_name != NULL) {
		delete[] texture->m_name;
		texture->m_name = NULL;
	}

	if (texture->m_palette != NULL) {
		texture->m_palette->Release();
		texture->m_palette = NULL;
	}

	if (texture->m_surface != NULL) {
		texture->m_surface->Release();
		texture->m_surface = NULL;
	}

	if (texture != NULL) {
		delete texture;
	}

	return NULL;
}
