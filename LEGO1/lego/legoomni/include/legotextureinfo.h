#ifndef LEGOTEXTUREINFO_H
#define LEGOTEXTUREINFO_H

#include <d3drmobj.h>
#include <ddraw.h>

class LegoTexture;

// SIZE 0x10
struct LegoTextureInfo {
public:
	LegoTextureInfo();
	~LegoTextureInfo();

	static LegoTextureInfo* Create(const char* p_name, LegoTexture* p_texture);

	char* m_name;                   // 0x00
	LPDIRECTDRAWSURFACE m_surface;  // 0x04
	LPDIRECTDRAWPALETTE m_palette;  // 0x08
	LPDIRECT3DRMTEXTURE2 m_texture; // 0x0c
};

#endif // LEGOTEXTUREINFO_H
