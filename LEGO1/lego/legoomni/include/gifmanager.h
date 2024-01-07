#ifndef GIFMANAGER_H
#define GIFMANAGER_H

#include "decomp.h"
#include "mxtypes.h"

#include <d3drmobj.h>
#include <ddraw.h>

struct GifData {
public:
	const char* m_name;
	LPDIRECTDRAWSURFACE m_surface;
	LPDIRECTDRAWPALETTE m_palette;
	LPDIRECT3DRMTEXTURE2 m_texture;
	MxU8* m_data;
};

struct GifMapEntry {
public:
	GifMapEntry* m_right;
	GifMapEntry* m_parent;
	GifMapEntry* m_left;
	const char* m_key;
	GifData* m_value;
};

class GifMap {
public:
	GifMapEntry* FindNode(const char*& p_string);

	inline GifData* Get(const char* p_string)
	{
		GifData* ret = NULL;
		GifMapEntry* entry = FindNode(p_string);
		if (((m_unk0x4 == entry || strcmp(p_string, entry->m_key) > 0) ? m_unk0x4 : entry) != entry)
			ret = entry->m_value;
		return ret;
	}

	undefined4 m_unk0x0;
	GifMapEntry* m_unk0x4;
};

// VTABLE: LEGO1 0x100d86d4
class GifManagerBase {
public:
	// STUB: LEGO1 0x1005a310
	virtual ~GifManagerBase() {} // vtable+00

	inline GifData* Get(const char* p_name) { return m_unk0x8.Get(p_name); }

protected:
	undefined4 m_unk0x0;
	undefined4 m_unk0x4;
	GifMap m_unk0x8;
};

// VTABLE: LEGO1 0x100d86fc
class GifManager : public GifManagerBase {
public:
	// STUB: LEGO1 0x1005a580
	virtual ~GifManager() {} // vtable+00

protected:
	undefined m_unk0x14[0x1c];
};

#endif // GIFMANAGER_H
