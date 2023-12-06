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
extern GifMapEntry* DAT_100f0100;

class GifMap {
public:
	// FUNCTION: LEGO1 0x10001cc0
	GifMapEntry* GifMap::FindNode(const char*& string)
	{
		GifMapEntry* ret = m_unk4;
		GifMapEntry* current = ret->m_parent;
		while (current != DAT_100f0100) {
			if (strcmp(current->m_key, string) <= 0) {
				ret = current;
				current = current->m_right;
			}
			else
				current = current->m_left;
		}
		return ret;
	}

	inline GifData* Get(const char* string)
	{
		GifData* ret = NULL;
		GifMapEntry* entry = FindNode(string);
		if (((m_unk4 == entry || strcmp(string, entry->m_key) > 0) ? m_unk4 : entry) != entry)
			ret = entry->m_value;
		return ret;
	}

	undefined4 m_unk0;
	GifMapEntry* m_unk4;
};

// VTABLE: LEGO1 0x100d86d4
class GifManagerBase {
public:
	// STUB: LEGO1 0x1005a310
	virtual ~GifManagerBase() {} // vtable+00

	inline GifData* Get(const char* name) { return m_unk8.Get(name); }

protected:
	undefined4 m_unk4;
	GifMap m_unk8;
};

// VTABLE: LEGO1 0x100d86fc
class GifManager : public GifManagerBase {
public:
	// STUB: LEGO1 0x1005a580
	virtual ~GifManager() {} // vtable+00

protected:
	undefined m_unk[0x14];
};

#endif // GIFMANAGER_H
