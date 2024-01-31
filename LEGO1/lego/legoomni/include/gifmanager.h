#ifndef GIFMANAGER_H
#define GIFMANAGER_H

#include "compat.h"
#include "decomp.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

#include <d3drmobj.h>
#include <ddraw.h>

#pragma warning(disable : 4237)

// SIZE 0x14
struct GifData {
public:
	char* m_name;                   // 0x00
	LPDIRECTDRAWSURFACE m_surface;  // 0x04
	LPDIRECTDRAWPALETTE m_palette;  // 0x08
	LPDIRECT3DRMTEXTURE2 m_texture; // 0x0c
	MxU8* m_data;                   // 0x10

	~GifData();
};

struct GifMapComparator {
	bool operator()(const char* const& p_key0, const char* const& p_key1) const { return strcmp(p_key0, p_key1) > 0; }
};

// SIZE 0x10
class GifMap : public map<const char*, GifData*, GifMapComparator> {
	// SYNTHETIC: LEGO1 0x1005a400
	// GifMap::~GifMap
};

typedef list<GifData*> GifList;

// VTABLE: LEGO1 0x100d86d4
// SIZE 0x18
class GifManagerBase {
public:
	// FUNCTION: LEGO1 0x1005b660
	virtual ~GifManagerBase()
	{
		GifMap::iterator it;
		for (it = m_map.begin(); it != m_map.end(); it++) {
			// DECOMP: Use of const_cast here matches ~ViewLODListManager from 96 source.
			const char* const& key = (*it).first;
			delete[] const_cast<char*>(key);

			if (m_ownership) {
				delete (*it).second; // GifData*
			}
		}
	}

	inline GifData* Get(const char* p_name)
	{
		GifMap::iterator it = m_map.find(p_name);
		if (it != m_map.end()) {
			return (*it).second;
		}

		return NULL;
	}

	// SYNTHETIC: LEGO1 0x1005a310
	// GifManagerBase::`scalar deleting destructor'

protected:
	MxBool m_ownership; // 0x04
	GifMap m_map;       // 0x08
};

// VTABLE: LEGO1 0x100d86fc
// SIZE 0x24
class GifManager : public GifManagerBase {
public:
	GifManager() { m_ownership = TRUE; }
	~GifManager() override;

	// SYNTHETIC: LEGO1 0x1005a580
	// GifManager::`scalar deleting destructor'

	void FUN_10099cc0(GifData* p_data);

protected:
	GifList m_list; // 0x18
};

// TEMPLATE: LEGO1 0x10059c50
// allocator<GifData *>::_Charalloc

// clang-format off
// TEMPLATE: LEGO1 0x10001cc0
// _Tree<char const *,pair<char const * const,GifData *>,map<char const *,GifData *,GifMapComparator,allocator<GifData *> >::_Kfn,GifMapComparator,allocator<GifData *> >::_Lbound

// TEMPLATE: LEGO1 0x1004f9b0
// _Tree<char const *,pair<char const * const,GifData *>,map<char const *,GifData *,GifMapComparator,allocator<GifData *> >::_Kfn,GifMapComparator,allocator<GifData *> >::_Insert

// TEMPLATE: LEGO1 0x10059c70
// _Tree<char const *,pair<char const * const,GifData *>,map<char const *,GifData *,GifMapComparator,allocator<GifData *> >::_Kfn,GifMapComparator,allocator<GifData *> >::_Color

// TEMPLATE: LEGO1 0x10059c80
// _Tree<char const *,pair<char const * const,GifData *>,map<char const *,GifData *,GifMapComparator,allocator<GifData *> >::_Kfn,GifMapComparator,allocator<GifData *> >::_Left

// TEMPLATE: LEGO1 0x10059c90
// _Tree<char const *,pair<char const * const,GifData *>,map<char const *,GifData *,GifMapComparator,allocator<GifData *> >::_Kfn,GifMapComparator,allocator<GifData *> >::_Parent

// TEMPLATE: LEGO1 0x10059ca0
// _Tree<char const *,pair<char const * const,GifData *>,map<char const *,GifData *,GifMapComparator,allocator<GifData *> >::_Kfn,GifMapComparator,allocator<GifData *> >::_Right

// TEMPLATE: LEGO1 0x10059cb0
// _Tree<char const *,pair<char const * const,GifData *>,map<char const *,GifData *,GifMapComparator,allocator<GifData *> >::_Kfn,GifMapComparator,allocator<GifData *> >::~_Tree<char const *,pair<char const * const,GifData *>,map<char const *,GifData *,GifMapComparator,allocator<GifData *> >::_Kfn,GifMapComparator,allocator<GifData *> >

// TEMPLATE: LEGO1 0x10059d80
// _Tree<char const *,pair<char const * const,GifData *>,map<char const *,GifData *,GifMapComparator,allocator<GifData *> >::_Kfn,GifMapComparator,allocator<GifData *> >::iterator::_Inc

// TEMPLATE: LEGO1 0x10059dc0
// _Tree<char const *,pair<char const * const,GifData *>,map<char const *,GifData *,GifMapComparator,allocator<GifData *> >::_Kfn,GifMapComparator,allocator<GifData *> >::erase

// TEMPLATE: LEGO1 0x1005a210
// _Tree<char const *,pair<char const * const,GifData *>,map<char const *,GifData *,GifMapComparator,allocator<GifData *> >::_Kfn,GifMapComparator,allocator<GifData *> >::_Erase

// TEMPLATE: LEGO1 0x1005a250
// list<GifData *,allocator<GifData *> >::~list<GifData *,allocator<GifData *> >

// TEMPLATE: LEGO1 0x1005a2c0
// map<char const *,GifData *,GifMapComparator,allocator<GifData *> >::~map<char const *,GifData *,GifMapComparator,allocator<GifData *> >

// TEMPLATE: LEGO1 0x1005a450
// Map<char const *,GifData *,GifMapComparator>::~Map<char const *,GifData *,GifMapComparator>

// TEMPLATE: LEGO1 0x1005a5a0
// List<GifData *>::~List<GifData *>

// GLOBAL: LEGO1 0x100f0100
// _Tree<char const *,pair<char const * const,GifData *>,map<char const *,GifData *,GifMapComparator,allocator<GifData *> >::_Kfn,GifMapComparator,allocator<GifData *> >::_Nil
// clang-format on

#endif // GIFMANAGER_H
