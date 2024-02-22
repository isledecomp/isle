#ifndef LEGOTEXTURECONTAINER_H
#define LEGOTEXTURECONTAINER_H

#include "compat.h"
#include "decomp.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

#include <d3drmobj.h>
#include <ddraw.h>

#pragma warning(disable : 4237)

class LegoTexture;

// SIZE 0x10
struct TextureData {
public:
	TextureData();
	~TextureData();

	static TextureData* Create(const char* p_name, LegoTexture* p_texture);

	char* m_name;                   // 0x00
	LPDIRECTDRAWSURFACE m_surface;  // 0x04
	LPDIRECTDRAWPALETTE m_palette;  // 0x08
	LPDIRECT3DRMTEXTURE2 m_texture; // 0x0c
};

struct LegoContainerInfoComparator {
	bool operator()(const char* const& p_key0, const char* const& p_key1) const { return strcmp(p_key0, p_key1) > 0; }
};

// SIZE 0x10
template <class T>
class LegoContainerInfo : public map<const char*, T*, LegoContainerInfoComparator> {
	// SYNTHETIC: LEGO1 0x1005a400
	// LegoContainerInfo::~LegoContainerInfo
};

// SIZE 0x18
template <class T>
class LegoContainer {
public:
	// FUNCTION: LEGO1 0x1005b660
	virtual ~LegoContainer()
	{
		LegoContainerInfo<T>::iterator it;
		for (it = m_map.begin(); it != m_map.end(); it++) {
			// DECOMP: Use of const_cast here matches ~ViewLODListManager from 96 source.
			const char* const& key = (*it).first;
			delete[] const_cast<char*>(key);

			if (m_ownership) {
				delete (*it).second;
			}
		}
	}

	inline T* Get(const char* p_name)
	{
		LegoContainerInfo<T>::iterator it = m_map.find(p_name);
		if (it != m_map.end()) {
			return (*it).second;
		}

		return NULL;
	}

	inline void SetOwnership(MxBool p_ownership) { m_ownership = p_ownership; }

	// SYNTHETIC: LEGO1 0x1005a310
	// LegoContainer<TextureData>::`scalar deleting destructor'

protected:
	MxBool m_ownership;         // 0x04
	LegoContainerInfo<T> m_map; // 0x08
};

// VTABLE: LEGO1 0x100d86d4
// class LegoContainer<TextureData>

typedef list<TextureData*> TextureList;

// VTABLE: LEGO1 0x100d86fc
// SIZE 0x24
class LegoTextureContainer : public LegoContainer<TextureData> {
public:
	LegoTextureContainer() { m_ownership = TRUE; }
	~LegoTextureContainer() override;

	// SYNTHETIC: LEGO1 0x1005a580
	// LegoTextureContainer::`scalar deleting destructor'

	void FUN_10099cc0(TextureData* p_data);

protected:
	TextureList m_list; // 0x18
};

// TEMPLATE: LEGO1 0x10059c50
// allocator<TextureData *>::_Charalloc

// clang-format off
// TEMPLATE: LEGO1 0x10001cc0
// _Tree<char const *,pair<char const * const,TextureData *>,map<char const *,TextureData *,LegoContainerInfoComparator,allocator<TextureData *> >::_Kfn,LegoContainerInfoComparator,allocator<TextureData *> >::_Lbound

// TEMPLATE: LEGO1 0x1004f9b0
// _Tree<char const *,pair<char const * const,TextureData *>,map<char const *,TextureData *,LegoContainerInfoComparator,allocator<TextureData *> >::_Kfn,LegoContainerInfoComparator,allocator<TextureData *> >::_Insert

// TEMPLATE: LEGO1 0x10059c70
// _Tree<char const *,pair<char const * const,TextureData *>,map<char const *,TextureData *,LegoContainerInfoComparator,allocator<TextureData *> >::_Kfn,LegoContainerInfoComparator,allocator<TextureData *> >::_Color

// TEMPLATE: LEGO1 0x10059c80
// _Tree<char const *,pair<char const * const,TextureData *>,map<char const *,TextureData *,LegoContainerInfoComparator,allocator<TextureData *> >::_Kfn,LegoContainerInfoComparator,allocator<TextureData *> >::_Left

// TEMPLATE: LEGO1 0x10059c90
// _Tree<char const *,pair<char const * const,TextureData *>,map<char const *,TextureData *,LegoContainerInfoComparator,allocator<TextureData *> >::_Kfn,LegoContainerInfoComparator,allocator<TextureData *> >::_Parent

// TEMPLATE: LEGO1 0x10059ca0
// _Tree<char const *,pair<char const * const,TextureData *>,map<char const *,TextureData *,LegoContainerInfoComparator,allocator<TextureData *> >::_Kfn,LegoContainerInfoComparator,allocator<TextureData *> >::_Right

// TEMPLATE: LEGO1 0x10059cb0
// _Tree<char const *,pair<char const * const,TextureData *>,map<char const *,TextureData *,LegoContainerInfoComparator,allocator<TextureData *> >::_Kfn,LegoContainerInfoComparator,allocator<TextureData *> >::~_Tree<char const *,pair<char const * const,TextureData *>,map<char const *,TextureData *,LegoContainerInfoComparator,allocator<TextureData *> >::_Kfn,LegoContainerInfoComparator,allocator<TextureData *> >

// TEMPLATE: LEGO1 0x10059d80
// _Tree<char const *,pair<char const * const,TextureData *>,map<char const *,TextureData *,LegoContainerInfoComparator,allocator<TextureData *> >::_Kfn,LegoContainerInfoComparator,allocator<TextureData *> >::iterator::_Inc

// TEMPLATE: LEGO1 0x10059dc0
// _Tree<char const *,pair<char const * const,TextureData *>,map<char const *,TextureData *,LegoContainerInfoComparator,allocator<TextureData *> >::_Kfn,LegoContainerInfoComparator,allocator<TextureData *> >::erase

// TEMPLATE: LEGO1 0x1005a210
// _Tree<char const *,pair<char const * const,TextureData *>,map<char const *,TextureData *,LegoContainerInfoComparator,allocator<TextureData *> >::_Kfn,LegoContainerInfoComparator,allocator<TextureData *> >::_Erase

// TEMPLATE: LEGO1 0x1005a250
// list<TextureData *,allocator<TextureData *> >::~list<TextureData *,allocator<TextureData *> >

// TEMPLATE: LEGO1 0x1005a2c0
// map<char const *,TextureData *,LegoContainerInfoComparator,allocator<TextureData *> >::~map<char const *,TextureData *,LegoContainerInfoComparator,allocator<TextureData *> >

// TEMPLATE: LEGO1 0x1005a450
// Map<char const *,TextureData *,LegoContainerInfoComparator>::~Map<char const *,TextureData *,LegoContainerInfoComparator>

// TEMPLATE: LEGO1 0x1005a5a0
// List<TextureData *>::~List<TextureData *>

// GLOBAL: LEGO1 0x100f0100
// _Tree<char const *,pair<char const * const,TextureData *>,map<char const *,TextureData *,LegoContainerInfoComparator,allocator<TextureData *> >::_Kfn,LegoContainerInfoComparator,allocator<TextureData *> >::_Nil
// clang-format on

#endif // LEGOTEXTURECONTAINER_H
