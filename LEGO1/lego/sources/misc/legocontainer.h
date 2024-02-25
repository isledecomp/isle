#ifndef LEGOCONTAINER_H
#define LEGOCONTAINER_H

#include "compat.h"
#include "decomp.h"
#include "legotexture.h"
#include "legotypes.h"
#include "mxstl/stlcompat.h"

// Note: dependency on LegoOmni
#include "lego/legoomni/include/legotextureinfo.h"

#pragma warning(disable : 4237)

struct LegoContainerInfoComparator {
	LegoBool operator()(const char* const& p_key0, const char* const& p_key1) const
	{
		return strcmp(p_key0, p_key1) > 0;
	}
};

// SIZE 0x10
template <class T>
class LegoContainerInfo : public map<const char*, T*, LegoContainerInfoComparator> {};

// SIZE 0x18
template <class T>
class LegoContainer {
public:
	virtual ~LegoContainer()
	{
#ifdef COMPAT_MODE
		typename LegoContainerInfo<T>::iterator it;
#else
		LegoContainerInfo<T>::iterator it;
#endif
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
		// TODO: Score::Paint matches better with no `value` on the stack,
		// while LegoModelPresenter::CreateROI only matches with `value`
		T* value = NULL;

#ifdef COMPAT_MODE
		typename LegoContainerInfo<T>::iterator it = m_map.find(p_name);
#else
		LegoContainerInfo<T>::iterator it = m_map.find(p_name);
#endif

		if (it != m_map.end()) {
			value = (*it).second;
		}

		return value;
	}

	inline void Add(const char* p_name, T* p_value)
	{
#ifdef COMPAT_MODE
		typename LegoContainerInfo<T>::iterator it = m_map.find(p_name);
#else
		LegoContainerInfo<T>::iterator it = m_map.find(p_name);
#endif

		char* name;
		if (it != m_map.end()) {
			name = const_cast<char*>((*it).first);

			if (m_ownership) {
				delete (*it).second;
			}
		}
		else {
			name = new char[strlen(p_name) + 1];
			strcpy(name, p_name);
		}

		m_map[name] = p_value;
	}

	inline void SetOwnership(LegoBool p_ownership) { m_ownership = p_ownership; }

protected:
	LegoBool m_ownership;       // 0x04
	LegoContainerInfo<T> m_map; // 0x08
};

// VTABLE: LEGO1 0x100d86d4
// class LegoContainer<LegoTextureInfo>

typedef pair<LegoTextureInfo*, BOOL> LegoTextureListElement;
typedef list<LegoTextureListElement> LegoTextureList;

// VTABLE: LEGO1 0x100d86fc
// SIZE 0x24
class LegoTextureContainer : public LegoContainer<LegoTextureInfo> {
public:
	LegoTextureContainer() { m_ownership = TRUE; }
	~LegoTextureContainer() override;

	LegoTextureInfo* AddToList(LegoTextureInfo* p_textureInfo);
	void EraseFromList(LegoTextureInfo* p_textureInfo);

protected:
	LegoTextureList m_list; // 0x18
};

// TEMPLATE: LEGO1 0x10059c50
// allocator<LegoTextureInfo *>::_Charalloc

// clang-format off
// TEMPLATE: LEGO1 0x10001cc0
// _Tree<char const *,pair<char const * const,LegoTextureInfo *>,map<char const *,LegoTextureInfo *,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Kfn,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Lbound

// TEMPLATE: LEGO1 0x1004f960
// _Tree<char const *,pair<char const * const,LegoTextureInfo *>,map<char const *,LegoTextureInfo *,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Kfn,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::iterator::_Dec

// TEMPLATE: LEGO1 0x1004f9b0
// _Tree<char const *,pair<char const * const,LegoTextureInfo *>,map<char const *,LegoTextureInfo *,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Kfn,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Insert

// TEMPLATE: LEGO1 0x10059c70
// _Tree<char const *,pair<char const * const,LegoTextureInfo *>,map<char const *,LegoTextureInfo *,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Kfn,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Color

// TEMPLATE: LEGO1 0x10059c80
// _Tree<char const *,pair<char const * const,LegoTextureInfo *>,map<char const *,LegoTextureInfo *,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Kfn,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Left

// TEMPLATE: LEGO1 0x10059c90
// _Tree<char const *,pair<char const * const,LegoTextureInfo *>,map<char const *,LegoTextureInfo *,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Kfn,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Parent

// TEMPLATE: LEGO1 0x10059ca0
// _Tree<char const *,pair<char const * const,LegoTextureInfo *>,map<char const *,LegoTextureInfo *,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Kfn,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Right

// TEMPLATE: LEGO1 0x10059cb0
// _Tree<char const *,pair<char const * const,LegoTextureInfo *>,map<char const *,LegoTextureInfo *,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Kfn,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::~_Tree<char const *,pair<char const * const,LegoTextureInfo *>,map<char const *,LegoTextureInfo *,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Kfn,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >

// TEMPLATE: LEGO1 0x10059d80
// _Tree<char const *,pair<char const * const,LegoTextureInfo *>,map<char const *,LegoTextureInfo *,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Kfn,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::iterator::_Inc

// TEMPLATE: LEGO1 0x10059dc0
// _Tree<char const *,pair<char const * const,LegoTextureInfo *>,map<char const *,LegoTextureInfo *,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Kfn,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::erase

// TEMPLATE: LEGO1 0x1005a210
// _Tree<char const *,pair<char const * const,LegoTextureInfo *>,map<char const *,LegoTextureInfo *,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Kfn,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Erase

// TEMPLATE: LEGO1 0x1005a250
// list<pair<LegoTextureInfo *,int>,allocator<pair<LegoTextureInfo *,int> > >::~list<pair<LegoTextureInfo *,int>,allocator<pair<LegoTextureInfo *,int> > >

// TEMPLATE: LEGO1 0x1005a2c0
// map<char const *,LegoTextureInfo *,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::~map<char const *,LegoTextureInfo *,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >

// TEMPLATE: LEGO1 0x1005a310
// LegoContainer<LegoTextureInfo>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1005a400
// LegoContainerInfo<LegoTextureInfo>::~LegoContainerInfo<LegoTextureInfo>

// TEMPLATE: LEGO1 0x1005a450
// Map<char const *,LegoTextureInfo *,LegoContainerInfoComparator>::~Map<char const *,LegoTextureInfo *,LegoContainerInfoComparator>

// SYNTHETIC: LEGO1 0x1005a580
// LegoTextureContainer::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1005a5a0
// List<pair<LegoTextureInfo *,int> >::~List<pair<LegoTextureInfo *,int> >

// TEMPLATE: LEGO1 0x1005b660
// LegoContainer<LegoTextureInfo>::~LegoContainer<LegoTextureInfo>

// GLOBAL: LEGO1 0x100f0100
// _Tree<char const *,pair<char const * const,LegoTextureInfo *>,map<char const *,LegoTextureInfo *,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Kfn,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Nil
// clang-format on

#endif // LEGOCONTAINER_H
