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
	LegoBool operator()(const char* p_key0, const char* p_key1) const { return strcmp(p_key0, p_key1) > 0; }
};

// SIZE 0x10
template <class T>
class LegoContainerInfo : public map<const char*, T*, LegoContainerInfoComparator> {};

// SIZE 0x18
template <class T>
class LegoContainer {
public:
	LegoContainer() { m_ownership = TRUE; }

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

	void Clear()
	{
		LegoContainerInfo<T>& map = m_map;

#ifdef COMPAT_MODE
		for (typename LegoContainerInfo<T>::iterator it = map.begin(); !(it == map.end()); it++)
#else
		for (LegoContainerInfo<T>::iterator it = map.begin(); !(it == map.end()); it++)
#endif
		{
			delete (*it).second;
		}
	}

	T* Get(const char* p_name)
	{
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

	void Add(const char* p_name, T* p_value)
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

	void SetOwnership(LegoBool p_ownership) { m_ownership = p_ownership; }

protected:
	LegoBool m_ownership;       // 0x04
	LegoContainerInfo<T> m_map; // 0x08
};

// VTABLE: LEGO1 0x100d86d4
// class LegoContainer<LegoTextureInfo>

typedef pair<LegoTextureInfo*, BOOL> LegoCachedTexture;
typedef list<LegoCachedTexture> LegoCachedTextureList;

// VTABLE: LEGO1 0x100d86fc
// SIZE 0x24
class LegoTextureContainer : public LegoContainer<LegoTextureInfo> {
public:
	~LegoTextureContainer() override;

	LegoTextureInfo* GetCached(LegoTextureInfo* p_textureInfo);
	void EraseCached(LegoTextureInfo* p_textureInfo);

	// Verified by LegoOmni::Create(), even though there have been significant changes.
	// SYNTHETIC: BETA10 0x10093ea0
	// LegoTextureContainer::LegoTextureContainer

protected:
	LegoCachedTextureList m_cached; // 0x18
};

// TEMPLATE: LEGO1 0x10059c50
// allocator<LegoTextureInfo *>::_Charalloc

// clang-format off
// TEMPLATE: LEGO1 0x10001cc0 SYMBOL
// ?_Lbound@?$_Tree@PBDU?$pair@QBDPAVLegoTextureInfo@@@@U_Kfn@?$map@PBDPAVLegoTextureInfo@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@IBEPAU_Node@1@ABQBD@Z

// TEMPLATE: LEGO1 0x1004f740 SYMBOL
// ?find@?$_Tree@PBDU?$pair@QBDPAVLegoTextureInfo@@@@U_Kfn@?$map@PBDPAVLegoTextureInfo@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@QAE?AViterator@1@ABQBD@Z

// TEMPLATE: LEGO1 0x1004f800 SYMBOL
// ?insert@?$map@PBDPAVLegoTextureInfo@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@QAE?AU?$pair@Viterator@?$_Tree@PBDU?$pair@QBDPAVLegoTextureInfo@@@@U_Kfn@?$map@PBDPAVLegoTextureInfo@@ULegoContainerInfoComparator@@V?$allocator@PAVLeg

// TEMPLATE: LEGO1 0x1004f960 SYMBOL
// ?_Dec@iterator@?$_Tree@PBDU?$pair@QBDPAVLegoTextureInfo@@@@U_Kfn@?$map@PBDPAVLegoTextureInfo@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@QAEXXZ

// TEMPLATE: LEGO1 0x1004f9b0 SYMBOL
// ?_Insert@?$_Tree@PBDU?$pair@QBDPAVLegoTextureInfo@@@@U_Kfn@?$map@PBDPAVLegoTextureInfo@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@IAE?AViterator@1@PAU_Node@1@0ABU?

// TEMPLATE: LEGO1 0x10059c70 SYMBOL
// ?_Color@?$_Tree@PBDU?$pair@QBDPAVLegoTextureInfo@@@@U_Kfn@?$map@PBDPAVLegoTextureInfo@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@KAAAW4_Redbl@1@PAU_Node@1@@Z

// TEMPLATE: LEGO1 0x10059c80 SYMBOL
// ?_Left@?$_Tree@PBDU?$pair@QBDPAVLegoTextureInfo@@@@U_Kfn@?$map@PBDPAVLegoTextureInfo@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@KAAAPAU_Node@1@PAU21@@Z

// TEMPLATE: LEGO1 0x10059c90 SYMBOL
// ?_Parent@?$_Tree@PBDU?$pair@QBDPAVLegoTextureInfo@@@@U_Kfn@?$map@PBDPAVLegoTextureInfo@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@KAAAPAU_Node@1@PAU21@@Z

// TEMPLATE: LEGO1 0x10059ca0 SYMBOL
// ?_Right@?$_Tree@PBDU?$pair@QBDPAVLegoTextureInfo@@@@U_Kfn@?$map@PBDPAVLegoTextureInfo@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@KAAAPAU_Node@1@PAU21@@Z

// TEMPLATE: LEGO1 0x10059cb0 SYMBOL
// ??1?$_Tree@PBDU?$pair@QBDPAVLegoTextureInfo@@@@U_Kfn@?$map@PBDPAVLegoTextureInfo@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@QAE@XZ

// TEMPLATE: LEGO1 0x10059d80 SYMBOL
// ?_Inc@iterator@?$_Tree@PBDU?$pair@QBDPAVLegoTextureInfo@@@@U_Kfn@?$map@PBDPAVLegoTextureInfo@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@QAEXXZ

// TEMPLATE: LEGO1 0x10059dc0 SYMBOL
// ?erase@?$_Tree@PBDU?$pair@QBDPAVLegoTextureInfo@@@@U_Kfn@?$map@PBDPAVLegoTextureInfo@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@QAE?AViterator@1@V21@@Z

// TEMPLATE: LEGO1 0x1005a210 SYMBOL
// ?_Erase@?$_Tree@PBDU?$pair@QBDPAVLegoTextureInfo@@@@U_Kfn@?$map@PBDPAVLegoTextureInfo@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@IAEXPAU_Node@1@@Z

// TEMPLATE: LEGO1 0x1005a250 SYMBOL
// ??1?$list@U?$pair@PAVLegoTextureInfo@@H@@V?$allocator@U?$pair@PAVLegoTextureInfo@@H@@@@@@QAE@XZ

// TEMPLATE: LEGO1 0x1005a2c0 SYMBOL
// ??1?$map@PBDPAVLegoTextureInfo@@ULegoContainerInfoComparator@@V?$allocator@PAVLegoTextureInfo@@@@@@QAE@XZ

// TEMPLATE: LEGO1 0x1005a310
// LegoContainer<LegoTextureInfo>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1005a400
// LegoContainerInfo<LegoTextureInfo>::~LegoContainerInfo<LegoTextureInfo>

// TEMPLATE: LEGO1 0x1005a450
// Map<char const *,LegoTextureInfo *,LegoContainerInfoComparator>::~Map<char const *,LegoTextureInfo *,LegoContainerInfoComparator>

// SYNTHETIC: LEGO1 0x1005a580
// LegoTextureContainer::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1005a5a0 SYMBOL
// ??1?$List@U?$pair@PAVLegoTextureInfo@@H@@@@QAE@XZ

// TEMPLATE: LEGO1 0x1005b660
// LegoContainer<LegoTextureInfo>::~LegoContainer<LegoTextureInfo>

// GLOBAL: LEGO1 0x100f0100
// _Tree<char const *,pair<char const * const,LegoTextureInfo *>,map<char const *,LegoTextureInfo *,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Kfn,LegoContainerInfoComparator,allocator<LegoTextureInfo *> >::_Nil
// clang-format on

// TEMPLATE: BETA10 0x1007bc00
// LegoContainer<LegoTextureInfo>::Get

#endif // LEGOCONTAINER_H
