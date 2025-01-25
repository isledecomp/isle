#ifndef VIEWLODLIST_H
#define VIEWLODLIST_H

#include "assert.h"
#include "compat.h"
#include "mxstl/stlcompat.h"
#include "realtime/lodlist.h"

#include <string.h>

#pragma warning(disable : 4237)
#pragma warning(disable : 4786)

class ViewLOD;
class ViewLODListManager;

//////////////////////////////////////////////////////////////////////////////
// ViewLODList
//
// An ViewLODList is an LODList that is shared among instances of the "same ROI".
//
// ViewLODLists are managed (created and destroyed) by ViewLODListManager.
//

// VTABLE: LEGO1 0x100dbdc4
// VTABLE: BETA10 0x101c34f0
// SIZE 0x18
class ViewLODList : public LODList<ViewLOD> {
	friend ViewLODListManager;

protected:
	ViewLODList(size_t capacity, ViewLODListManager* owner);
	~ViewLODList() override;

	// SYNTHETIC: LEGO1 0x100a80f0
	// SYNTHETIC: BETA10 0x1017b590
	// ViewLODList::`scalar deleting destructor'

public:
	inline int AddRef();
	inline int Release();

#ifdef _DEBUG
	void Dump(void (*pTracer)(const char*, ...)) const;
#endif

private:
	int m_refCount;              // 0x10
	ViewLODListManager* m_owner; // 0x14
};

//////////////////////////////////////////////////////////////////////////////
//

// ??? for now, until we have symbol management
typedef const char* ROIName;
struct ROINameComparator {
	// FUNCTION: BETA10 0x101794c0
	unsigned char operator()(const ROIName& rName1, const ROIName& rName2) const
	{
		return strcmp((const char*) rName1, (const char*) rName2) > 0;
	}
};

//////////////////////////////////////////////////////////////////////////////
//
// ViewLODListManager
//
// ViewLODListManager manages creation and sharing of ViewLODLists.
// It stores ViewLODLists under a name, the name of the ROI where
// the ViewLODList belongs.

// VTABLE: LEGO1 0x100dbdbc
// VTABLE: BETA10 0x101c34ec
// SIZE 0x14
class ViewLODListManager {

	typedef map<ROIName, ViewLODList*, ROINameComparator> ViewLODListMap;

public:
	ViewLODListManager();
	virtual ~ViewLODListManager();

	// ??? should LODList be const

	// creates an LODList with room for lodCount LODs for a named ROI
	// returned LODList has a refCount of 1, i.e. caller must call Release()
	// when it no longer holds on to the list
	ViewLODList* Create(const ROIName& rROIName, int lodCount);

	// returns an LODList for a named ROI
	// returned LODList's refCount is increased, i.e. caller must call Release()
	// when it no longer holds on to the list
	ViewLODList* Lookup(const ROIName&) const;
	unsigned char Destroy(ViewLODList* lodList);

#ifdef _DEBUG
	void Dump(void (*pTracer)(const char*, ...)) const;
#endif

	// SYNTHETIC: LEGO1 0x100a70c0
	// SYNTHETIC: BETA10 0x10178a80
	// ViewLODListManager::`scalar deleting destructor'

private:
	static int g_ROINameUID;

	ViewLODListMap m_map;
};

// clang-format off
// FUNCTION: LEGO1 0x1001dde0
// FUNCTION: BETA10 0x100223c0
// _Lockit::~_Lockit

// TEMPLATE: LEGO1 0x100a70e0
// TEMPLATE: BETA10 0x10178ac0
// Map<char const *,ViewLODList *,ROINameComparator>::~Map<char const *,ViewLODList *,ROINameComparator>

// TEMPLATE: LEGO1 0x100a7800
// _Tree<char const *,pair<char const * const,ViewLODList *>,map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::_Kfn,ROINameComparator,allocator<ViewLODList *> >::iterator::_Dec

// TEMPLATE: LEGO1 0x100a7850
// _Tree<char const *,pair<char const * const,ViewLODList *>,map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::_Kfn,ROINameComparator,allocator<ViewLODList *> >::iterator::_Inc

// TEMPLATE: LEGO1 0x100a7890
// _Tree<char const *,pair<char const * const,ViewLODList *>,map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::_Kfn,ROINameComparator,allocator<ViewLODList *> >::~_Tree<char const *,pair<char const * const,ViewLODList *>,map<char c

// TEMPLATE: LEGO1 0x100a7960
// TEMPLATE: BETA10 0x1017ab40
// _Tree<char const *,pair<char const * const,ViewLODList *>,map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::_Kfn,ROINameComparator,allocator<ViewLODList *> >::erase

// TEMPLATE: LEGO1 0x100a7db0
// TEMPLATE: BETA10 0x1017aca0
// _Tree<char const *,pair<char const * const,ViewLODList *>,map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::_Kfn,ROINameComparator,allocator<ViewLODList *> >::_Erase

// TEMPLATE: LEGO1 0x100a7df0
// TEMPLATE: BETA10 0x101796b0
// _Tree<char const *,pair<char const * const,ViewLODList *>,map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::_Kfn,ROINameComparator,allocator<ViewLODList *> >::_Insert

// TEMPLATE: LEGO1 0x100a80a0
// TEMPLATE: BETA10 0x1017b1e0
// map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::~map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >

// GLOBAL: LEGO1 0x10101068
// GLOBAL: BETA10 0x10205eb4
// _Tree<char const *,pair<char const * const,ViewLODList *>,map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::_Kfn,ROINameComparator,allocator<ViewLODList *> >::_Nil

// TEMPLATE: BETA10 0x101791f0
// map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::operator[]

// TEMPLATE: BETA10 0x10178c80
// _Tree<char const *,pair<char const * const,ViewLODList *>,map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::_Kfn,ROINameComparator,allocator<ViewLODList *> >::iterator::operator==

// TEMPLATE: BETA10 0x10178ef0
// map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::begin

// TEMPLATE: BETA10 0x10179070
// map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::end

// TEMPLATE: BETA10 0x10179250
// pair<char const * const,ViewLODList *>::pair<char const * const,ViewLODList *>

// TEMPLATE: BETA10 0x10179280
// map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::insert

// TEMPLATE: BETA10 0x101792c0
// _Tree<char const *,pair<char const * const,ViewLODList *>,map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::_Kfn,ROINameComparator,allocator<ViewLODList *> >::insert

// TEMPLATE: BETA10 0x10178c00
// _Tree<char const *,pair<char const * const,ViewLODList *>,map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::_Kfn,ROINameComparator,allocator<ViewLODList *> >::iterator::operator*

// TEMPLATE: BETA10 0x1017ab10
// map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::erase
// No symbol generated for this?
// Two iterators

// TEMPLATE: BETA10 0x1017a040
// ?erase@?$map@PBDPAVViewLODList@@UROINameComparator@@V?$allocator@PAVViewLODList@@@@@@QAE?AViterator@?$_Tree@PBDU?$pair@QBDPAVViewLODList@@@@U_Kfn@?$map@PBDPAVViewLODList@@UROINameComparator@@V?$allocator@PAVViewLODList@@@@@@UROINameComparator@@V?$allocato
// aka map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::erase
// One iterator

// TEMPLATE: BETA10 0x10178f80
// _Tree<char const *,pair<char const * const,ViewLODList *>,map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::_Kfn,ROINameComparator,allocator<ViewLODList *> >::_Lmost

// TEMPLATE: BETA10 0x10179e70
// _Tree<char const *,pair<char const * const,ViewLODList *>,map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::_Kfn,ROINameComparator,allocator<ViewLODList *> >::_Rmost

// TEMPLATE: BETA10 0x10179670
// _Tree<char const *,pair<char const * const,ViewLODList *>,map<char const *,ViewLODList *,ROINameComparator,allocator<ViewLODList *> >::_Kfn,ROINameComparator,allocator<ViewLODList *> >::_Color

// TEMPLATE: BETA10 0x1017aa30
// ?swap@@YAXAAW4_Redbl@?$_Tree@PBDU?$pair@QBDPAVViewLODList@@@@U_Kfn@?$map@PBDPAVViewLODList@@UROINameComparator@@V?$allocator@PAVViewLODList@@@@@@UROINameComparator@@V?$allocator@PAVViewLODList@@@@@@0@Z

// clang-format on

//////////////////////////////////////////////////////////////////////////////
//
// ViewLODList implementation

// FUNCTION: BETA10 0x1017b240
inline ViewLODList::ViewLODList(size_t capacity, ViewLODListManager* owner) : LODList<ViewLOD>(capacity), m_refCount(0)
{
	m_owner = owner;
}

inline ViewLODList::~ViewLODList()
{
	assert(m_refCount == 0);
}

// FUNCTION: BETA10 0x1007b5b0
inline int ViewLODList::AddRef()
{
	return ++m_refCount;
}

// FUNCTION: BETA10 0x1007ad70
inline int ViewLODList::Release()
{
	assert(m_refCount > 0);
	if (!--m_refCount) {
		m_owner->Destroy(this);
		return 0;
	}

	return m_refCount;
}

#endif // VIEWLODLIST_H
