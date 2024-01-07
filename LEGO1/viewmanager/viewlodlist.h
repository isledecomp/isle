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

class ViewLODList : public LODList<ViewLOD> {
	friend ViewLODListManager;

protected:
	ViewLODList(size_t capacity);
	~ViewLODList();

public:
	inline int AddRef();
	inline int Release();

#ifdef _DEBUG
	void Dump(void (*pTracer)(const char*, ...)) const;
#endif

private:
	int m_refCount;
	ViewLODListManager* m_owner;
};

//////////////////////////////////////////////////////////////////////////////
//

// ??? for now, until we have symbol management
typedef const char* ROIName;
struct ROINameComparator {
	bool operator()(const ROIName& rName1, const ROIName& rName2) const
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
	void Destroy(ViewLODList* lodList);

#ifdef _DEBUG
	void Dump(void (*pTracer)(const char*, ...)) const;
#endif

private:
	ViewLODListMap m_map;
};

//////////////////////////////////////////////////////////////////////////////
//
// ViewLODList implementation

inline ViewLODList::ViewLODList(size_t capacity) : LODList<ViewLOD>(capacity), m_refCount(0)
{
}

inline ViewLODList::~ViewLODList()
{
	assert(m_refCount == 0);
}

inline int ViewLODList::AddRef()
{
	return ++m_refCount;
}

inline int ViewLODList::Release()
{
	assert(m_refCount > 0);
	if (!--m_refCount)
		m_owner->Destroy(this);
	return m_refCount;
}

#endif // VIEWLODLIST_H
