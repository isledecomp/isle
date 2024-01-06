#include "viewlodlist.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(ViewLODListManager, 0x14);

// FUNCTION: LEGO1 0x100a6fd0
ViewLODListManager::ViewLODListManager()
{
}

// STUB: LEGO1 0x100a7130
ViewLODListManager::~ViewLODListManager()
{
	// TODO
}

// STUB: LEGO1 0x100a72c0
ViewLODList* ViewLODListManager::Create(const ROIName& rROIName, int lodCount)
{
	// returned ViewLODList has a refCount of 1, i.e. caller must call Release()
	// when it no longer holds on to the list

	ViewLODList* pLODList;
	int refCount;
	char* pROIName;

	assert(!Lookup(rROIName));

	pLODList = new ViewLODList(lodCount);
	refCount = pLODList->AddRef();
	assert(refCount == 1);

	pROIName = new char[strlen(rROIName) + 1];
	strcpy(pROIName, rROIName);

	m_map[pROIName] = pLODList;

	// NOTE: Lookup() adds a refCount
	assert((Lookup(rROIName) == pLODList) && (pLODList->Release() == 1));

	return pLODList;
}

// STUB: LEGO1 0x100a75b0
ViewLODList* ViewLODListManager::Lookup(const ROIName&) const
{
	return NULL;
}

// STUB: LEGO1 0x100a7680
void ViewLODListManager::Destroy(ViewLODList* lodList)
{
}
