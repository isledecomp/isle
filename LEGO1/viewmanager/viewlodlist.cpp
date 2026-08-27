#include "viewlodlist.h"

#include "decomp.h"
#include "viewlod.h"

#include <stdio.h>

DECOMP_SIZE_ASSERT(ViewLODListManager, 0x14)
DECOMP_SIZE_ASSERT(LODListBase, 0x10)
DECOMP_SIZE_ASSERT(LODList<ViewLOD>, 0x10)
DECOMP_SIZE_ASSERT(ViewLODList, 0x18)

// GLOBAL: LEGO1 0x10101064
// GLOBAL: BETA10 0x10205d08
int ViewLODListManager::g_ROINameUID = 0;

#ifdef _DEBUG
// FUNCTION: BETA10 0x10178310
inline void ViewLODList::Dump(void (*pTracer)(const char*, ...)) const
{
	pTracer("   ViewLODList<0x%x>: Capacity=%d, Size=%d, RefCount=%d\n", this, Capacity(), Size(), m_refCount);

	for (int i = 0; i < (int) Size(); i++) {
		ViewLOD* lod = const_cast<ViewLOD*>(this->operator[](i));
		pTracer("      [%d]: ViewLOD<0x%x>: Vertices=%d\n", i, lod, lod->NVerts());
	}
}
#endif

// FUNCTION: LEGO1 0x100a6fd0
// FUNCTION: BETA10 0x101783a3
ViewLODListManager::ViewLODListManager()
{
}

// FUNCTION: LEGO1 0x100a7130
// FUNCTION: BETA10 0x1017841c
// FUNCTION: ALPHA 0x100e3402
ViewLODListManager::~ViewLODListManager()
{
	ViewLODListMap::iterator iterator;

	// delete all ViewLODLists
	for (iterator = m_map.begin(); !(iterator == m_map.end()); ++iterator) {
		const ROIName& rROIName = (*iterator).first;
		ViewLODList* pLODList = (*iterator).second;

		// ???who pops and deletes LODObjects
		while (pLODList->Size() > 0) {
			delete const_cast<ViewLOD*>(pLODList->PopBack());
		}

		delete pLODList;
		// ??? for now
		delete[] const_cast<char*>(rROIName);
	}

	// ??? correct way of "emptying" map
	m_map.erase(m_map.begin(), m_map.end());

	assert(m_map.begin() == m_map.end());
}

// FUNCTION: LEGO1 0x100a72c0
// FUNCTION: BETA10 0x101785ef
// FUNCTION: ALPHA 0x100e35d2
ViewLODList* ViewLODListManager::Create(const ROIName& rROIName, int lodCount)
{
	// returned ViewLODList has a refCount of 1, i.e. caller must call Release()
	// when it no longer holds on to the list

	ViewLODList* pLODList;
	int refCount;
	char* pROIName;

	// assert(!Lookup(rROIName)); // alpha only

	pLODList = new ViewLODList(lodCount, this);
	refCount = pLODList->AddRef();
	assert(refCount == 1);

	ViewLODList* list = Lookup(rROIName);
	if (list != NULL) {
		list->Release();

		char num[12];
		sprintf(num, "%d", g_ROINameUID);
		pROIName = new char[strlen(rROIName) + strlen(num) + 1];
		strcpy(pROIName, rROIName);
		strcat(pROIName, num);
		g_ROINameUID++;
	}
	else {
		pROIName = new char[strlen(rROIName) + 1];
		strcpy(pROIName, rROIName);
	}

	m_map[pROIName] = pLODList;

	// NOTE: Lookup() adds a refCount
	assert((Lookup(pROIName) == pLODList) && (pLODList->Release() == 1));

	return pLODList;
}

// FUNCTION: LEGO1 0x100a75b0
// FUNCTION: BETA10 0x101787d8
ViewLODList* ViewLODListManager::Lookup(const ROIName& p_roiName) const
{
	// returned ViewLODList's refCount is increased, i.e. caller must call Release()
	// when it no longer holds on to the list

	ViewLODListMap::const_iterator iterator = m_map.find(p_roiName);
	ViewLODList* pLODList = 0;

	if (!(iterator == m_map.end())) {
		pLODList = (*iterator).second;

		assert(pLODList);
		pLODList->AddRef();
	}

	return pLODList;
}

// FUNCTION: LEGO1 0x100a7680
// FUNCTION: BETA10 0x1017886b
unsigned char ViewLODListManager::Destroy(ViewLODList* lodList)
{
	ViewLODListMap::iterator iterator;
	char deleted = FALSE;

	for (iterator = m_map.begin(); !(iterator == m_map.end()); ++iterator) {
		const ROIName& rROIName = (*iterator).first;
		ViewLODList* pLODList = (*iterator).second;

		if (lodList == pLODList) {
			while (pLODList->Size() > 0) {
				delete const_cast<ViewLOD*>(pLODList->PopBack());
			}

			delete pLODList;
			delete[] const_cast<char*>(rROIName);
			m_map.erase(iterator);

			deleted = TRUE;
			break;
		}
	}

	return deleted;
}
