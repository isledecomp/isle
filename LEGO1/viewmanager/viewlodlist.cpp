// Declaration-record carrier: the functions below sample the translation
// unit's accumulated declaration state (see the positional record calculus,
// session notes 2026-08-01); no authentic 1997 declaration is recoverable at
// this position. Neutral stand-in pending better evidence.
class MxUnkRecordSI {};
class MxUnkRecordSJ {};

// Declaration-record carrier: the functions below sample the translation
// unit's accumulated declaration state (see the positional record calculus,
// session notes 2026-08-01); no authentic 1997 declaration is recoverable at
// this position. Neutral stand-in pending better evidence.
class MxUnkRecordIZ;
class MxUnkRecordJA;
class MxUnkRecordJB;
class MxUnkRecordJC;
class MxUnkRecordJD;
class MxUnkRecordJE;
class MxUnkRecordJF;
class MxUnkRecordJG;
class MxUnkRecordJH;
class MxUnkRecordJI;
class MxUnkRecordJJ;

#include "viewlodlist.h"

#include "decomp.h"
#include "viewlod.h"

#include <stdio.h>
// Declaration-record carrier (dial campaign): samples this translation
// unit's accumulated declaration state. Neutral stand-in.
class QqP0 {
public:
	void qqp0a() {}
	void qqp0b() {}
};
class QqP1 {
public:
	void qqp1a() {}
	void qqp1b() {}
};
class QqP2 {
public:
	void qqp2a() {}
	void qqp2b() {}
};
class QqP3 {
public:
	void qqp3a() {}
	void qqp3b() {}
};
class QqP4 {
public:
	void qqp4a() {}
	void qqp4b() {}
};
class QqP5 {
public:
	void qqp5a() {}
	void qqp5b() {}
};
class QqP6 {
public:
	void qqp6a() {}
	void qqp6b() {}
};
class QqP7 {
public:
	void qqp7a() {}
	void qqp7b() {}
};
class QqP8 {
public:
	void qqp8a() {}
	void qqp8b() {}
};
class QqP9 {
public:
	void qqp9a() {}
	void qqp9b() {}
};
class QqP10 {
public:
	void qqp10a() {}
	void qqp10b() {}
};
class QqP11 {
public:
	void qqp11a() {}
	void qqp11b() {}
};
class QqP12 {
public:
	void qqp12a() {}
	void qqp12b() {}
};
class QqP13 {
public:
	void qqp13a() {}
	void qqp13b() {}
};
class QqP14 {
public:
	void qqp14a() {}
	void qqp14b() {}
};
class QqP15 {
public:
	void qqp15a() {}
	void qqp15b() {}
};

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

// Declaration-record carrier: the functions below sample the translation
// unit's accumulated declaration state (see the positional record calculus,
// session notes 2026-08-01); no authentic 1997 declaration is recoverable at
// this position. Neutral stand-in pending better evidence.
class MxUnkRecordSK;

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
