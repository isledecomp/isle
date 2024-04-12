#ifndef LEGOCHARACTERMANAGER_H
#define LEGOCHARACTERMANAGER_H

#include "decomp.h"
#include "legoextraactor.h"
#include "legovariables.h"
#include "misc/legostorage.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

class LegoActor;
class LegoROI;

#pragma warning(disable : 4237)

struct LegoCharacterComparator {
	MxBool operator()(const char* const& p_a, const char* const& p_b) const { return strcmpi(p_a, p_b) < 0; }
};

// SIZE 0x08
struct LegoCharacter {
	LegoCharacter(LegoROI* p_roi)
	{
		m_roi = p_roi;
		m_refCount = 1;
	}
	~LegoCharacter() { delete m_roi; }

	inline void AddRef() { m_refCount++; }
	inline MxU32 RemoveRef()
	{
		if (m_refCount != 0) {
			m_refCount--;
		}

		return m_refCount;
	}

	LegoROI* m_roi;   // 0x00
	MxU32 m_refCount; // 0x04
};

struct LegoCharacterData;

typedef map<const char*, LegoCharacter*, LegoCharacterComparator> LegoCharacterMap;

// SIZE 0x08
class LegoCharacterManager {
public:
	LegoCharacterManager();

	MxResult Write(LegoStorage* p_storage);
	MxResult Read(LegoStorage* p_storage);
	LegoROI* GetROI(const char* p_key, MxBool p_createEntity);

	void Init();
	static void SetCustomizeAnimFile(const char* p_value);
	static MxBool Exists(const char* p_key);

	void FUN_100832a0();
	MxU32 GetRefCount(LegoROI* p_roi);
	void FUN_10083db0(LegoROI* p_roi);
	void FUN_10083f10(LegoROI* p_roi);
	LegoExtraActor* GetActor(const char* p_key);
	LegoCharacterData* GetData(const char* p_key);
	LegoCharacterData* GetData(LegoROI* p_roi);
	MxBool FUN_10084ec0(LegoROI* p_roi);
	MxU32 FUN_10085140(LegoROI* p_roi, MxBool p_und);
	LegoROI* FUN_10085210(const char* p_name, const char* p_lodName, MxBool p_createEntity);
	LegoROI* FUN_10085a80(const char* p_name, const char* p_lodName, MxBool p_createEntity);

	static const char* GetCustomizeAnimFile() { return g_customizeAnimFile; }

private:
	LegoROI* CreateROI(const char* p_key);
	void RemoveROI(LegoROI* p_roi);
	LegoROI* FUN_10084cf0(LegoROI* p_roi, const char* p_name);
	MxResult FUN_10085870(LegoROI* p_roi);

	static char* g_customizeAnimFile;

	LegoCharacterMap* m_characters;                 // 0x00
	CustomizeAnimFileVariable* m_customizeAnimFile; // 0x04
};

// clang-format off
// TEMPLATE: LEGO1 0x1001a690
// list<ROI *,allocator<ROI *> >::_Buynode

// TEMPLATE: LEGO1 0x10035790
// _Construct

// TEMPLATE: LEGO1 0x10082b90
// _Tree<char const *,pair<char const * const,LegoCharacter *>,map<char const *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::~_Tree<char const *,pair<char const * const,LegoCharacter *>,map<char const *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >

// TEMPLATE: LEGO1 0x10082c60
// _Tree<char const *,pair<char const * const,LegoCharacter *>,map<char const *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::iterator::_Inc

// TEMPLATE: LEGO1 0x10082ca0
// _Tree<char const *,pair<char const * const,LegoCharacter *>,map<char const *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::erase

// TEMPLATE: LEGO1 0x100830f0
// _Tree<char const *,pair<char const * const,LegoCharacter *>,map<char const *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::_Erase

// TEMPLATE: LEGO1 0x10083130
// map<char *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::~map<char *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >

// TEMPLATE: LEGO1 0x10083840
// _Tree<char const *,pair<char const * const,LegoCharacter *>,map<char const *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::iterator::_Dec

// TEMPLATE: LEGO1 0x10083890
// _Tree<char const *,pair<char const * const,LegoCharacter *>,map<char const *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::_Insert

// TEMPLATE: LEGO1 0x10085500
// _Tree<char const *,pair<char const * const,LegoCharacter *>,map<char const *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::insert

// TEMPLATE: LEGO1 0x10085790
// _Tree<char const *,pair<char const * const,LegoCharacter *>,map<char const *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::_Buynode

// TEMPLATE: LEGO1 0x100857b0
// _Tree<char const *,pair<char const * const,LegoCharacter *>,map<char const *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::_Lrotate

// TEMPLATE: LEGO1 0x10085810
// _Tree<char const *,pair<char const * const,LegoCharacter *>,map<char const *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::_Rrotate

// GLOBAL: LEGO1 0x100fc508
// _Tree<char const *,pair<char const * const,LegoCharacter *>,map<char const *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::_Nil
// clang-format on

#endif // LEGOCHARACTERMANAGER_H
