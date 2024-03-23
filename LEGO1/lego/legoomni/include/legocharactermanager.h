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

// TODO: generic string comparator?
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

	inline void AddRef() { m_refCount++; }

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
	static MxBool FUN_10084c00(const LegoChar*);

	void FUN_100832a0();
	void FUN_10083db0(LegoROI* p_roi);
	void FUN_10083f10(LegoROI* p_roi);
	LegoExtraActor* FUN_10084c40(const LegoChar*);
	LegoCharacterData* Find(const char* p_key);
	MxBool FUN_10084ec0(LegoROI* p_roi);
	MxU32 FUN_10085140(LegoROI*, MxBool);
	LegoROI* FUN_10085210(const LegoChar*, LegoChar*, undefined);
	LegoROI* FUN_10085a80(LegoChar* p_und1, LegoChar* p_und2, undefined p_und3);

	static const char* GetCustomizeAnimFile() { return g_customizeAnimFile; }

private:
	LegoROI* CreateROI(const char* p_key);

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

// GLOBAL: LEGO1 0x100fc508
// _Tree<char const *,pair<char const * const,LegoCharacter *>,map<char const *,LegoCharacter *,LegoCharacterComparator,allocator<LegoCharacter *> >::_Kfn,LegoCharacterComparator,allocator<LegoCharacter *> >::_Nil
// clang-format on

#endif // LEGOCHARACTERMANAGER_H
