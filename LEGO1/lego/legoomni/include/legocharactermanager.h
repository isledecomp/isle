#ifndef LEGOCHARACTERMANAGER_H
#define LEGOCHARACTERMANAGER_H

#include "decomp.h"
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

typedef map<const char*, LegoCharacter*, LegoCharacterComparator> LegoCharacterMap;

struct LegoSaveDataEntry3 {
	char* m_name;
	void* m_unk0x04;
	LegoActor* m_actor;
	MxS32 m_savePart1;
	MxS32 m_savePart2;
	MxU8 m_savePart3;
	undefined4 m_unk0x18[6];
	MxU8 m_frameOffsetInDwords; // 0x30
	MxS32* m_pFrameData;
	MxU8 m_currentFrame;
	undefined4 m_unk0x3c[2];
	MxU8 m_savePart5; // 0x44
	undefined4 m_unk0x48[5];
	MxU8 m_savePart6; // 0x5c
	undefined4 m_unk0x60[11];
	MxU8 m_savePart7; // 0x8c
	undefined4 m_unk0x90[5];
	MxU8 m_savePart8; // 0xa4
	undefined4 m_unk0xa8[17];
	MxU8 m_savePart9; // 0xec
	undefined4 m_unk0xf0[5];
	MxU8 m_savePart10; // 0x104
};

// SIZE 0x08
class LegoCharacterManager {
public:
	LegoCharacterManager();

	MxResult WriteSaveData3(LegoStorage* p_storage);
	MxResult ReadSaveData3(LegoStorage* p_storage);
	LegoROI* GetROI(const char* p_key, MxBool p_createEntity);

	void InitSaveData();
	static void SetCustomizeAnimFile(const char* p_value);
	static MxBool FUN_10084c00(const LegoChar*);

	void FUN_100832a0();
	void FUN_10083db0(LegoROI* p_roi);
	void FUN_10083f10(LegoROI* p_roi);
	LegoSaveDataEntry3* FUN_10084c60(const char* p_key);
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
