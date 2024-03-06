#ifndef LEGOUNKSAVEDATAWRITER_H
#define LEGOUNKSAVEDATAWRITER_H

#include "decomp.h"
#include "legovariables.h"
#include "misc/legostorage.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

class LegoROI;

#pragma warning(disable : 4237)

// TODO: generic string comparator?
struct LegoUnkSaveDataMapComparator {
	bool operator()(const char* const& p_a, const char* const& p_b) const { return strcmpi(p_a, p_b) > 0; }
};

// TODO: pair instead?
// SIZE 0x08
struct LegoUnkSaveDataMapValue {
	LegoROI* m_roi;  // 0x00
	MxU32 m_counter; // 0x04
};

typedef map<char*, LegoUnkSaveDataMapValue*, LegoUnkSaveDataMapComparator> LegoUnkSaveDataMap;

struct LegoSaveDataEntry3 {
	char* m_name;
	void* m_unk0x04;
	void* m_unk0x08;
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
class LegoUnkSaveDataWriter {
public:
	LegoUnkSaveDataWriter();

	MxResult WriteSaveData3(LegoStorage* p_storage);
	MxResult ReadSaveData3(LegoStorage* p_storage);
	LegoROI* FUN_10083500(const char*, MxBool);

	void InitSaveData();
	static void SetCustomizeAnimFile(const char* p_value);
	static MxBool FUN_10084c00(const LegoChar*);

	void FUN_100832a0();
	void FUN_10083db0(LegoROI* p_roi);
	void FUN_10083f10(LegoROI* p_roi);
	MxU32 FUN_10085140(LegoROI*, MxBool);
	LegoROI* FUN_10085210(const LegoChar*, LegoChar*, undefined);
	LegoROI* FUN_10085a80(LegoChar* p_und1, LegoChar* p_und2, undefined p_und3);

	static const char* GetCustomizeAnimFile() { return g_customizeAnimFile; }

private:
	static char* g_customizeAnimFile;

	LegoUnkSaveDataMap* m_map;                      // 0x00
	CustomizeAnimFileVariable* m_customizeAnimFile; // 0x04
};

// clang-format off

// FUNCTION: LEGO1 0x10082b90
// _Tree<char *,pair<char * const,LegoUnkSaveDataMapValue *>,map<char *,LegoUnkSaveDataMapValue *,LegoUnkSaveDataMapComparator,allocator<LegoUnkSaveDataMapValue *> >::_Kfn,LegoUnkSaveDataMapComparator,allocator<LegoUnkSaveDataMapValue *> >::~_Tree<char *,pair<char * const,LegoUnkSaveDataMapValue *>,map<char *,LegoUnkSaveDataMapValue *,LegoUnkSaveDataMapComparator,allocator<LegoUnkSaveDataMapValue *> >::_Kfn,LegoUnkSaveDataMapComparator,allocator<LegoUnkSaveDataMapValue *> >

// FUNCTION: LEGO1 0x10082c60
// _Tree<char *,pair<char * const,LegoUnkSaveDataMapValue *>,map<char *,LegoUnkSaveDataMapValue *,LegoUnkSaveDataMapComparator,allocator<LegoUnkSaveDataMapValue *> >::_Kfn,LegoUnkSaveDataMapComparator,allocator<LegoUnkSaveDataMapValue *> >::iterator::_Inc

// FUNCTION: LEGO1 0x10082ca0
// _Tree<char *,pair<char * const,LegoUnkSaveDataMapValue *>,map<char *,LegoUnkSaveDataMapValue *,LegoUnkSaveDataMapComparator,allocator<LegoUnkSaveDataMapValue *> >::_Kfn,LegoUnkSaveDataMapComparator,allocator<LegoUnkSaveDataMapValue *> >::erase

// FUNCTION: LEGO1 0x100830f0
// _Tree<char *,pair<char * const,LegoUnkSaveDataMapValue *>,map<char *,LegoUnkSaveDataMapValue *,LegoUnkSaveDataMapComparator,allocator<LegoUnkSaveDataMapValue *> >::_Kfn,LegoUnkSaveDataMapComparator,allocator<LegoUnkSaveDataMapValue *> >::_Erase

// FUNCTION: LEGO1 0x10083130
// map<char *,LegoUnkSaveDataMapValue *,LegoUnkSaveDataMapComparator,allocator<LegoUnkSaveDataMapValue *> >::~map<char *,LegoUnkSaveDataMapValue *,LegoUnkSaveDataMapComparator,allocator<LegoUnkSaveDataMapValue *> >

// GLOBAL: LEGO1 0x100fc508
// _Tree<char *,pair<char * const,LegoUnkSaveDataMapValue *>,map<char *,LegoUnkSaveDataMapValue *,LegoUnkSaveDataMapComparator,allocator<LegoUnkSaveDataMapValue *> >::_Kfn,LegoUnkSaveDataMapComparator,allocator<LegoUnkSaveDataMapValue *> >::_Nil

// clang-format on

#endif // LEGOUNKSAVEDATAWRITER_H
