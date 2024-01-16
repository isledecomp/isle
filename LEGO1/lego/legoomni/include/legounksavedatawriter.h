#ifndef LEGOUNKSAVEDATAWRITER_H
#define LEGOUNKSAVEDATAWRITER_H

#include "decomp.h"
#include "mxtypes.h"

class LegoROI;
class LegoStream;

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

class LegoUnkSaveDataWriter {
public:
	MxResult WriteSaveData3(LegoStream* p_stream);
	void FUN_10083db0(LegoROI* p_roi);
};

#endif // LEGOUNKSAVEDATAWRITER_H
