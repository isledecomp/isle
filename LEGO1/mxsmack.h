#ifndef MXSMACK_H
#define MXSMACK_H

#include "decomp.h"
#include "mxtypes.h"

#include <smack.h>

// These functions are not part of the public interface,
// but present in SMACK.LIB and used directly by Mindscape.
extern "C"
{
	// (SMACK.LIB) FUNCTION: LEGO1 0x100cd782
	u32 SmackGetSizeTables();

	// (SMACK.LIB) FUNCTION: LEGO1 0x100cd7e8
	void SmackDoTables(
		u8* p_huffmanTrees,
		u8* p_huffmanTables,
		u32 p_codeSize,
		u32 p_abSize,
		u32 p_detailSize,
		u32 p_typeSize
	);

	// (SMACK.LIB) FUNCTION: LEGO1 0x100d052c
	u32 SmackGetSizeDeltas(u32 p_width, u32 p_height);
}

// SIZE 0x6b8
struct MxSmack {
	SmackTag m_smackTag;       // 0x00
	undefined m_unk0x3f4[784]; // 0x390
	MxU32* m_frameSizes;       // 0x6a0
	MxU8* m_frameTypes;        // 0x6a4
	MxU8* m_huffmanTrees;      // 0x6a8
	MxU8* m_huffmanTables;     // 0x6ac
	MxU32 m_maxFrameSize;      // 0x6b0
	MxU8* m_unk0x6b4;          // 0x6b4

	static MxResult LoadHeaderAndTrees(MxU8* p_data, MxSmack* p_mxSmack);
	static void Destroy(MxSmack* p_mxSmack);
};

#endif // MXSMACK_H
