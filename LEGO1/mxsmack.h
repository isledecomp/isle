#ifndef MXSMACK_H
#define MXSMACK_H

#include "decomp.h"
#include "mxtypes.h"

#include <smk.h>

// SIZE 0x6b8
struct MxSmack {
	Smack m_smack;             // 0x00
	undefined m_unk0x3f4[784]; // 0x390
	MxU32* m_frameSizes;       // 0x6a0
	MxU8* m_frameTypes;        // 0x6a4
	MxU8* m_huffmanTrees;      // 0x6a8
	MxU8* m_huffmanTables;     // 0x6ac
	MxU32 maxFrameSize;        // 0x6b0
	MxU8* m_unk0x6b4;          // 0x6b4

	static MxResult LoadHeaderAndTrees(MxU8* p_data, MxSmack* p_mxSmack);
	static void Destroy(MxSmack* p_mxSmack);
	static MxU32 FUN_100cd782();
	static void DecodeHuffmanTrees(
		MxU8* p_huffmanTrees,
		MxU8* p_huffmanTables,
		MxULong p_codeSize,
		MxULong p_abSize,
		MxULong p_detailSize,
		MxULong p_typeSize
	);
	static MxULong FUN_100d052c(MxULong p_width, MxULong p_height);
};

#endif // MXSMACK_H
