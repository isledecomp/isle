#ifndef MXSMK_H
#define MXSMK_H

#include "decomp.h"
#include "mxgeometry.h"
#include "mxtypes.h"

#include <smack.h>

struct MxBITMAPINFO;

// These functions are not part of the public interface,
// but present in SMACK.LIB and used directly by Mindscape.
extern "C"
{
	u32 SmackGetSizeTables();
	void SmackDoTables(
		u8* p_huffmanTrees,
		u8* p_huffmanTables,
		u32 p_codeSize,
		u32 p_abSize,
		u32 p_detailSize,
		u32 p_typeSize
	);
	void SmackDoFrameToBuffer(u8* p_source, u8* p_huffmanTables, u8* p_unk0x6b4);
	u32 SmackGetSizeDeltas(u32 p_width, u32 p_height);
	u8 SmackGetRect(u8* p_unk0x6b4, u32* p_rect);
}

// SIZE 0x6b8
struct MxSmk {
	SmackTag m_smackTag;       // 0x00
	undefined m_unk0x390[784]; // 0x390
	MxU32* m_frameSizes;       // 0x6a0
	MxU8* m_frameTypes;        // 0x6a4
	MxU8* m_huffmanTrees;      // 0x6a8
	MxU8* m_huffmanTables;     // 0x6ac
	MxU32 m_maxFrameSize;      // 0x6b0
	MxU8* m_unk0x6b4;          // 0x6b4

	static MxResult LoadHeader(MxU8* p_data, MxSmk* p_mxSmk);
	static void Destroy(MxSmk* p_mxSmk);
	static MxResult LoadFrame(
		MxBITMAPINFO* p_bitmapInfo,
		MxU8* p_bitmapData,
		MxSmk* p_mxSmk,
		MxU8* p_chunkData,
		MxBool p_paletteChanged,
		MxRect32List* p_list
	);
	static MxBool GetRect(MxU8* p_unk0x6b4, MxU16* p_und, u32* p_smackRect, MxRect32* p_rect);
};

#endif // MXSMK_H
