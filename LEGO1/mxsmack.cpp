#include "mxsmack.h"

#include <string.h>

DECOMP_SIZE_ASSERT(Smack, 0x390);
DECOMP_SIZE_ASSERT(Smack::Header, 0x68);
DECOMP_SIZE_ASSERT(MxSmack, 0x6b8);

// FUNCTION: LEGO1 0x100c5a90
MxResult MxSmack::LoadHeaderAndTrees(MxU8* p_data, MxSmack* p_mxSmack)
{
// Macros for readability
#define HEADER(mxSmack) mxSmack->m_smack.m_header
#define FRAME_COUNT(mxSmack) (HEADER(p_mxSmack).m_frames + (HEADER(p_mxSmack).m_smkType & 1))

	MxResult result = SUCCESS;
	MxU8* frameTypes = NULL;
	MxU8* huffmanTrees = NULL;

	if (!p_data || !p_mxSmack) {
		result = FAILURE;
	}
	else {
		p_mxSmack->m_frameTypes = NULL;
		p_mxSmack->m_frameSizes = NULL;
		p_mxSmack->m_huffmanTrees = NULL;
		p_mxSmack->m_huffmanTables = NULL;

		memcpy(&HEADER(p_mxSmack), p_data, sizeof(Smack::Header));
		p_data += sizeof(Smack::Header);

		MxU32* frameSizes = new MxU32[FRAME_COUNT(p_mxSmack)];

		if (!frameSizes) {
			result = FAILURE;
		}
		else {
			memcpy(frameSizes, p_data, FRAME_COUNT(p_mxSmack) * sizeof(MxU32));

			p_data += FRAME_COUNT(p_mxSmack) * sizeof(MxU32);
			p_mxSmack->m_maxFrameSize = 0;

			// TODO
			for (MxU32 i = 0; i < FRAME_COUNT(p_mxSmack); i++) {
				if (p_mxSmack->m_maxFrameSize < frameSizes[i])
					p_mxSmack->m_maxFrameSize = frameSizes[i];
			}

			frameTypes = new MxU8[FRAME_COUNT(p_mxSmack)];

			if (!frameTypes) {
				result = FAILURE;
			}
			else {
				memcpy(frameTypes, p_data, FRAME_COUNT(p_mxSmack));
				p_data += FRAME_COUNT(p_mxSmack);

				MxU32 treeSize = HEADER(p_mxSmack).m_treeSize + 0x1000;
				if (treeSize <= 0x2000)
					treeSize = 0x2000;

				huffmanTrees = new MxU8[treeSize];

				if (!huffmanTrees) {
					result = FAILURE;
				}
				else {
					memcpy(huffmanTrees + 0x1000, p_data, HEADER(p_mxSmack).m_treeSize);

					p_mxSmack->m_huffmanTables = new MxU8
						[HEADER(p_mxSmack).m_codeSize + HEADER(p_mxSmack).m_abSize + HEADER(p_mxSmack).m_detailSize +
						 HEADER(p_mxSmack).m_typeSize + SmackGetSizeTables()];

					if (!p_mxSmack->m_huffmanTables) {
						result = FAILURE;
					}
					else {
						SmackDoTables(
							huffmanTrees,
							p_mxSmack->m_huffmanTables,
							HEADER(p_mxSmack).m_codeSize,
							HEADER(p_mxSmack).m_abSize,
							HEADER(p_mxSmack).m_detailSize,
							HEADER(p_mxSmack).m_typeSize
						);

						MxU32 size = SmackGetSizeDeltas(HEADER(p_mxSmack).m_width, HEADER(p_mxSmack).m_height) + 32;
						p_mxSmack->m_unk0x6b4 = new MxU8[size];
						memset(p_mxSmack->m_unk0x6b4, 0, size);

						MxS32 width = HEADER(p_mxSmack).m_width;
						MxU32* data = (MxU32*) p_mxSmack->m_unk0x6b4;

						*data = 1;
						data++;
						*data = 0;
						data++;
						*data = HEADER(p_mxSmack).m_width / 4;
						data++;
						*data = HEADER(p_mxSmack).m_height / 4;
						data++;
						*data = width - 4;
						data++;
						*data = width * 3;
						data++;
						*data = width;
						data++;
						*data = width * 4 - HEADER(p_mxSmack).m_width;
						data++;
						data++;
						*data = HEADER(p_mxSmack).m_width;
						data++;
						*data = HEADER(p_mxSmack).m_height;
					}
				}
			}
		}

		p_mxSmack->m_frameTypes = frameTypes;
		p_mxSmack->m_frameSizes = frameSizes;
		p_mxSmack->m_huffmanTrees = huffmanTrees;
	}

	return result;

#undef FRAME_COUNT
#undef HEADER
}

// FUNCTION: LEGO1 0x100c5d40
void MxSmack::Destroy(MxSmack* p_mxSmack)
{
	if (p_mxSmack->m_frameSizes)
		delete[] p_mxSmack->m_frameSizes;
	if (p_mxSmack->m_frameTypes)
		delete[] p_mxSmack->m_frameTypes;
	if (p_mxSmack->m_huffmanTrees)
		delete[] p_mxSmack->m_huffmanTrees;
	if (p_mxSmack->m_huffmanTables)
		delete[] p_mxSmack->m_huffmanTables;
	if (p_mxSmack->m_unk0x6b4)
		delete[] p_mxSmack->m_unk0x6b4;
}

// Part of the Smacker SDK

// FUNCTION: LEGO1 0x100cd782
MxU32 MxSmack::SmackGetSizeTables()
{
	return 29800;
}

// STUB: LEGO1 0x100cd7e8
void MxSmack::SmackDoTables(
	MxU8* p_huffmanTrees,
	MxU8* p_huffmanTables,
	MxULong p_codeSize,
	MxULong p_abSize,
	MxULong p_detailSize,
	MxULong p_typeSize
)
{
	// TODO
}

// STUB: LEGO1 0x100d052c
MxULong MxSmack::SmackGetSizeDeltas(MxULong p_width, MxULong p_height)
{
	// TODO
	return 0;
}
