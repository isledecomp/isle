#include "mxsmack.h"

#include <string.h>

DECOMP_SIZE_ASSERT(SmackTag, 0x390);
DECOMP_SIZE_ASSERT(MxSmack, 0x6b8);

// FUNCTION: LEGO1 0x100c5a90
MxResult MxSmack::LoadHeaderAndTrees(MxU8* p_data, MxSmack* p_mxSmack)
{
// Macros for readability
#define FRAME_COUNT(mxSmack) (p_mxSmack->m_smackTag.Frames + (p_mxSmack->m_smackTag.SmackerType & 1))

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

		memcpy(&p_mxSmack->m_smackTag, p_data, SmackHeaderSize(&p_mxSmack->m_smackTag));
		p_data += SmackHeaderSize(&p_mxSmack->m_smackTag);

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

				MxU32 treeSize = p_mxSmack->m_smackTag.tablesize + 0x1000;
				if (treeSize <= 0x2000)
					treeSize = 0x2000;

				huffmanTrees = new MxU8[treeSize];

				if (!huffmanTrees) {
					result = FAILURE;
				}
				else {
					memcpy(huffmanTrees + 0x1000, p_data, p_mxSmack->m_smackTag.tablesize);

					p_mxSmack->m_huffmanTables = new MxU8
						[p_mxSmack->m_smackTag.codesize + p_mxSmack->m_smackTag.absize +
						 p_mxSmack->m_smackTag.detailsize + p_mxSmack->m_smackTag.typesize + SmackGetSizeTables()];

					if (!p_mxSmack->m_huffmanTables) {
						result = FAILURE;
					}
					else {
						SmackDoTables(
							huffmanTrees,
							p_mxSmack->m_huffmanTables,
							p_mxSmack->m_smackTag.codesize,
							p_mxSmack->m_smackTag.absize,
							p_mxSmack->m_smackTag.detailsize,
							p_mxSmack->m_smackTag.typesize
						);

						MxU32 size =
							::SmackGetSizeDeltas(p_mxSmack->m_smackTag.Width, p_mxSmack->m_smackTag.Height) + 32;
						p_mxSmack->m_unk0x6b4 = new MxU8[size];
						memset(p_mxSmack->m_unk0x6b4, 0, size);

						MxS32 width = p_mxSmack->m_smackTag.Width;
						MxU32* data = (MxU32*) p_mxSmack->m_unk0x6b4;

						*data = 1;
						data++;
						*data = 0;
						data++;
						*data = p_mxSmack->m_smackTag.Width / 4;
						data++;
						*data = p_mxSmack->m_smackTag.Height / 4;
						data++;
						*data = width - 4;
						data++;
						*data = width * 3;
						data++;
						*data = width;
						data++;
						*data = width * 4 - p_mxSmack->m_smackTag.Width;
						data++;
						data++;
						*data = p_mxSmack->m_smackTag.Width;
						data++;
						*data = p_mxSmack->m_smackTag.Height;
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
