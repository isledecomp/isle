#include "mxsmack.h"

#include <string.h>

DECOMP_SIZE_ASSERT(SmackTag, 0x390);
DECOMP_SIZE_ASSERT(MxSmack, 0x6b8);

// FUNCTION: LEGO1 0x100c5a90
MxResult MxSmack::LoadHeader(MxU8* p_data, MxSmack* p_mxSmack)
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
				if (p_mxSmack->m_maxFrameSize < frameSizes[i]) {
					p_mxSmack->m_maxFrameSize = frameSizes[i];
				}
			}

			frameTypes = new MxU8[FRAME_COUNT(p_mxSmack)];

			if (!frameTypes) {
				result = FAILURE;
			}
			else {
				memcpy(frameTypes, p_data, FRAME_COUNT(p_mxSmack));
				p_data += FRAME_COUNT(p_mxSmack);

				MxU32 treeSize = p_mxSmack->m_smackTag.tablesize + 0x1000;
				if (treeSize <= 0x2000) {
					treeSize = 0x2000;
				}

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

						MxU32 size = SmackGetSizeDeltas(p_mxSmack->m_smackTag.Width, p_mxSmack->m_smackTag.Height) + 32;
						p_mxSmack->m_unk0x6b4 = new MxU8[size];
						memset(p_mxSmack->m_unk0x6b4, 0, size);

						MxS32 width = p_mxSmack->m_smackTag.Width;
						MxU32* data = (MxU32*) p_mxSmack->m_unk0x6b4;

						*data = 1;
						data++;
						*data = NULL; // MxU8* bitmapData
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
	if (p_mxSmack->m_frameSizes) {
		delete[] p_mxSmack->m_frameSizes;
	}
	if (p_mxSmack->m_frameTypes) {
		delete[] p_mxSmack->m_frameTypes;
	}
	if (p_mxSmack->m_huffmanTrees) {
		delete[] p_mxSmack->m_huffmanTrees;
	}
	if (p_mxSmack->m_huffmanTables) {
		delete[] p_mxSmack->m_huffmanTables;
	}
	if (p_mxSmack->m_unk0x6b4) {
		delete[] p_mxSmack->m_unk0x6b4;
	}
}

// This should be refactored to somewhere else
inline MxLong AbsFlipped(MxLong p_value)
{
	return p_value > 0 ? p_value : -p_value;
}

// FUNCTION: LEGO1 0x100c5db0
MxResult MxSmack::LoadFrame(
	MxBITMAPINFO* p_bitmapInfo,
	MxU8* p_bitmapData,
	MxSmack* p_mxSmack,
	MxU8* p_chunkData,
	MxBool p_paletteChanged,
	MxRectList* p_list
)
{
	p_bitmapInfo->m_bmiHeader.biHeight = -AbsFlipped(p_bitmapInfo->m_bmiHeader.biHeight);
	*(MxU8**) (p_mxSmack->m_unk0x6b4 + 4) = p_bitmapData;

	// Reference: https://wiki.multimedia.cx/index.php/Smacker#Palette_Chunk
	if (p_paletteChanged) {
		MxU8 palette[772];

		MxU8* intoChunk = p_chunkData + 1;
		MxU8* intoPalette = palette;
		MxU16 paletteIndex = 0;
		// TODO: struct incorrect, Palette at wrong offset?
		MxU8* currentPalette = &p_mxSmack->m_smackTag.Palette[4];

		do {
			if (*intoChunk & 0x80) {
				MxU8 length = (*intoChunk & 0x7f) + 1;
				memcpy(intoPalette, &currentPalette[paletteIndex * 3], length * 3);
				intoPalette += length * 3;
				paletteIndex += length;
				intoChunk++;
			}
			else {
				if (*intoChunk & 0x40) {
					MxU8 length = (*intoChunk & 0x3f) + 1;
					memcpy(intoPalette, &currentPalette[*(intoChunk + 1) * 3], length * 3);
					intoPalette += length * 3;
					paletteIndex += length;
					intoChunk += 2;
				}
				else {
					*(MxU32*) intoPalette = *(MxU32*) intoChunk;
					intoPalette += 3;
					paletteIndex++;
					intoChunk += 3;
				}
			}
		} while (paletteIndex < 256);

		for (MxU32 i = 0; i < 256; i++) {
			memcpy(currentPalette, &palette[i * 3], 3);
			currentPalette += 3;
			p_bitmapInfo->m_bmiColors[i].rgbBlue = palette[i * 3 + 2] * 4;
			p_bitmapInfo->m_bmiColors[i].rgbGreen = palette[i * 3 + 1] * 4;
			p_bitmapInfo->m_bmiColors[i].rgbRed = palette[i * 3] * 4;
		}

		p_chunkData += *p_chunkData * 4;
	}

	SmackDoFrameToBuffer(p_chunkData, p_mxSmack->m_huffmanTables, p_mxSmack->m_unk0x6b4);

	MxU16 und = 1;
	u32 smackRect[4];
	MxRect32 rect;

	while (GetRect(p_mxSmack->m_unk0x6b4, &und, smackRect, &rect)) {
		MxRect32* newRect = new MxRect32(rect);
		p_list->Append(newRect);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c6050
MxBool MxSmack::GetRect(MxU8* p_unk0x6b4, MxU16* p_und, u32* p_smackRect, MxRect32* p_rect)
{
	u32 left, bottom, top, right;

	if (!*p_und) {
		return FALSE;
	}

	if (*p_und == 1) {
		if (!SmackGetRect(p_unk0x6b4, p_smackRect)) {
			return FALSE;
		}
		*p_und = 2;
	}

	left = p_smackRect[0];
	top = p_smackRect[1];
	right = p_smackRect[2] + p_smackRect[0];
	bottom = p_smackRect[3] + p_smackRect[1];

	while (SmackGetRect(p_unk0x6b4, p_smackRect)) {
		if (left > p_smackRect[0]) {
			left = p_smackRect[0];
		}
		if (right < p_smackRect[0] + p_smackRect[2]) {
			right = p_smackRect[0] + p_smackRect[2];
		}

		bottom = p_smackRect[1] + p_smackRect[3];
	}

	*p_und = 0;
	*p_rect = MxRect32(left, top, right, bottom);
	return TRUE;
}
