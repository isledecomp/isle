#include "mxsmk.h"

#include "mxbitmap.h"

#include <string.h>

DECOMP_SIZE_ASSERT(SmackTag, 0x390);
DECOMP_SIZE_ASSERT(MxSmk, 0x6b8);

// FUNCTION: LEGO1 0x100c5a90
// FUNCTION: BETA10 0x10151e70
MxResult MxSmk::LoadHeader(MxU8* p_data, MxSmk* p_mxSmk)
{
// Macros for readability
// If bit0 of SmackerType is set, there is an extra frame ("ring frame")
// at the end. It is a duplicate of the first frame to simplify looping.
#define FRAME_COUNT(_tag) (_tag->Frames + (_tag->SmackerType & 1))

	MxResult result = SUCCESS;
	MxU32* frameSizes = NULL;
	MxU8* frameTypes = NULL;
	MxU8* huffmanTrees = NULL;
	MxU32 sizetables = 0;

	// Forced to declare here because of the gotos.
	MxU32 i;
	MxU32 treeSize;
	MxU32* data;
	MxU32 size;
	MxS32 width;

	if (!p_data || !p_mxSmk) {
		return FAILURE;
	}

	SmackTag* smackTag = &p_mxSmk->m_smackTag;
	p_mxSmk->m_frameTypes = NULL;
	p_mxSmk->m_frameSizes = NULL;
	p_mxSmk->m_huffmanTrees = NULL;
	p_mxSmk->m_huffmanTables = NULL;

	memcpy(smackTag, p_data, SmackHeaderSize(smackTag));
	p_data += SmackHeaderSize(smackTag);

	frameSizes = new MxU32[FRAME_COUNT(smackTag)];

	if (!frameSizes) {
		result = FAILURE;
		goto done;
	}

	memcpy(frameSizes, p_data, FRAME_COUNT(smackTag) * sizeof(MxU32));

	p_data += FRAME_COUNT(smackTag) * sizeof(MxU32);
	p_mxSmk->m_maxFrameSize = 0;

	for (i = 0; i < FRAME_COUNT(smackTag); i++) {
		if (p_mxSmk->m_maxFrameSize < frameSizes[i]) {
			p_mxSmk->m_maxFrameSize = frameSizes[i];
		}
	}

	frameTypes = new MxU8[FRAME_COUNT(smackTag)];

	if (!frameTypes) {
		result = FAILURE;
		goto done;
	}

	memcpy(frameTypes, p_data, FRAME_COUNT(smackTag));
	p_data += FRAME_COUNT(smackTag);

	treeSize = smackTag->tablesize + 0x1000;
	huffmanTrees = new MxU8[treeSize <= 0x2000 ? 0x2000 : treeSize];

	if (!huffmanTrees) {
		result = FAILURE;
		goto done;
	}

	memcpy(huffmanTrees + 0x1000, p_data, smackTag->tablesize);
	p_data += smackTag->tablesize;

	sizetables = SmackGetSizeTables();
	p_mxSmk->m_huffmanTables =
		new MxU8[smackTag->codesize + smackTag->detailsize + smackTag->typesize + smackTag->absize + sizetables];

	if (!p_mxSmk->m_huffmanTables) {
		result = FAILURE;
		goto done;
	}

	SmackDoTables(
		huffmanTrees,
		p_mxSmk->m_huffmanTables,
		smackTag->codesize,
		smackTag->absize,
		smackTag->detailsize,
		smackTag->typesize
	);

	size = SmackGetSizeDeltas(smackTag->Width, smackTag->Height) + 32;
	p_mxSmk->m_unk0x6b4 = new MxU8[size];
	memset(p_mxSmk->m_unk0x6b4, 0, size);

	width = p_mxSmk->m_smackTag.Width;
	data = (MxU32*) p_mxSmk->m_unk0x6b4;

	*data = 1;
	data++;
	*data = NULL; // MxU8* bitmapData
	data++;
	*data = smackTag->Width / 4;
	data++;
	*data = smackTag->Height / 4;
	data++;
	*data = width - 4;
	data++;
	*data = width * 3;
	data++;
	*data = width;
	data++;
	*data = width * 3 + (width - smackTag->Width);
	data++;
	data++;
	*data = smackTag->Width;
	data++;
	*data = smackTag->Height;

done:
	p_mxSmk->m_frameTypes = frameTypes;
	p_mxSmk->m_frameSizes = frameSizes;
	p_mxSmk->m_huffmanTrees = huffmanTrees;
	return result;

#undef FRAME_COUNT
}

// FUNCTION: LEGO1 0x100c5d40
// FUNCTION: BETA10 0x10152298
void MxSmk::Destroy(MxSmk* p_mxSmk)
{
	if (p_mxSmk->m_frameSizes) {
		delete[] p_mxSmk->m_frameSizes;
	}
	if (p_mxSmk->m_frameTypes) {
		delete[] p_mxSmk->m_frameTypes;
	}
	if (p_mxSmk->m_huffmanTrees) {
		delete[] p_mxSmk->m_huffmanTrees;
	}
	if (p_mxSmk->m_huffmanTables) {
		delete[] p_mxSmk->m_huffmanTables;
	}
	if (p_mxSmk->m_unk0x6b4) {
		delete[] p_mxSmk->m_unk0x6b4;
	}
}

// FUNCTION: LEGO1 0x100c5db0
// FUNCTION: BETA10 0x10152391
MxResult MxSmk::LoadFrame(
	MxBITMAPINFO* p_bitmapInfo,
	MxU8* p_bitmapData,
	MxSmk* p_mxSmk,
	MxU8* p_chunkData,
	MxBool p_paletteChanged,
	MxRect32List* p_list
)
{
	p_bitmapInfo->m_bmiHeader.biHeight = -MxBitmap::HeightAbs(p_bitmapInfo->m_bmiHeader.biHeight);
	*(MxU8**) (p_mxSmk->m_unk0x6b4 + 4) = p_bitmapData;

	// Reference: https://wiki.multimedia.cx/index.php/Smacker#Palette_Chunk
	if (p_paletteChanged) {
		MxU8 palette[772];

		MxU8* intoChunk = p_chunkData + 1;
		MxU8* intoPalette = palette;
		MxU16 paletteIndex = 0;
		// TODO: struct incorrect, Palette at wrong offset?
		MxU8* currentPalette = &p_mxSmk->m_smackTag.Palette[4];

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

	SmackDoFrameToBuffer(p_chunkData, p_mxSmk->m_huffmanTables, p_mxSmk->m_unk0x6b4);

	MxU16 und = 1;
	u32 smackRect[4];
	MxRect32 rect;

	while (GetRect(p_mxSmk->m_unk0x6b4, &und, smackRect, &rect)) {
		MxRect32* newRect = new MxRect32(rect);
		p_list->Append(newRect);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100c6050
// FUNCTION: BETA10 0x10152739
MxBool MxSmk::GetRect(MxU8* p_unk0x6b4, MxU16* p_und, u32* p_smackRect, MxRect32* p_rect)
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
