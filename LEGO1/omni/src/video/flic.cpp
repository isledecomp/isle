#include "flic.h"

DECOMP_SIZE_ASSERT(FLIC_CHUNK, 0x06)
DECOMP_SIZE_ASSERT(FLIC_HEADER, 0x14)
DECOMP_SIZE_ASSERT(FLIC_FRAME, 0x10)

void WritePixel(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, short p_column, short p_row, byte p_pixel);
void WritePixels(
	LPBITMAPINFOHEADER p_bitmapHeader,
	BYTE* p_pixelData,
	short p_column,
	short p_row,
	BYTE* p_data,
	short p_count
);
int ClampLine(LPBITMAPINFOHEADER p_bitmapHeader, short& p_column, short& p_row, short& p_count);
void WritePixelRun(
	LPBITMAPINFOHEADER p_bitmapHeader,
	BYTE* p_pixelData,
	short p_column,
	short p_row,
	byte p_pixel,
	short p_count
);
void WritePixelPairs(
	LPBITMAPINFOHEADER p_bitmapHeader,
	BYTE* p_pixelData,
	short p_column,
	short p_row,
	WORD p_pixel,
	short p_count
);
short DecodeChunks(
	LPBITMAPINFOHEADER p_bitmapHeader,
	BYTE* p_pixelData,
	FLIC_HEADER* p_flcHeader,
	FLIC_FRAME* p_flcFrame,
	BYTE* p_flcSubchunks,
	BYTE* p_decodedColorMap
);
void DecodeColors256(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_data);
void DecodeColorPackets(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_data);
void DecodeColorPacket(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_data, short p_index, short p_count);
void DecodeColors64(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_data);
void DecodeBrun(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader);
void DecodeLC(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader);
void DecodeSS2(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader);
void DecodeBlack(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader);
void DecodeCopy(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader);

// FUNCTION: LEGO1 0x100bd530
// FUNCTION: BETA10 0x1013dd80
void WritePixel(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, short p_column, short p_row, byte p_pixel)
{
	if (p_column < 0 || p_row < 0 || p_column >= p_bitmapHeader->biWidth || p_row >= p_bitmapHeader->biHeight) {
		return;
	}

	*(((p_bitmapHeader->biWidth + 3) & -4) * p_row + p_column + p_pixelData) = p_pixel;
}

// FUNCTION: LEGO1 0x100bd580
// FUNCTION: BETA10 0x1013ddef
void WritePixels(
	LPBITMAPINFOHEADER p_bitmapHeader,
	BYTE* p_pixelData,
	short p_column,
	short p_row,
	BYTE* p_data,
	short p_count
)
{
	// ClampLine could modify p_column. Save the original value.
	short zcol = p_column;

	if (!ClampLine(p_bitmapHeader, p_column, p_row, p_count)) {
		return;
	}

	short offset = p_column - zcol;
	if (offset) {
		p_data += offset;
	}

	BYTE* dest = ((p_bitmapHeader->biWidth + 3) & -4) * p_row + p_column + p_pixelData;
	memcpy(dest, p_data, p_count);
}

// FUNCTION: LEGO1 0x100bd600
// FUNCTION: BETA10 0x1013de84
int ClampLine(LPBITMAPINFOHEADER p_bitmapHeader, short& p_column, short& p_row, short& p_count)
{
	short column = p_column;
	short a_row = p_row;
	short f_count = p_count;
	short end = column + f_count;

	if (a_row < 0 || p_bitmapHeader->biHeight <= a_row || end < 0 || p_bitmapHeader->biWidth <= column) {
		return 0;
	}

	if (column < 0) {
		f_count += column;
		p_count = f_count;
		p_column = 0;
	}

	if (p_bitmapHeader->biWidth < end) {
		f_count -= end - (short) p_bitmapHeader->biWidth;
		p_count = f_count;
	}

	if (f_count < 0) {
		return 0;
	}

	return 1;
}

// FUNCTION: LEGO1 0x100bd680
// FUNCTION: BETA10 0x1013df77
void WritePixelRun(
	LPBITMAPINFOHEADER p_bitmapHeader,
	BYTE* p_pixelData,
	short p_column,
	short p_row,
	byte p_pixel,
	short p_count
)
{
	if (!ClampLine(p_bitmapHeader, p_column, p_row, p_count)) {
		return;
	}

	BYTE* dst = ((p_bitmapHeader->biWidth + 3) & -4) * p_row + p_column + p_pixelData;

	while (--p_count >= 0) {
		*dst++ = p_pixel;
	}
}

// FUNCTION: LEGO1 0x100bd6e0
// FUNCTION: BETA10 0x1013dfee
void WritePixelPairs(
	LPBITMAPINFOHEADER p_bitmapHeader,
	BYTE* p_pixelData,
	short p_column,
	short p_row,
	WORD p_pixel,
	short p_count
)
{
	p_count <<= 1;

	if (!ClampLine(p_bitmapHeader, p_column, p_row, p_count)) {
		return;
	}

	short is_odd = p_count & 1;
	p_count >>= 1;

	WORD* dst = (WORD*) (((p_bitmapHeader->biWidth + 3) & -4) * p_row + p_column + p_pixelData);
	while (--p_count >= 0) {
		*dst++ = p_pixel;
	}

	if (is_odd) {
		BYTE* dst_byte = (BYTE*) dst;
		*dst_byte = p_pixel;
	}
}

// FUNCTION: LEGO1 0x100bd760
// FUNCTION: BETA10 0x1013e097
short DecodeChunks(
	LPBITMAPINFOHEADER p_bitmapHeader,
	BYTE* p_pixelData,
	FLIC_HEADER* p_flcHeader,
	FLIC_FRAME* p_flcFrame,
	BYTE* p_flcSubchunks,
	BYTE* p_decodedColorMap
)
{
	*p_decodedColorMap = FALSE;

	for (short subchunk = 0; subchunk < (short) p_flcFrame->chunks; subchunk++) {
		FLIC_CHUNK* chunk = (FLIC_CHUNK*) p_flcSubchunks;
		p_flcSubchunks += chunk->size;

		switch (chunk->type) {
		case FLI_CHUNK_COLOR256:
			DecodeColors256(p_bitmapHeader, (BYTE*) (chunk + 1));
			*p_decodedColorMap = TRUE;
			break;
		case FLI_CHUNK_SS2:
			DecodeSS2(p_bitmapHeader, p_pixelData, (BYTE*) (chunk + 1), p_flcHeader);
			break;
		case FLI_CHUNK_COLOR64:
			DecodeColors64(p_bitmapHeader, (BYTE*) (chunk + 1));
			*p_decodedColorMap = TRUE;
			break;
		case FLI_CHUNK_LC:
			DecodeLC(p_bitmapHeader, p_pixelData, (BYTE*) (chunk + 1), p_flcHeader);
			break;
		case FLI_CHUNK_BLACK:
			DecodeBlack(p_bitmapHeader, p_pixelData, (BYTE*) (chunk + 1), p_flcHeader);
			break;
		case FLI_CHUNK_BRUN:
			DecodeBrun(p_bitmapHeader, p_pixelData, (BYTE*) (chunk + 1), p_flcHeader);
			break;
		case FLI_CHUNK_COPY:
			DecodeCopy(p_bitmapHeader, p_pixelData, (BYTE*) (chunk + 1), p_flcHeader);
			break;
		default:
			break;
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x100bd880
// FUNCTION: BETA10 0x1013e22c
void DecodeColors256(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_data)
{
	DecodeColorPackets(p_bitmapHeader, p_data);
}

// FUNCTION: LEGO1 0x100bd8a0
// FUNCTION: BETA10 0x1013e24c
void DecodeColorPackets(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_data)
{
	short colorIndex = 0;
	BYTE* colors = p_data;
	short* pPackets = (short*) colors;
	short packets = *pPackets;
	colors += 2;

	while (--packets >= 0) {
		colorIndex += *colors++;
		short colorCount = *colors++;

		if (colorCount == 0) {
			colorCount = 256;
		}

		DecodeColorPacket(p_bitmapHeader, colors, colorIndex, colorCount);
		colors += colorCount * 3;
		colorIndex += colorCount;
	}
}

// FUNCTION: LEGO1 0x100bd8f0
// FUNCTION: BETA10 0x1013e2f8
void DecodeColorPacket(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_data, short index, short p_count)
{
	RGBQUAD* palette = (RGBQUAD*) ((BYTE*) p_bitmapHeader + p_bitmapHeader->biSize) + index;

	while (p_count--) {
		palette->rgbRed = p_data[0];
		palette->rgbGreen = p_data[1];
		palette->rgbBlue = p_data[2];

		palette++;
		p_data += 3;
	}
}

// FUNCTION: LEGO1 0x100bd940
// FUNCTION: BETA10 0x1013e364
void DecodeColors64(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_data)
{
	DecodeColorPackets(p_bitmapHeader, p_data);
}

// FUNCTION: LEGO1 0x100bd960
// FUNCTION: BETA10 0x1013e384
void DecodeBrun(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader)
{
	short width = p_flcHeader->width;
	short height = p_flcHeader->height;
	BYTE* data = p_data;
	BYTE* offset = ((p_bitmapHeader->biWidth + 3) & -4) * (height - 1) + p_pixelData;

	short line = height;
	short width2 = width;

	while (--line >= 0) {
		short column = 0;
		data++;
		char count = 0;
		while ((column += count) < width2) {
			count = *data++;

			short i;
			if (count >= 0) {
				for (i = 0; i < count; i++) {
					*offset++ = *data;
				}

				data++;
			}
			else {
				count = -count;
				for (i = 0; i < count; i++) {
					*offset++ = *data++;
				}
			}
		}

		offset -= (((p_bitmapHeader->biWidth + 3) & -4) + width);
	}
}

// FUNCTION: LEGO1 0x100bda10
// FUNCTION: BETA10 0x1013e4ca
void DecodeLC(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader)
{
	short xofs = 0;
	short yofs = 0;
	short* word_data = (short*) p_data;
	BYTE* data = (BYTE*) word_data + 4;
	short row = p_flcHeader->height - (*word_data + yofs) - 1;

	word_data++;
	short lines = *word_data;

	while (--lines >= 0) {
		short column = xofs;
		BYTE packets = *data++;

		while (packets > 0) {
			column += *data++; // skip byte
			char type = *((char*) data++);

			if (type < 0) {
				type = -type;
				WritePixelRun(p_bitmapHeader, p_pixelData, column, row, *data++, type);
				column += type;
				packets = packets - 1;
			}
			else {
				WritePixels(p_bitmapHeader, p_pixelData, column, row, data, type);
				data += type;
				column += type;
				packets = packets - 1;
			}
		}

		row--;
	}
}

// FUNCTION: LEGO1 0x100bdac0
// FUNCTION: BETA10 0x1013e61d
void DecodeSS2(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader)
{
	short xofs = 0;
	short yofs = 0;

	short width = p_flcHeader->width;
	short token = 0;




	// LINE: BETA10 0x1013e643
	short xmax = xofs + width - 1;

	// LINE: BETA10 0x1013e652
	short* data = (short*) p_data;

	// The first word in the data following the chunk header contains the number of lines in the chunk.
	// The line count does not include skipped lines.
	short lines = *data++;


	// LINE: BETA10 0x1013e666
	short row = p_flcHeader->height - yofs - 1;


	do {
		// LINE: BETA10 0x1013e692
		token = *((short*) data);
		data += 2; // TODO: likely an otherData assignment

		if (token < 0) {
			if (token & 0x4000) {
				// TODO: Make the compiler move this code all the way to the top of the loop
				// // LINE: BETA10 0x1013e684
				row += token;
				// TODO: otherData assigment
				continue;
			}

			WritePixel(p_bitmapHeader, p_pixelData, width, row, token);
			token = *((WORD*) data);
			data += 2;

			if (!token) {
				row--;
				if (--lines <= 0) {
					return;
				}
			}
			else {
				break;
			}
		}
		else {
			break;
		}

		short column = 0;
		do {
			column += *(data++);
			short type = *((char*) data++);
			type += type;

			if (type >= 0) {
				WritePixels(p_bitmapHeader, p_pixelData, column, row, (BYTE*) data, type);
				column += type;
				data += type;
			}
			else {
				type = -type;
				short p_pixel = *((WORD*) data); // removed for stack size
				data += 2;
				WritePixelPairs(p_bitmapHeader, p_pixelData, column, row, p_pixel, type >> 1);
				column += type;
			}
		} while (--token);

		row--;
	} while (--lines > 0);
}

// FUNCTION: LEGO1 0x100bdc00
// FUNCTION: BETA10 0x1013e85a
void DecodeBlack(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader)
{
	short height = p_flcHeader->height;
	short width = p_flcHeader->width;
	short t_col = 0;
	short t_row = 0;

	BYTE pixel[2];
	pixel[0] = pixel[1] = 0;

	for (short i = height - 1; i >= 0; i--) {
		WritePixelPairs(p_bitmapHeader, p_pixelData, t_col, t_row + i, *(WORD*) pixel, width / 2);

		if (width & 1) {
			WritePixel(p_bitmapHeader, p_pixelData, t_col + width - 1, t_row + i, 0);
		}
	}
}

// FUNCTION: LEGO1 0x100bdc90
// FUNCTION: BETA10 0x1013e91f
void DecodeCopy(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader)
{
	short height = p_flcHeader->height;
	short width = p_flcHeader->width;
	short t_col = 0;
	short t_row = 0;

	for (short i = height - 1; i >= 0; i--) {
		WritePixels(p_bitmapHeader, p_pixelData, t_col, t_row + i, p_data, width);
		p_data += width;
	}
}

// FUNCTION: LEGO1 0x100bdce0
// FUNCTION: BETA10 0x1013e9a5
void DecodeFLCFrame(
	LPBITMAPINFOHEADER p_bitmapHeader,
	BYTE* p_pixelData,
	FLIC_HEADER* p_flcHeader,
	FLIC_FRAME* p_flcFrame,
	BYTE* p_decodedColorMap
)
{
	FLIC_FRAME* frame = p_flcFrame;
	if (frame->type != FLI_CHUNK_FRAME) {
		return;
	}

	if (DecodeChunks(p_bitmapHeader, p_pixelData, p_flcHeader, frame, (BYTE*) (p_flcFrame + 1), p_decodedColorMap)) {
		return;
	}
}
