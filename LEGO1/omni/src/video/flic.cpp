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
void DecodeColorPacket(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_data, short p_index, WORD p_count);
void DecodeColors64(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_data);
void DecodeBrun(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader);
void DecodeLC(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader);
void DecodeSS2(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader);
void DecodeBlack(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader);
void DecodeCopy(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader);

// FUNCTION: LEGO1 0x100bd530
void WritePixel(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, short p_column, short p_row, byte p_pixel)
{
	if (p_column >= 0 && p_row >= 0 && p_column < p_bitmapHeader->biWidth && p_row < p_bitmapHeader->biHeight) {
		*(((p_bitmapHeader->biWidth + 3) & -4) * p_row + p_column + p_pixelData) = p_pixel;
	}
}

// FUNCTION: LEGO1 0x100bd580
void WritePixels(
	LPBITMAPINFOHEADER p_bitmapHeader,
	BYTE* p_pixelData,
	short p_column,
	short p_row,
	BYTE* p_data,
	short p_count
)
{
	short col = p_column;

	if (ClampLine(p_bitmapHeader, p_column, p_row, p_count)) {
		short offset = p_column - col;
		BYTE* pixels = offset ? p_data + offset : p_data;
		memcpy(((p_bitmapHeader->biWidth + 3) & -4) * p_row + p_column + p_pixelData, pixels, p_count);
	}
}

// FUNCTION: LEGO1 0x100bd600
int ClampLine(LPBITMAPINFOHEADER p_bitmapHeader, short& p_column, short& p_row, short& p_count)
{
	short column = p_column;
	short row = p_row;
	short count = p_count;
	short end = column + count;
	int result;

	if (row < 0 || p_bitmapHeader->biHeight <= row || end < 0 || p_bitmapHeader->biWidth <= column) {
		result = 0;
	}
	else {
		if (column < 0) {
			count += column;
			p_count = end;
			p_column = 0;
		}

		if (p_bitmapHeader->biWidth < end) {
			count -= end - p_bitmapHeader->biWidth;
			p_count = count;
		}

		if (count < 0) {
			result = 0;
		}
		else {
			result = 1;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100bd680
void WritePixelRun(
	LPBITMAPINFOHEADER p_bitmapHeader,
	BYTE* p_pixelData,
	short p_column,
	short p_row,
	byte p_pixel,
	short p_count
)
{
	short col = p_column;

	if (ClampLine(p_bitmapHeader, p_column, p_row, p_count)) {
		BYTE* dst = ((p_bitmapHeader->biWidth + 3) & -4) * p_row + p_column + p_pixelData;

		while (--p_count >= 0) {
			*dst++ = p_pixel;
		}
	}
}

// FUNCTION: LEGO1 0x100bd6e0
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

	if (ClampLine(p_bitmapHeader, p_column, p_row, p_count)) {
		short odd = p_count & 1;
		p_count >>= 1;

		WORD* dst = (WORD*) (((p_bitmapHeader->biWidth + 3) & -4) * p_row + p_column + p_pixelData);
		while (--p_count >= 0) {
			*dst++ = p_pixel;
		}

		if (odd) {
			*(BYTE*) dst = p_pixel;
		}
	}
}

// FUNCTION: LEGO1 0x100bd760
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
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x100bd880
void DecodeColors256(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_data)
{
	DecodeColorPackets(p_bitmapHeader, p_data);
}

// FUNCTION: LEGO1 0x100bd8a0
void DecodeColorPackets(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_data)
{
	WORD colorIndex = 0;
	BYTE* colors = p_data + 2;

	for (short packet = *((short*) p_data) - 1; packet >= 0; packet--) {
		colorIndex += colors[0];
		short colorCount = colors[1];

		colors++;
		colors++;

		if (!colorCount) {
			colorCount = 256;
		}

		DecodeColorPacket(p_bitmapHeader, colors, colorIndex, colorCount);
		colorIndex += colorCount;
		colors += colorCount * 3;
	}
}

// FUNCTION: LEGO1 0x100bd8f0
void DecodeColorPacket(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_data, short index, WORD p_count)
{
	BYTE* palette = (BYTE*) p_bitmapHeader + p_bitmapHeader->biSize + index * 4;

	while (p_count-- > 0) {
		palette[2] = p_data[0];
		palette[1] = p_data[1];
		palette[0] = p_data[2];

		palette += 4;
		p_data += 3;
	}
}

// FUNCTION: LEGO1 0x100bd940
void DecodeColors64(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_data)
{
	DecodeColorPackets(p_bitmapHeader, p_data);
}

// FUNCTION: LEGO1 0x100bd960
void DecodeBrun(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader)
{
	BYTE* data = p_data;
	short width = p_flcHeader->width;
	short height = p_flcHeader->height;
	BYTE* offset = ((p_bitmapHeader->biWidth + 3) & -4) * (height - 1) + p_pixelData;

	for (short line = height - 1; line >= 0; line--) {
		data++;

		for (short pixel = 0; pixel < width;) {
			char count = *data++;

			if (count >= 0) {
				for (short i = 0; i < count; i++) {
					*offset++ = *data;
				}

				data++;
			}
			else {
				count = -count;
				for (short i = 0; i < count; i++) {
					*offset++ = *data++;
				}
			}

			pixel += count;
		}

		offset -= (((p_bitmapHeader->biWidth + 3) & -4) + width);
	}
}

// FUNCTION: LEGO1 0x100bda10
void DecodeLC(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader)
{
	short row = (short) p_flcHeader->height - *((short*) p_data) - 1;
	BYTE* data = p_data + 4;

	for (short lines = *((short*) (p_data + 2)) - 1; lines >= 0; lines--) {
		WORD column = 0;
		BYTE packets = *data++;

		for (BYTE i = 0; i < packets; i++) {
			column += *data++;
			char type = *((char*) data++);

			if (type < 0) {
				type = -type;
				WritePixelRun(p_bitmapHeader, p_pixelData, column, row, *data++, type);
				column += type;
			}
			else {
				WritePixels(p_bitmapHeader, p_pixelData, column, row, data, type);
				data += type;
				column += type;
			}
		}

		row--;
	}
}

// FUNCTION: LEGO1 0x100bdac0
void DecodeSS2(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader)
{
	short width = (short) p_flcHeader->width - 1;
	short row = (short) p_flcHeader->height - 1;
	short lines = *((short*) p_data);
	BYTE* data = p_data + 2;

	while (--lines > 0) {
		short token;

		while (TRUE) {
			token = *((short*) data);
			data += 2;

			if (token < 0) {
				if (token & 0x4000) {
					row += token;
				}
				else {
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
			}
			else {
				break;
			}
		}

		short column = 0;
		do {
			column += *(data++);
			short type = *((char*) data++);
			type += type;

			if (type >= 0) {
				WritePixels(p_bitmapHeader, p_pixelData, column, row, data, type);
				column += type;
				data += type;
			}
			else {
				type = -type;
				short p_pixel = *((WORD*) data);
				data += 2;
				WritePixelPairs(p_bitmapHeader, p_pixelData, column, row, p_pixel, type >> 1);
				column += type;
			}
		} while (--token);

		row--;
	}
}

// FUNCTION: LEGO1 0x100bdc00
void DecodeBlack(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader)
{
	short line = p_flcHeader->height;
	short width = p_flcHeader->width;

	BYTE pixel[2];
	pixel[1] = 0;
	pixel[0] = 0;

	while (--line >= 0) {
		short count = width / 2;
		short odd = width & 1;

		WritePixelPairs(p_bitmapHeader, p_pixelData, 0, line, *((WORD*) pixel), count);

		if (odd) {
			WritePixel(p_bitmapHeader, p_pixelData, width - 1, line, 0);
		}
	}
}

// FUNCTION: LEGO1 0x100bdc90
void DecodeCopy(LPBITMAPINFOHEADER p_bitmapHeader, BYTE* p_pixelData, BYTE* p_data, FLIC_HEADER* p_flcHeader)
{
	short line = p_flcHeader->height;
	short width = p_flcHeader->width;

	while (--line >= 0) {
		WritePixels(p_bitmapHeader, p_pixelData, 0, line, p_data, width);
		p_data += width;
	}
}

// FUNCTION: LEGO1 0x100bdce0
void DecodeFLCFrame(
	LPBITMAPINFOHEADER p_bitmapHeader,
	BYTE* p_pixelData,
	FLIC_HEADER* p_flcHeader,
	FLIC_FRAME* p_flcFrame,
	BYTE* p_decodedColorMap
)
{
	if (p_flcFrame->type == FLI_CHUNK_FRAME) {
		DecodeChunks(p_bitmapHeader, p_pixelData, p_flcHeader, p_flcFrame, (BYTE*) (p_flcFrame + 1), p_decodedColorMap);
	}
}
