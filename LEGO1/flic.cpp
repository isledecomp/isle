#include "flic.h"

// Private forward declarations
void WritePixel(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_pixelData, short p_column, short p_row, byte p_pixel);
void WritePixels(
	LPBITMAPINFOHEADER p_bitmapHeader,
	byte* p_pixelData,
	short p_column,
	short p_row,
	byte* p_data,
	short p_count
);
int ClampLine(LPBITMAPINFOHEADER p_bitmapHeader, short& p_column, short& p_row, short& p_count);
void WritePixelRun(
	LPBITMAPINFOHEADER p_bitmapHeader,
	byte* p_pixelData,
	short p_column,
	short p_row,
	byte p_pixel,
	short p_count
);
void WritePixelPairs(
	LPBITMAPINFOHEADER p_bitmapHeader,
	byte* p_pixelData,
	short p_column,
	short p_row,
	WORD p_pixel,
	short p_count
);
short DecodeChunks(
	LPBITMAPINFOHEADER p_bitmapHeader,
	byte* p_pixelData,
	FLIC_HEADER* p_flcHeader,
	FLIC_FRAME* p_flcFrame,
	byte* p_flcSubchunks,
	unsigned char* p_decodedColorMap
);
void DecodeColors256(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_data);
void DecodeColorPackets(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_data);
void DecodeColorPacket(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_data, short p_index, WORD p_count);
void DecodeColors64(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_data);
void DecodeBrun(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_pixelData, byte* p_data, FLIC_HEADER* p_flcHeader);
void DecodeLC(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_pixelData, byte* p_data, FLIC_HEADER* p_flcHeader);
void DecodeSS2(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_pixelData, byte* p_data, FLIC_HEADER* p_flcHeader);
void DecodeBlack(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_pixelData, byte* p_data, FLIC_HEADER* p_flcHeader);
void DecodeCopy(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_pixelData, byte* p_data, FLIC_HEADER* p_flcHeader);

// FUNCTION: LEGO1 0x100bd530
void WritePixel(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_pixelData, short p_column, short p_row, byte p_pixel)
{
	if (p_column >= 0 && p_row >= 0 && p_column < p_bitmapHeader->biWidth && p_row < p_bitmapHeader->biHeight) {
		*(((p_bitmapHeader->biWidth + 3) & -4) * p_row + p_column + p_pixelData) = p_pixel;
	}
}

// FUNCTION: LEGO1 0x100bd580
void WritePixels(
	LPBITMAPINFOHEADER p_bitmapHeader,
	byte* p_pixelData,
	short p_column,
	short p_row,
	byte* p_data,
	short p_count
)
{
	short col = p_column;
	if (ClampLine(p_bitmapHeader, p_column, p_row, p_count)) {
		short offset = p_column - col;
		byte* pixels = offset ? p_data + offset : p_data;
		memcpy(((p_bitmapHeader->biWidth + 3) & -4) * p_row + p_column + p_pixelData, pixels, p_count);
	}
}

// FUNCTION: LEGO1 0x100bd600
int ClampLine(LPBITMAPINFOHEADER p_bitmapHeader, short& p_column, short& p_row, short& p_count)
{
	short lp_count;
	short end = p_column + p_count;
	if (p_row >= 0 && p_row < p_bitmapHeader->biHeight && end >= 0 && p_column < p_bitmapHeader->biWidth) {
		if (p_column < 0) {
			lp_count = end;
			p_count = end;
			p_column = 0;
		}
		if (end > p_bitmapHeader->biWidth) {
			lp_count -= end;
			lp_count += p_bitmapHeader->biWidth;
			p_count = lp_count;
		}
		return lp_count >= 0;
	}
	return 0;
}

// FUNCTION: LEGO1 0x100bd680
void WritePixelRun(
	LPBITMAPINFOHEADER p_bitmapHeader,
	byte* p_pixelData,
	short p_column,
	short p_row,
	byte p_pixel,
	short p_count
)
{
	short col = p_column;
	if (ClampLine(p_bitmapHeader, p_column, p_row, p_count)) {
		byte* dst = ((p_bitmapHeader->biWidth + 3) & -4) * p_row + p_column + p_pixelData;
		while (--p_count >= 0) {
			*(dst++) = p_pixel;
		}
	}
}

// FUNCTION: LEGO1 0x100bd6e0
void WritePixelPairs(
	LPBITMAPINFOHEADER p_bitmapHeader,
	byte* p_pixelData,
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
			*(dst++) = p_pixel;
		}
		if (odd)
			*((byte*) dst) = p_pixel;
	}
}

// FUNCTION: LEGO1 0x100bd760
short DecodeChunks(
	LPBITMAPINFOHEADER p_bitmapHeader,
	byte* p_pixelData,
	FLIC_HEADER* p_flcHeader,
	FLIC_FRAME* p_flcFrame,
	byte* p_flcSubchunks,
	unsigned char* p_decodedColorMap
)
{
	*p_decodedColorMap = 0;
	for (short subchunk = 0; subchunk < p_flcFrame->chunks; subchunk++) {
		FLIC_CHUNK* chunk = (FLIC_CHUNK*) p_flcSubchunks;
		p_flcSubchunks += chunk->size;
		switch (chunk->type) {
		case FLI_CHUNK_COLOR256:
			DecodeColors256(p_bitmapHeader, (byte*) (chunk + 1));
			*p_decodedColorMap = 1;
			break;
		case FLI_CHUNK_SS2:
			DecodeSS2(p_bitmapHeader, p_pixelData, (byte*) (chunk + 1), p_flcHeader);
			break;
		case FLI_CHUNK_COLOR64:
			DecodeColors64(p_bitmapHeader, (byte*) (chunk + 1));
			*p_decodedColorMap = 1;
			break;
		case FLI_CHUNK_LC:
			DecodeLC(p_bitmapHeader, p_pixelData, (byte*) (chunk + 1), p_flcHeader);
			break;
		case FLI_CHUNK_BLACK:
			DecodeBlack(p_bitmapHeader, p_pixelData, (byte*) (chunk + 1), p_flcHeader);
			break;
		case FLI_CHUNK_BRUN:
			DecodeBrun(p_bitmapHeader, p_pixelData, (byte*) (chunk + 1), p_flcHeader);
			break;
		case FLI_CHUNK_COPY:
			DecodeCopy(p_bitmapHeader, p_pixelData, (byte*) (chunk + 1), p_flcHeader);
			break;
		}
	}
	return 0;
}

// FUNCTION: LEGO1 0x100bd880
void DecodeColors256(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_data)
{
	DecodeColorPackets(p_bitmapHeader, p_data);
}

// FUNCTION: LEGO1 0x100bd8a0
void DecodeColorPackets(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_data)
{
	WORD colorIndex = 0;
	byte* colors = p_data + 2;
	for (short packet = *((short*) p_data) - 1; packet >= 0; packet--) {
		colorIndex += colors[0];
		short colorCount = colors[1];
		colors++;
		colors++;
		if (!colorCount)
			colorCount = 256;
		DecodeColorPacket(p_bitmapHeader, colors, colorIndex, colorCount);
		colorIndex += colorCount;
		colors += (colorCount * 3);
	}
}

// FUNCTION: LEGO1 0x100bd8f0
void DecodeColorPacket(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_data, short index, WORD p_count)
{
	byte* palette = (byte*) (p_bitmapHeader) + p_bitmapHeader->biSize + index * 4;
	while (p_count-- > 0) {
		palette[2] = p_data[0];
		palette[1] = p_data[1];
		palette[0] = p_data[2];
		palette += 4;
		p_data += 3;
	}
}

// FUNCTION: LEGO1 0x100bd940
void DecodeColors64(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_data)
{
	DecodeColorPackets(p_bitmapHeader, p_data);
}

// FUNCTION: LEGO1 0x100bd960
void DecodeBrun(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_pixelData, byte* p_data, FLIC_HEADER* p_flcHeader)
{
	byte* offset = ((p_bitmapHeader->biWidth + 3) & -4) * (p_flcHeader->height - 1) + p_pixelData;
	short line = p_flcHeader->height;
	while (--line >= 0) {
		p_data++;
		for (short p_pixel = 0; p_pixel < p_flcHeader->width;) {
			char p_count = *(p_data++);
			if (p_count >= 0) {
				for (short i = p_count; i > 0; i--) {
					*(offset++) = *p_data;
				}
				p_data++;
			}
			else {
				for (short i = -p_count; i > 0; i--) {
					*(offset++) = *(p_data++);
				}
			}
			p_pixel += p_count;
		}
		offset -= (((p_bitmapHeader->biWidth + 3) & -4) + p_flcHeader->width);
	}
}

// FUNCTION: LEGO1 0x100bda10
void DecodeLC(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_pixelData, byte* p_data, FLIC_HEADER* p_flcHeader)
{
	short row = p_flcHeader->height - *((short*) p_data) - 1;
	byte* pixels = p_data + 4;
	short numLines = *((short*) (p_data + 2));
	while (--numLines >= 0) {
		WORD column = 0;
		byte i = *(pixels++);
		while (i) {
			column += *(pixels++);
			char type = *(pixels++);
			short p_count;
			if (type < 0) {
				p_count = -type;
				WritePixelRun(p_bitmapHeader, p_pixelData, column, row, *(pixels++), p_count);
			}
			else {
				p_count = type;
				WritePixels(p_bitmapHeader, p_pixelData, column, row, pixels, p_count);
				pixels += p_count;
			}
			column += p_count;
			i--;
		}
		row--;
	}
}

// FUNCTION: LEGO1 0x100bdac0
void DecodeSS2(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_pixelData, byte* p_data, FLIC_HEADER* p_flcHeader)
{
	short width = p_flcHeader->width - 1;
	short row = p_flcHeader->height - 1;
	short lines = *p_data;
	byte* data = p_data + 2;
	do {
		short token;
		while (true) {
			token = *((WORD*) data);
			data += 2;
			if (token < 0) {
				if (token & 0x4000) {
					row += token;
					continue;
				}
			}
			break;
		}
		if (token < 0) {
			WritePixel(p_bitmapHeader, p_pixelData, width, row, token);
			token = *((WORD*) data);
			data += 2;
			if (!token) {
				row--;
				continue;
			}
		}
		short column = 0;
		do {
			column += *(data++);
			short type = ((short) *(data++));
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
				WritePixelPairs(p_bitmapHeader, p_pixelData, column, row, p_pixel, type);
				column += type;
			}
		} while (--token);

	} while (--lines > 0);
}

// FUNCTION: LEGO1 0x100bdc00
void DecodeBlack(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_pixelData, byte* p_data, FLIC_HEADER* p_flcHeader)
{
	short width = p_flcHeader->width;
	byte pixel[2];
	pixel[1] = 0;
	pixel[0] = 0;
	short line = p_flcHeader->height;
	while (--line >= 0) {
		short p_count = width / 2;
		short odd = width & 1;
		WritePixelPairs(p_bitmapHeader, p_pixelData, 0, line, *((WORD*) pixel), p_count);
		if (odd) {
			WritePixel(p_bitmapHeader, p_pixelData, width - 1, line, 0);
		}
	}
}

// FUNCTION: LEGO1 0x100bdc90
void DecodeCopy(LPBITMAPINFOHEADER p_bitmapHeader, byte* p_pixelData, byte* p_data, FLIC_HEADER* p_flcHeader)
{
	short line = p_flcHeader->height;
	int width = p_flcHeader->width;
	while (--line >= 0) {
		WritePixels(p_bitmapHeader, p_pixelData, 0, line, p_data, p_flcHeader->width);
		p_data += width;
	}
}

// FUNCTION: LEGO1 0x100bdce0
void DecodeFLCFrame(
	LPBITMAPINFOHEADER p_bitmapHeader,
	byte* p_pixelData,
	FLIC_HEADER* p_flcHeader,
	FLIC_FRAME* p_flcFrame,
	unsigned char* p_decodedColorMap
)
{
	if (p_flcFrame->type == FLI_CHUNK_FRAME) {
		DecodeChunks(p_bitmapHeader, p_pixelData, p_flcHeader, p_flcFrame, (byte*) (p_flcFrame + 1), p_decodedColorMap);
	}
}
