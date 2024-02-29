#ifndef FLIC_H
#define FLIC_H

#include "decomp.h"

#include <windows.h>

enum FLI_CHUNK_TYPE {
	FLI_CHUNK_COLOR256 = 4,  // 256-level color palette info
	FLI_CHUNK_SS2 = 7,       // Word-oriented delta compression
	FLI_CHUNK_COLOR64 = 11,  // 64-level color palette info
	FLI_CHUNK_LC = 12,       // Byte-oriented delta compression
	FLI_CHUNK_BLACK = 13,    // Entire frame is color index 0
	FLI_CHUNK_BRUN = 15,     // Byte run length compression
	FLI_CHUNK_COPY = 16,     // No compression
	FLI_CHUNK_PSTAMP = 18,   // Postage stamp sized image
	FLI_CHUNK_FRAME = 0xf1fa // Frame
};

#pragma pack(push, 1)
// A basic FLIC header structure from the "EGI" documentation. Source: https://www.compuphase.com/flic.htm#FLICHEADER
// This also goes over the FLIC structures: https://github.com/thinkbeforecoding/nomemalloc.handson/blob/master/flic.txt
typedef struct {
	DWORD size; /* Size of the chunk, including subchunks */ // 0x00
	WORD type;                                               // 0x04
} FLIC_CHUNK;

typedef struct : FLIC_CHUNK {
	WORD frames; /* Number of frames in first segment */ // 0x06
	WORD width; /* FLIC width in pixels */               // 0x08
	WORD height; /* FLIC height in pixels */             // 0x0a
	WORD depth; /* Bits per pixel (usually 8) */         // 0x0c
	WORD flags; /* Set to zero or to three */            // 0x0e
	DWORD speed; /* Delay between frames */              // 0x10
} FLIC_HEADER;
#pragma pack(pop)

typedef struct : FLIC_CHUNK {
	WORD chunks; /* Number of subchunks */                 // 0x06
	WORD delay; /* Delay in milliseconds */                // 0x08
	WORD reserved; /* Always zero */                       // 0x0a
	WORD width; /* Frame width override (if non-zero) */   // 0x0c
	WORD height; /* Frame height override (if non-zero) */ // 0x0e
} FLIC_FRAME;

void DecodeFLCFrame(
	LPBITMAPINFOHEADER p_bitmapHeader,
	BYTE* p_pixelData,
	FLIC_HEADER* p_flcHeader,
	FLIC_FRAME* p_flcFrame,
	BYTE* p_decodedColorMap
);

#endif // FLIC_H
