#ifndef FLIC_H
#define FLIC_H

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
	DWORD size; /* Size of the chunk, including subchunks */ // 0x0;
	WORD type;                                               // 0x4;
} FLIC_CHUNK;

typedef struct : FLIC_CHUNK {
	WORD frames; /* Number of frames in first segment */                      // 0x6
	short width; /* FLIC width in pixels */                                   // 0x8
	short height; /* FLIC height in pixels */                                 // 0xa
	WORD depth; /* Bits per pixel (usually 8) */                              // 0xc
	WORD flags; /* Set to zero or to three */                                 // 0xe
	DWORD speed; /* Delay between frames */                                   // 0x10
	WORD reserved1; /* Set to zero */                                         // 0x14
	DWORD created; /* Date of FLIC creation (FLC only) */                     // 0x18
	DWORD creator; /* Serial number or compiler id (FLC only) */              // 0x1c
	DWORD updated; /* Date of FLIC update (FLC only) */                       // 0x20
	DWORD updater; /* Serial number (FLC only), see creator */                // 0x24
	WORD aspect_dx; /* Width of square rectangle (FLC only) */                // 0x28
	WORD aspect_dy; /* Height of square rectangle (FLC only) */               // 0x2a
	WORD ext_flags; /* EGI: flags for specific EGI extensions */              // 02c
	WORD keyframes; /* EGI: key-image frequency */                            // 0x2e
	WORD totalframes; /* EGI: total number of frames (segments) */            // 0x30
	DWORD req_memory; /* EGI: maximum chunk size (uncompressed) */            // 0x32
	WORD max_regions; /* EGI: max. number of regions in a CHK_REGION chunk */ // 0x36
	WORD transp_num; /* EGI: number of transparent levels */                  // 0x38
	BYTE reserved2[24]; /* Set to zero */                                     // 3e
	DWORD oframe1; /* Offset to frame 1 (FLC only) */                         // 0x56
	DWORD oframe2; /* Offset to frame 2 (FLC only) */                         // 0x5a
	BYTE reserved3[40]; /* Set to zero */                                     // 0x5e
} FLIC_HEADER;
#pragma pack(pop)

typedef struct : FLIC_CHUNK {
	short chunks; /* Number of subchunks */                // 0x6
	WORD delay; /* Delay in milliseconds */                // 0x8
	WORD reserved; /* Always zero */                       // 0xa
	WORD width; /* Frame width override (if non-zero) */   // 0xc
	WORD height; /* Frame height override (if non-zero) */ // 0xe
} FLIC_FRAME;

extern "C"
{
	void DecodeFLCFrame(
		LPBITMAPINFOHEADER p_bitmapHeader,
		byte* p_pixelData,
		FLIC_HEADER* p_flcHeader,
		FLIC_FRAME* p_flcFrame,
		unsigned char* p_decodedColorMap
	);
}

#endif // FLIC_H
