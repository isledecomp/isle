#ifndef FLIC_H
#define FLIC_H

#include <windows.h>

// A basic FLIC header structure from the "EGI" documentation. Source: https://www.compuphase.com/flic.htm#FLICHEADER
// This also goes over the FLIC structures: https://github.com/thinkbeforecoding/nomemalloc.handson/blob/master/flic.txt
typedef struct {
  DWORD size;          /* Size of FLIC including this header */
  WORD  type;          /* File type 0xAF11, 0xAF12, 0xAF30, 0xAF44, ... */
  WORD  frames;        /* Number of frames in first segment */
  WORD  width;         /* FLIC width in pixels */
  WORD  height;        /* FLIC height in pixels */
  WORD  depth;         /* Bits per pixel (usually 8) */
  WORD  flags;         /* Set to zero or to three */
  DWORD speed;         /* Delay between frames */
  WORD  reserved1;     /* Set to zero */
  DWORD created;       /* Date of FLIC creation (FLC only) */
  DWORD creator;       /* Serial number or compiler id (FLC only) */
  DWORD updated;       /* Date of FLIC update (FLC only) */
  DWORD updater;       /* Serial number (FLC only), see creator */
  WORD  aspect_dx;     /* Width of square rectangle (FLC only) */
  WORD  aspect_dy;     /* Height of square rectangle (FLC only) */
  WORD  ext_flags;     /* EGI: flags for specific EGI extensions */
  WORD  keyframes;     /* EGI: key-image frequency */
  WORD  totalframes;   /* EGI: total number of frames (segments) */
  DWORD req_memory;    /* EGI: maximum chunk size (uncompressed) */
  WORD  max_regions;   /* EGI: max. number of regions in a CHK_REGION chunk */
  WORD  transp_num;    /* EGI: number of transparent levels */
  BYTE  reserved2[24]; /* Set to zero */
  DWORD oframe1;       /* Offset to frame 1 (FLC only) */
  DWORD oframe2;       /* Offset to frame 2 (FLC only) */
  BYTE  reserved3[40]; /* Set to zero */
} FLIC_HEADER;

#endif // FLIC_H
