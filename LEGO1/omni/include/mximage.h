#ifndef MXIMAGE_H
#define MXIMAGE_H
#include "legostream.h"
#include "mxcolor.h"

class MxImage {
public:
	MxImage();
	MxImage(MxU32 p_width, MxU32 p_height);
	~MxImage();
	MxResult Read(LegoStream* p_stream, MxU32 p_square);
	MxResult Write(LegoStream* p_stream);

private:
	MxU32 m_width;
	MxU32 m_height;
	MxU32 m_colors;
	MxColor m_palette[256];
	MxU8* m_image;
};

#endif // MXIMAGE_H
