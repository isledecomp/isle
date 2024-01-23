#ifndef MXIMAGEPTR_H
#define MXIMAGEPTR_H

#include "mximage.h"

class MxImagePtr {
	MxImagePtr();
	~MxImagePtr();
	MxResult Read(LegoStream* p_stream, MxU32 p_square);
	MxResult Write(LegoStream* p_stream);

private:
	MxImage* m_pImage;
};

#endif // MXIMAGEPTR_H
