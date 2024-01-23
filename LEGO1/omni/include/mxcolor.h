#ifndef MXCOLOR_H
#define MXCOLOR_H
#include "legostream.h"

class MxColor {
public:
	MxColor();
	MxResult Read(LegoStream* p_stream);
	MxResult Write(LegoStream* p_stream);

private:
	MxU8 m_color[3];
};

#endif // MXCOLOR_H
