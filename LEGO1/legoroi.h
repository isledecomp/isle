#ifndef LEGOROI_H
#define LEGOROI_H

#include "mxtypes.h"

typedef MxBool (*ROIHandler)(char*, char*, MxU32);

class LegoROI {
public:
	__declspec(dllexport) void SetDisplayBB(MxS32 p_displayBB);
	__declspec(dllexport) static void configureLegoROI(MxS32 p_roi);

	static void SetSomeHandlerFunction(ROIHandler p_func);
	static MxBool CallTheHandlerFunction(
		char* p_param,
		MxFloat& p_red,
		MxFloat& p_green,
		MxFloat& p_blue,
		MxFloat& p_other
	);
	static MxBool ColorAliasLookup(char* p_param, MxFloat& p_red, MxFloat& p_green, MxFloat& p_blue, MxFloat& p_other);
};

#endif // LEGOROI_H
