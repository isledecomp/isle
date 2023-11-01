#ifndef LEGOROI_H
#define LEGOROI_H

#include "mxtypes.h"

typedef MxBool (*ROI_Handler)(char*, char*, MxU32);

class LegoROI {
public:
	__declspec(dllexport) void SetDisplayBB(MxS32 p_displayBB);
	__declspec(dllexport) static void configureLegoROI(MxS32 p_roi);

	static void SetSomeHandlerFunction(ROI_Handler p_func);
	static MxBool CallTheHandlerFunction(char* p_param, float& p_red, float& p_green, float& p_blue, float& p_other);
	static MxBool ColorAliasLookup(char* p_param, float& p_red, float& p_green, float& p_blue, float& p_other);
};

#endif // LEGOROI_H
