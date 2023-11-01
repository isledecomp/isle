#include "legoroi.h"

#include <string.h>

// SIZE 0x14
typedef struct {
	const char* m_name;
	MxS32 m_red;
	MxS32 m_green;
	MxS32 m_blue;
	MxS32 m_unk10;
} ROIColorAlias;

// 0x100dbe28
const double g_normalizeByteToFloat = 1.0 / 255;

// 0x101011b0
ROIColorAlias g_roiColorAliases[22] = {
	{"lego black", 0x21, 0x21, 0x21, 0},       {"lego black f", 0x21, 0x21, 0x21, 0},
	{"lego black flat", 0x21, 0x21, 0x21, 0},  {"lego blue", 0x00, 0x54, 0x8c, 0},
	{"lego blue flat", 0x00, 0x54, 0x8c, 0},   {"lego brown", 0x4a, 0x23, 0x1a, 0},
	{"lego brown flt", 0x4a, 0x23, 0x1a, 0},   {"lego brown flat", 0x4a, 0x23, 0x1a, 0},
	{"lego drk grey", 0x40, 0x40, 0x40, 0},    {"lego drk grey flt", 0x40, 0x40, 0x40, 0},
	{"lego dk grey flt", 0x40, 0x40, 0x40, 0}, {"lego green", 0x00, 0x78, 0x2d, 0},
	{"lego green flat", 0x00, 0x78, 0x2d, 0},  {"lego lt grey", 0x82, 0x82, 0x82, 0},
	{"lego lt grey flt", 0x82, 0x82, 0x82, 0}, {"lego lt grey fla", 0x82, 0x82, 0x82, 0},
	{"lego red", 0xcb, 0x12, 0x20, 0},         {"lego red flat", 0xcb, 0x12, 0x20, 0},
	{"lego white", 0xfa, 0xfa, 0xfa, 0},       {"lego white flat", 0xfa, 0xfa, 0xfa, 0},
	{"lego yellow", 0xff, 0xb9, 0x00, 0},      {"lego yellow flat", 0xff, 0xb9, 0x00, 0},
};

// 0x10101368
MxS32 g_roiConfig = 100;

// 0x101013ac
ROIHandler g_someHandlerFunction = NULL;

// OFFSET: LEGO1 0x100a81c0
void LegoROI::configureLegoROI(MxS32 p_roi)
{
	g_roiConfig = p_roi;
}

// OFFSET: LEGO1 0x100a9bf0
MxBool LegoROI::CallTheHandlerFunction(
	char* p_param,
	MxFloat& p_red,
	MxFloat& p_green,
	MxFloat& p_blue,
	MxFloat& p_other
)
{
	// TODO
	if (p_param == NULL)
		return FALSE;

	if (g_someHandlerFunction) {
		char buf[32];
		if (g_someHandlerFunction(p_param, buf, 32))
			p_param = buf;
	}

	return ColorAliasLookup(p_param, p_red, p_green, p_blue, p_other);
}

// OFFSET: LEGO1 0x100a9c50
MxBool LegoROI::ColorAliasLookup(char* p_param, MxFloat& p_red, MxFloat& p_green, MxFloat& p_blue, MxFloat& p_other)
{
	// TODO: this seems awfully hacky for these devs. is there a dynamic way
	// to represent `the end of this array` that would improve this?
	MxU32 i = 0;
	do {
		if (strcmpi(g_roiColorAliases[i].m_name, p_param) == 0) {
			p_red = g_roiColorAliases[i].m_red * g_normalizeByteToFloat;
			p_green = g_roiColorAliases[i].m_green * g_normalizeByteToFloat;
			p_blue = g_roiColorAliases[i].m_blue * g_normalizeByteToFloat;
			p_other = g_roiColorAliases[i].m_unk10 * g_normalizeByteToFloat;
			return TRUE;
		}
		i++;
	} while ((MxS32*) &g_roiColorAliases[i] < &g_roiConfig);

	return FALSE;
}

// OFFSET: LEGO1 0x100a9d30
void LegoROI::SetSomeHandlerFunction(ROIHandler p_func)
{
	g_someHandlerFunction = p_func;
}

// OFFSET: LEGO1 0x100a9e10
void LegoROI::SetDisplayBB(MxS32 p_displayBB)
{
	// Intentionally empty function
}
