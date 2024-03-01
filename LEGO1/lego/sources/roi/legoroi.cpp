#include "legoroi.h"

#include <string.h>

DECOMP_SIZE_ASSERT(LegoROI, 0x108)
DECOMP_SIZE_ASSERT(TimeROI, 0x10c)

// SIZE 0x14
typedef struct {
	const char* m_name;
	int m_red;
	int m_green;
	int m_blue;
	int m_unk0x10;
} ROIColorAlias;

// GLOBAL: LEGO1 0x100dbe28
const double g_normalizeByteToFloat = 1.0 / 255;

// GLOBAL: LEGO1 0x101011b0
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

// GLOBAL: LEGO1 0x10101368
int g_roiConfig = 100;

// GLOBAL: LEGO1 0x101013ac
ROIHandler g_someHandlerFunction = NULL;

// FUNCTION: LEGO1 0x100a81c0
void LegoROI::configureLegoROI(int p_roiConfig)
{
	g_roiConfig = p_roiConfig;
}

// FUNCTION: LEGO1 0x100a81d0
LegoROI::LegoROI(Tgl::Renderer* p_renderer) : ViewROI(p_renderer, NULL)
{
	m_unk0xd4 = NULL;
	m_name = NULL;
	m_unk0x104 = NULL;
}

// FUNCTION: LEGO1 0x100a82d0
LegoROI::LegoROI(Tgl::Renderer* p_renderer, ViewLODList* p_lodList) : ViewROI(p_renderer, p_lodList)
{
	m_unk0xd4 = NULL;
	m_name = NULL;
	m_unk0x104 = NULL;
}

// FUNCTION: LEGO1 0x100a83c0
LegoROI::~LegoROI()
{
	if (comp) {
		CompoundObject::iterator iterator;

		for (iterator = comp->begin(); !(iterator == comp->end()); ++iterator) {
			ROI* child = *iterator;

			delete child;
		}

		delete comp;
		comp = 0;
	}
	if (m_name) {
		delete[] m_name;
	}
}

// STUB: LEGO1 0x100a84a0
LegoResult LegoROI::Read(
	OrientableROI* p_unk0xd4,
	Tgl::Renderer* p_renderer,
	ViewLODListManager* p_viewLODListManager,
	LegoTextureContainer* p_textureContainer,
	LegoStorage* p_storage
)
{
	return SUCCESS;
}

// STUB: LEGO1 0x100a90f0
LegoResult LegoROI::SetFrame(LegoAnim* p_anim, LegoTime p_time)
{
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100a9a50
TimeROI::TimeROI(Tgl::Renderer* p_renderer, ViewLODList* p_lodList, int p_time) : LegoROI(p_renderer, p_lodList)
{
	m_time = p_time;
}

// FUNCTION: LEGO1 0x100a9bf0
unsigned char LegoROI::CallTheHandlerFunction(
	char* p_param,
	float& p_red,
	float& p_green,
	float& p_blue,
	float& p_other
)
{
	// TODO
	if (p_param == NULL) {
		return FALSE;
	}

	if (g_someHandlerFunction) {
		char buf[32];
		if (g_someHandlerFunction(p_param, buf, 32)) {
			p_param = buf;
		}
	}

	return ColorAliasLookup(p_param, p_red, p_green, p_blue, p_other);
}

// FUNCTION: LEGO1 0x100a9c50
unsigned char LegoROI::ColorAliasLookup(char* p_param, float& p_red, float& p_green, float& p_blue, float& p_other)
{
	// TODO: this seems awfully hacky for these devs. is there a dynamic way
	// to represent `the end of this array` that would improve this?
	unsigned int i = 0;
	do {
		if (strcmpi(g_roiColorAliases[i].m_name, p_param) == 0) {
			p_red = g_roiColorAliases[i].m_red * g_normalizeByteToFloat;
			p_green = g_roiColorAliases[i].m_green * g_normalizeByteToFloat;
			p_blue = g_roiColorAliases[i].m_blue * g_normalizeByteToFloat;
			p_other = g_roiColorAliases[i].m_unk0x10 * g_normalizeByteToFloat;
			return TRUE;
		}
		i++;
	} while ((int*) &g_roiColorAliases[i] < &g_roiConfig);

	return FALSE;
}

// FUNCTION: LEGO1 0x100a9d30
void LegoROI::SetSomeHandlerFunction(ROIHandler p_func)
{
	g_someHandlerFunction = p_func;
}

// FUNCTION: LEGO1 0x100a9e10
void LegoROI::SetDisplayBB(int p_displayBB)
{
	// Intentionally empty function
}

// FUNCTION: LEGO1 0x100aa340
float LegoROI::IntrinsicImportance() const
{
	return .5;
}

// STUB: LEGO1 0x100aa350
void LegoROI::UpdateWorldBoundingVolumes()
{
	// TODO
}
