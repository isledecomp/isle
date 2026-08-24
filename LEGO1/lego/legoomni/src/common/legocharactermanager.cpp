
#include "legocharactermanager.h"

#include "3dmanager/lego3dmanager.h"
#include "legoactors.h"
#include "legoanimactor.h"
#include "legobuildingmanager.h"
#include "legoextraactor.h"
#include "legogamestate.h"
#include "legoplantmanager.h"
#include "legovideomanager.h"
#include "misc.h"
#include "misc/legocontainer.h"
#include "misc/legostorage.h"
#include "mxmisc.h"
#include "mxvariabletable.h"
#include "realtime/realtime.h"
#include "roi/legolod.h"
#include "viewmanager/viewmanager.h"

#include <assert.h>
#include <vec.h>

DECOMP_SIZE_ASSERT(LegoCharacter, 0x08)
DECOMP_SIZE_ASSERT(LegoCharacterManager, 0x08)
DECOMP_SIZE_ASSERT(CustomizeAnimFileVariable, 0x24)
DECOMP_SIZE_ASSERT(BoundingBox, 0x28)
DECOMP_SIZE_ASSERT(BoundingSphere, 0x18)
DECOMP_SIZE_ASSERT(ROI, 0x10)
DECOMP_SIZE_ASSERT(MxVariableTable, 0x28)
DECOMP_SIZE_ASSERT(LegoActorInfo, 0x108)
DECOMP_SIZE_ASSERT(LegoActorInfo::Part, 0x18)
DECOMP_SIZE_ASSERT(LegoActorLOD, 0x58)

enum {
	c_maxMood = 3,
	c_numParts = 10,
	c_indexEnd = 0xff
};

// Unclear whether g_actorLODs[0] (top) is its own global, see: LegoCharacterManager::CreateActorROI

// GLOBAL: LEGO1 0x100da3b0
const LegoActorLOD g_actorLODs[] = {
	{"top",    "top",     0,    0.000267f, 0.780808f, -0.01906f, 0.951612f, -0.461166f, -0.002794f, -0.299442f, 0.4617f,
	 1.56441f, 0.261321f, 0.0f, 0.0f,      0.0f,      0.0f,      0.0f,      1.0f,       0.0f,       1.0f,       0.0f},
	{"body",      "body",     LegoActorLOD::c_useTexture,
	 0.00158332f, 0.401828f,  -0.00048697f,
	 0.408071f,   -0.287507f, 0.150419f,
	 -0.147452f,  0.289219f,  0.649774f,
	 0.14258f,    -0.00089f,  0.436353f,
	 0.007277f,   0.0f,       0.0f,
	 1.0f,        0.0f,       1.0f,
	 0.0f},
	{"infohat",  "infohat",  LegoActorLOD::c_useColor,
	 0.0f,       -0.00938f,  -0.01955f,
	 0.35f,      -0.231822f, -0.140237f,
	 -0.320954f, 0.234149f,  0.076968f,
	 0.249083f,  0.000191f,  1.519793f,
	 0.001767f,  0.0f,       0.0f,
	 1.0f,       0.0f,       1.0f,
	 0.0f},
	{"infogron", "infogron", LegoActorLOD::c_useColor,
	 0.0f,       0.11477f,   0.00042f,
	 0.26f,      -0.285558f, -0.134391f,
	 -0.142231f, 0.285507f,  0.152986f,
	 0.143071f,  -0.00089f,  0.436353f,
	 0.007277f,  0.0f,       0.0f,
	 1.0f,       0.0f,       1.0f,
	 0.0f},
	{"head",     "head",     LegoActorLOD::c_useTexture,
	 0.0f,       -0.03006f,  0.0f,
	 0.3f,       -0.189506f, -0.209665f,
	 -0.189824f, 0.189532f,  0.228822f,
	 0.194945f,  -0.00105f,  1.293115f,
	 0.001781f,  0.0f,       0.0f,
	 1.0f,       0.0f,       1.0f,
	 0.0f},
	{"arm-lft",  "arm-lft",   LegoActorLOD::c_useColor,
	 -0.06815f,  -0.0973747f, 0.0154655f,
	 0.237f,     -0.137931f,  -0.282775f,
	 -0.105316f, 0.000989f,   0.100221f,
	 0.140759f,  -0.225678f,  0.963312f,
	 0.023286f,  -0.003031f,  -0.017187f,
	 0.999848f,  0.173622f,   0.984658f,
	 0.017453f},
	{"arm-rt",   "arm-rt",   LegoActorLOD::c_useColor,
	 0.0680946f, -0.097152f, 0.0152722f,
	 0.237f,     0.00141f,   -0.289604f,
	 -0.100831f, 0.138786f,  0.09291f,
	 0.145437f,  0.223494f,  0.963583f,
	 0.018302f,  0.0f,       0.0f,
	 1.0f,       -0.173648f, 0.984808f,
	 0.0f},
	{"claw-lft",   "claw-lft", LegoActorLOD::c_useColor,
	 0.000773381f, -0.101422f, -0.0237761f,
	 0.15f,        -0.089838f, -0.246208f,
	 -0.117735f,   0.091275f,  0.000263f,
	 0.07215f,     -0.341869f, 0.700355f,
	 0.092779f,    0.000001f,  0.000003f,
	 1.0f,         0.190812f,  0.981627f,
	 -0.000003f},
	{"claw-rt",    "claw-lft", LegoActorLOD::c_useColor,
	 0.000773381f, -0.101422f, -0.0237761f,
	 0.15f,        -0.095016f, -0.245349f,
	 -0.117979f,   0.086528f,  0.00067f,
	 0.069743f,    0.343317f,  0.69924f,
	 0.096123f,    0.00606f,   -0.034369f,
	 0.999391f,    -0.190704f, 0.981027f,
	 0.034894f},
	{"leg-lft",   "leg",      LegoActorLOD::c_useColor,
	 0.00433584f, -0.177404f, -0.0313928f,
	 0.33f,       -0.129782f, -0.440428f,
	 -0.184207f,  0.13817f,   0.118415f,
	 0.122607f,   -0.156339f, 0.436087f,
	 0.006822f,   0.0f,       0.0f,
	 1.0f,        0.0f,       1.0f,
	 0.0f},
	{"leg-rt",    "leg",      LegoActorLOD::c_useColor,
	 0.00433584f, -0.177404f, -0.0313928f,
	 0.33f,       -0.132864f, -0.437138f,
	 -0.183944f,  0.134614f,  0.12043f,
	 0.121888f,   0.151154f,  0.436296f,
	 0.007373f,   0.0f,       0.0f,
	 1.0f,        0.0f,       1.0f,
	 0.0f}
};

// GLOBAL: LEGO1 0x100da778
const MxU8 g_hatPartIndices[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 0xff};

// GLOBAL: LEGO1 0x100da790
const MxU8 g_pepperHatPartIndices[] = {21, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 0xff};

// GLOBAL: LEGO1 0x100da7a8
const MxU8 g_infomanHatPartIndices[] = {22, 0xff};

// GLOBAL: LEGO1 0x100da7ac
const MxU8 g_ghostHatPartIndices[] = {20, 0xff};

// GLOBAL: LEGO1 0x100da7b0
const MxU8 g_bodyPartIndices[] = {0, 1, 2, 3, 4, 5, 6, 7, 0xff};

// GLOBAL: LEGO1 0x100da7c0
const MxU8 g_hatColorIndices[] = {0, 1, 2, 3, 4, 5, 6, 7, 0xff};

// GLOBAL: LEGO1 0x100da7d0
const MxU8 g_faceTextureIndices[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0xff};

// GLOBAL: LEGO1 0x100da7e0
const MxU8 g_chestTextureIndices[] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13,
									  14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 27, 0xff};

// GLOBAL: LEGO1 0x100da800
const MxU8 g_armColorIndices[] = {0, 1, 2, 3, 4, 5, 6, 7, 0xff};

// GLOBAL: LEGO1 0x100da810
const MxU8 g_clawRightColorIndices[] = {0, 1, 2, 3, 4, 5, 6, 7, 0xff};

// GLOBAL: LEGO1 0x100da820
const MxU8 g_clawLeftColorIndices[] = {0, 1, 2, 3, 4, 5, 6, 7, 0xff};

// GLOBAL: LEGO1 0x100da830
const MxU8 g_gronColorIndices[] = {0, 1, 2, 3, 4, 5, 6, 7, 0xff};

// GLOBAL: LEGO1 0x100da840
const MxU8 g_legColorIndices[] = {0, 1, 2, 3, 4, 5, 6, 7, 0xff};

// GLOBAL: LEGO1 0x100f7f78
const char* g_hatPartName[] = {"baseball", "chef",   "cap",     "cophat", "helmet", "ponytail", "pageboy", "shrthair",
							   "bald",     "flower", "cboyhat", "cuphat", "cathat", "backbcap", "pizhat",  "caprc",
							   "capch",    "capdb",  "capjs",   "capmd",  "sheet",  "phat",     "icap",    NULL};

// GLOBAL: LEGO1 0x100f7fd8
const char* g_bodyPartName[] =
	{"body", "bodyred", "bodyblck", "bodywhte", "bodyyllw", "bodyblue", "bodygren", "bodybrwn"};

// GLOBAL: LEGO1 0x100f7ff8
const char* g_chestTexture[] = {"peprchst.gif", "mamachst.gif", "papachst.gif", "nickchst.gif", "norachst.gif",
								"infochst.gif", "shftchst.gif", "rac1chst.gif", "rac2chst.gif", "bth1chst.gif",
								"bth2chst.gif", "mech.gif",     "polkadot.gif", "bowtie.gif",   "postchst.gif",
								"vest.gif",     "doctor.gif",   "copchest.gif", "l.gif",        "e.gif",
								"g.gif",        "o.gif",        "fruit.gif",    "flowers.gif",  "construct.gif",
								"paint.gif",    "l6.gif",       "unkchst.gif"};

// GLOBAL: LEGO1 0x100f8068
const char* g_faceTexture[] = {
	"peprface.gif",
	"mamaface.gif",
	"papaface.gif",
	"nickface.gif",
	"noraface.gif",
	"infoface.gif",
	"shftface.gif",
	"dogface.gif",
	"womanshd.gif",
	"smileshd.gif",
	"woman.gif",
	"smile.gif",
	"mustache.gif",
	"black.gif"
};

// GLOBAL: LEGO1 0x100f80a0
const char* g_colorAlias[] =
	{"lego white", "lego black", "lego yellow", "lego red", "lego blue", "lego brown", "lego lt grey", "lego green"};

// GLOBAL: LEGO1 0x100f80c0
LegoActorInfo g_actorInfoInit[] = {
	{"pepper",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 1, g_chestTextureIndices, g_chestTexture, 0},
	  {g_pepperHatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4}}},
	{"mama",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 1, g_chestTextureIndices, g_chestTexture, 1},
	  {g_hatPartIndices, g_hatPartName, 1, g_hatColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 1},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0}}},
	{"papa",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 2, g_chestTextureIndices, g_chestTexture, 2},
	  {g_hatPartIndices, g_hatPartName, 1, g_hatColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 2},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1}}},
	{"nick",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 2, g_chestTextureIndices, g_chestTexture, 3},
	  {g_hatPartIndices, g_hatPartName, 3, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 3},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4}}},
	{"laura",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 2, g_chestTextureIndices, g_chestTexture, 4},
	  {g_hatPartIndices, g_hatPartName, 3, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 4},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4}}},
	{"infoman",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 1, g_chestTextureIndices, g_chestTexture, 5},
	  {g_infomanHatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 5},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0}}},
	{"brickstr",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 3, g_chestTextureIndices, g_chestTexture, 6},
	  {g_hatPartIndices, g_hatPartName, 13, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 6},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1}}},
	{"studs",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 1, g_chestTextureIndices, g_chestTexture, 7},
	  {g_hatPartIndices, g_hatPartName, 4, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 7},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1}}},
	{"rhoda",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 5, g_chestTextureIndices, g_chestTexture, 8},
	  {g_hatPartIndices, g_hatPartName, 4, g_hatColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 8},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1}}},
	{"valerie",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 1, g_chestTextureIndices, g_chestTexture, 9},
	  {g_hatPartIndices, g_hatPartName, 5, g_hatColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 8},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 2}}},
	{"snap",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 3, g_chestTextureIndices, g_chestTexture, 10},
	  {g_hatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 9},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 2}}},
	{"pt",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 5, g_chestTextureIndices, g_chestTexture, 11},
	  {g_hatPartIndices, g_hatPartName, 6, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 8},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1}}},
	{"mg",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 1, g_chestTextureIndices, g_chestTexture, 12},
	  {g_hatPartIndices, g_hatPartName, 6, g_hatColorIndices, g_colorAlias, 5},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 10},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4}}},
	{"bu",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 3, g_chestTextureIndices, g_chestTexture, 13},
	  {g_hatPartIndices, g_hatPartName, 7, g_hatColorIndices, g_colorAlias, 5},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 5},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 11},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 5},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 5}}},
	{"ml",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 5, g_chestTextureIndices, g_chestTexture, 14},
	  {g_hatPartIndices, g_hatPartName, 2, g_hatColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 12},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1}}},
	{"nu",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 5, g_chestTextureIndices, g_chestTexture, 11},
	  {g_hatPartIndices, g_hatPartName, 7, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 7},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4}}},
	{"na",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 3, g_chestTextureIndices, g_chestTexture, 15},
	  {g_hatPartIndices, g_hatPartName, 10, g_hatColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 8},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 3}}},
	{"cl",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 3, g_chestTextureIndices, g_chestTexture, 16},
	  {g_hatPartIndices, g_hatPartName, 19, g_hatColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 12},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4}}},
	{"en",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 3, g_chestTextureIndices, g_chestTexture, 16},
	  {g_hatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 11},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0}}},
	{"re",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 3, g_chestTextureIndices, g_chestTexture, 16},
	  {g_hatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 11},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0}}},
	{"ro",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 2, g_chestTextureIndices, g_chestTexture, 17},
	  {g_hatPartIndices, g_hatPartName, 3, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 9},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1}}},
	{"d1",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 5, g_chestTextureIndices, g_chestTexture, 11},
	  {g_hatPartIndices, g_hatPartName, 15, g_hatColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 11},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4}}},
	{"d2",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 5, g_chestTextureIndices, g_chestTexture, 11},
	  {g_hatPartIndices, g_hatPartName, 16, g_hatColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 11},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4}}},
	{"d3",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 5, g_chestTextureIndices, g_chestTexture, 11},
	  {g_hatPartIndices, g_hatPartName, 17, g_hatColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 11},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4}}},
	{"d4",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 5, g_chestTextureIndices, g_chestTexture, 11},
	  {g_hatPartIndices, g_hatPartName, 18, g_hatColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 11},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4}}},
	{"l1",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 1, g_chestTextureIndices, g_chestTexture, 18},
	  {g_hatPartIndices, g_hatPartName, 5, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 11},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0}}},
	{"l2",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 1, g_chestTextureIndices, g_chestTexture, 19},
	  {g_hatPartIndices, g_hatPartName, 6, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 12},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0}}},
	{"l3",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 1, g_chestTextureIndices, g_chestTexture, 20},
	  {g_hatPartIndices, g_hatPartName, 7, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 11},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0}}},
	{"l4",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 1, g_chestTextureIndices, g_chestTexture, 21},
	  {g_hatPartIndices, g_hatPartName, 7, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 11},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0}}},
	{"l5",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 1, g_chestTextureIndices, g_chestTexture, 26},
	  {g_hatPartIndices, g_hatPartName, 7, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 12},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0}}},
	{"l6",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 1, g_chestTextureIndices, g_chestTexture, 26},
	  {g_hatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 11},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0}}},
	{"b1",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 1},
	  {g_hatPartIndices, g_hatPartName, 7, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 12},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1}}},
	{"b2",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 1},
	  {g_hatPartIndices, g_hatPartName, 5, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 10},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4}}},
	{"b3",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 4},
	  {g_hatPartIndices, g_hatPartName, 7, g_hatColorIndices, g_colorAlias, 5},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 11},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1}}},
	{"b4",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 1},
	  {g_hatPartIndices, g_hatPartName, 7, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 9},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1}}},
	{"cm",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 4, g_chestTextureIndices, g_chestTexture, 22},
	  {g_hatPartIndices, g_hatPartName, 9, g_hatColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 8},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 3}}},
	{"gd",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 1},
	  {g_hatPartIndices, g_hatPartName, 7, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 6},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 11},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 6},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 6},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 6},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 6}}},
	{"rd",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 3},
	  {g_hatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 7},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 9},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 7},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 7}}},
	{"pg",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 3},
	  {g_hatPartIndices, g_hatPartName, 5, g_hatColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 11},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 3}}},
	{"bd",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 6},
	  {g_hatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 6},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 12},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1}}},
	{"sy",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 4},
	  {g_hatPartIndices, g_hatPartName, 5, g_hatColorIndices, g_colorAlias, 6},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 10},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4}}},
	{"gn",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 6, g_chestTextureIndices, g_chestTexture, 13},
	  {g_hatPartIndices, g_hatPartName, 7, g_hatColorIndices, g_colorAlias, 5},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 5},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 9},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 5},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 5}}},
	{"df",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 5, g_chestTextureIndices, g_chestTexture, 23},
	  {g_hatPartIndices, g_hatPartName, 6, g_hatColorIndices, g_colorAlias, 5},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 6},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 8},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 6},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 6}}},
	{"bs",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 3, g_chestTextureIndices, g_chestTexture, 10},
	  {g_hatPartIndices, g_hatPartName, 7, g_hatColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 7},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 11},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 2}}},
	{"lt",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 3, g_chestTextureIndices, g_chestTexture, 10},
	  {g_hatPartIndices, g_hatPartName, 7, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 11},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 2}}},
	{"st",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 1, g_chestTextureIndices, g_chestTexture, 9},
	  {g_hatPartIndices, g_hatPartName, 5, g_hatColorIndices, g_colorAlias, 5},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 10},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 2}}},
	{"bm",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 3, g_chestTextureIndices, g_chestTexture, 24},
	  {g_hatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 7},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 6},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 6},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4}}},
	{"jk",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 3, g_chestTextureIndices, g_chestTexture, 24},
	  {g_hatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 9},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 6},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 6},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4}}},
	{"ghost",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 0},
	  {g_ghostHatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 13},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0}}},
	{"ghost01",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 0},
	  {g_ghostHatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 13},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0}}},
	{"ghost02",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 0},
	  {g_ghostHatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 13},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0}}},
	{"ghost03",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 0},
	  {g_ghostHatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 13},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0}}},
	{"ghost04",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 0},
	  {g_ghostHatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 13},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0}}},
	{"ghost05",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 0},
	  {g_ghostHatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 13},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 0}}},
	{"hg",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 3},
	  {g_hatPartIndices, g_hatPartName, 8, g_hatColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 8},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 3}}},
	{"pntgy",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 3},
	  {g_hatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 7},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 3}}},
	{"pep",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 1, g_chestTextureIndices, g_chestTexture, 0},
	  {g_pepperHatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4}}},
	{"cop01",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 2, g_chestTextureIndices, g_chestTexture, 17},
	  {g_hatPartIndices, g_hatPartName, 3, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 9},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1}}},
	{"actor_01",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 4},
	  {g_hatPartIndices, g_hatPartName, 5, g_hatColorIndices, g_colorAlias, 6},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 10},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4}}},
	{"actor_02",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 6},
	  {g_hatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 6},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 12},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 1}}},
	{"actor_03",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 1},
	  {g_hatPartIndices, g_hatPartName, 7, g_hatColorIndices, g_colorAlias, 1},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 6},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 11},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 6},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 6},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 6},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 6}}},
	{"actor_04",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 1, g_chestTextureIndices, g_chestTexture, 12},
	  {g_hatPartIndices, g_hatPartName, 6, g_hatColorIndices, g_colorAlias, 5},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 10},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 4}}},
	{"actor_05",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 4, g_chestTextureIndices, g_chestTexture, 22},
	  {g_hatPartIndices, g_hatPartName, 9, g_hatColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 8},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 3}}},
	{"btmncycl",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 3},
	  {g_hatPartIndices, g_hatPartName, 5, g_hatColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 11},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 0},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 3}}},
	{"cboycycl",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 3, g_chestTextureIndices, g_chestTexture, 10},
	  {g_hatPartIndices, g_hatPartName, 7, g_hatColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 7},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 11},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 2}}},
	{"boatman",
	 NULL,
	 NULL,
	 0,
	 0,
	 0,
	 {{g_bodyPartIndices, g_bodyPartName, 0, g_legColorIndices, g_colorAlias, 3},
	  {g_hatPartIndices, g_hatPartName, 0, g_hatColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_gronColorIndices, g_colorAlias, 7},
	  {NULL, NULL, 0, g_faceTextureIndices, g_faceTexture, 9},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_armColorIndices, g_colorAlias, 3},
	  {NULL, NULL, 0, g_clawLeftColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_clawRightColorIndices, g_colorAlias, 2},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 7},
	  {NULL, NULL, 0, g_legColorIndices, g_colorAlias, 7}}}
};

// GLOBAL: LEGO1 0x100fc4d0
MxU32 LegoCharacterManager::g_maxMove = 4;

// GLOBAL: LEGO1 0x100fc4d4
MxU32 LegoCharacterManager::g_maxSound = 9;

// GLOBAL: LEGO1 0x100fc4d8
MxU32 g_characterSoundIdOffset = 50;

// GLOBAL: LEGO1 0x100fc4dc
MxU32 g_characterSoundIdMoodOffset = 66;

// GLOBAL: LEGO1 0x100fc4e0
MxU32 g_characterAnimationId = 10;

// GLOBAL: LEGO1 0x100fc4e4
char* LegoCharacterManager::g_customizeAnimFile = NULL;

// GLOBAL: LEGO1 0x100fc4e8
MxU32 g_headTextureCounter = 0;

// GLOBAL: LEGO1 0x100fc4ec
MxU32 g_infohatVariantCounter = 2;

// GLOBAL: LEGO1 0x100fc4f0
MxU32 g_autoRoiCounter = 0;

// GLOBAL: LEGO1 0x10104f20
LegoActorInfo g_actorInfo[66];

// FUNCTION: LEGO1 0x10082a20
// FUNCTION: BETA10 0x10073c60
LegoCharacterManager::LegoCharacterManager()
{
	m_characters = new LegoCharacterMap();
	Init(); // DECOMP: inlined here in BETA10

	m_customizeAnimFile = new CustomizeAnimFileVariable("CUSTOMIZE_ANIM_FILE");
	VariableTable()->SetVariable(m_customizeAnimFile);
}

// FUNCTION: LEGO1 0x10083180
// FUNCTION: BETA10 0x10073dad
LegoCharacterManager::~LegoCharacterManager()
{
	LegoCharacter* character = NULL;
	LegoCharacterMap::iterator it;

	for (it = m_characters->begin(); it != m_characters->end(); it++) {
		character = (*it).second;

		RemoveROI(character->m_roi);

		delete[] (*it).first;
		delete (*it).second;
	}

	delete m_characters;
	delete[] g_customizeAnimFile;
}

// FUNCTION: LEGO1 0x10083270
void LegoCharacterManager::Init()
{
	for (MxS32 i = 0; i < sizeOfArray(g_actorInfo); i++) {
		g_actorInfo[i] = g_actorInfoInit[i];
	}
}

// FUNCTION: LEGO1 0x100832a0
void LegoCharacterManager::ReleaseAllActors()
{
	for (MxS32 i = 0; i < sizeOfArray(g_actorInfo); i++) {
		LegoActorInfo* info = GetActorInfo(g_actorInfo[i].m_name);

		if (info != NULL) {
			LegoExtraActor* actor = info->m_actor;

			if (actor != NULL && actor->IsA("LegoExtraActor")) {
				LegoROI* roi = g_actorInfo[i].m_roi;
				MxU32 refCount = GetRefCount(roi);

				while (refCount != 0) {
					ReleaseActor(roi);
					refCount = GetRefCount(roi);
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x10083310
MxResult LegoCharacterManager::Write(LegoStorage* p_storage)
{
	MxResult result = FAILURE;

	for (MxS32 i = 0; i < sizeOfArray(g_actorInfo); i++) {
		LegoActorInfo* info = &g_actorInfo[i];

		if (p_storage->Write(&info->m_sound, sizeof(info->m_sound)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_move, sizeof(info->m_move)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_mood, sizeof(info->m_mood)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(
				&info->m_parts[c_infohatPart].m_partNameIndex,
				sizeof(info->m_parts[c_infohatPart].m_partNameIndex)
			) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(
				&info->m_parts[c_infohatPart].m_nameIndex,
				sizeof(info->m_parts[c_infohatPart].m_nameIndex)
			) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(
				&info->m_parts[c_infogronPart].m_nameIndex,
				sizeof(info->m_parts[c_infogronPart].m_nameIndex)
			) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(
				&info->m_parts[c_armlftPart].m_nameIndex,
				sizeof(info->m_parts[c_armlftPart].m_nameIndex)
			) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_parts[c_armrtPart].m_nameIndex, sizeof(info->m_parts[c_armrtPart].m_nameIndex)) !=
			SUCCESS) {
			goto done;
		}
		if (p_storage->Write(
				&info->m_parts[c_leglftPart].m_nameIndex,
				sizeof(info->m_parts[c_leglftPart].m_nameIndex)
			) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_parts[c_legrtPart].m_nameIndex, sizeof(info->m_parts[c_legrtPart].m_nameIndex)) !=
			SUCCESS) {
			goto done;
		}
	}

	result = SUCCESS;

done:
	return result;
}

// FUNCTION: LEGO1 0x100833f0
MxResult LegoCharacterManager::Read(LegoStorage* p_storage)
{
	MxResult result = FAILURE;

	for (MxS32 i = 0; i < sizeOfArray(g_actorInfo); i++) {
		LegoActorInfo* info = &g_actorInfo[i];

		if (p_storage->Read(&info->m_sound, sizeof(MxS32)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_move, sizeof(MxS32)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_mood, sizeof(MxU8)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_parts[c_infohatPart].m_partNameIndex, sizeof(MxU8)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_parts[c_infohatPart].m_nameIndex, sizeof(MxU8)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_parts[c_infogronPart].m_nameIndex, sizeof(MxU8)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_parts[c_armlftPart].m_nameIndex, sizeof(MxU8)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_parts[c_armrtPart].m_nameIndex, sizeof(MxU8)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_parts[c_leglftPart].m_nameIndex, sizeof(MxU8)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_parts[c_legrtPart].m_nameIndex, sizeof(MxU8)) != SUCCESS) {
			goto done;
		}
	}

	result = SUCCESS;

done:
	return result;
}

// FUNCTION: LEGO1 0x100834d0
// FUNCTION: BETA10 0x100742eb
const char* LegoCharacterManager::GetActorName(MxS32 p_index)
{
	if (p_index < sizeOfArray(g_actorInfo)) {
		return g_actorInfo[p_index].m_name;
	}
	else {
		return NULL;
	}
}

// FUNCTION: LEGO1 0x100834f0
// FUNCTION: BETA10 0x1007432a
MxU32 LegoCharacterManager::GetNumActors()
{
	return sizeOfArray(g_actorInfo);
}

// FUNCTION: LEGO1 0x10083500
// FUNCTION: BETA10 0x10074345
LegoROI* LegoCharacterManager::GetActorROI(const char* p_name, MxBool p_createEntity)
{
	LegoCharacter* character = NULL;
	LegoCharacterMap::const_iterator it = m_characters->find(const_cast<char*>(p_name));

	if (!(it == m_characters->end())) {
		character = (*it).second;
		character->AddRef();
	}

	if (character == NULL) {
		LegoROI* roi = CreateActorROI(p_name);

		if (roi != NULL) {
			roi->SetVisibility(FALSE);

			character = new LegoCharacter(roi);
			char* name = new char[strlen(p_name) + 1];

			if (name != NULL) {
				strcpy(name, p_name);
				(*m_characters)[name] = character;
				VideoManager()->Get3DManager()->Add(*roi);
			}
		}
	}
	else {
		VideoManager()->Get3DManager()->Remove(*character->m_roi);
		VideoManager()->Get3DManager()->Add(*character->m_roi);
	}

	if (character != NULL) {
		if (p_createEntity && character->m_roi->GetEntity() == NULL) {
			LegoExtraActor* actor = new LegoExtraActor();

			actor->SetROI(character->m_roi, FALSE, FALSE);
			actor->SetType(LegoEntity::e_actor);
			actor->SetFlag(LegoEntity::c_managerOwned);
			GetActorInfo(p_name)->m_actor = actor;
		}

		return character->m_roi;
	}
	else {
		return NULL;
	}
}

// FUNCTION: LEGO1 0x10083b20
// FUNCTION: BETA10 0x10074608
MxBool LegoCharacterManager::Exists(const char* p_name)
{
	LegoCharacterMap::iterator it = m_characters->find(const_cast<char*>(p_name));

	if (it != m_characters->end()) {
		return TRUE;
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10083bc0
// FUNCTION: BETA10 0x1007466a
MxU32 LegoCharacterManager::GetRefCount(LegoROI* p_roi)
{
	LegoCharacter* character = NULL;
	LegoCharacterMap::iterator it;

	for (it = m_characters->begin(); it != m_characters->end(); it++) {
		character = (*it).second;
		LegoROI* roi = character->m_roi;

		if (roi == p_roi) {
			return character->m_refCount;
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x10083c30
// FUNCTION: BETA10 0x10074701
void LegoCharacterManager::ReleaseActor(const char* p_name)
{
	LegoCharacter* character = NULL;
	LegoCharacterMap::iterator it = m_characters->find(const_cast<char*>(p_name));

	if (it != m_characters->end()) {
		character = (*it).second;

		if (character->RemoveRef() == 0) {
			LegoActorInfo* info = GetActorInfo(p_name);
			LegoEntity* entity = character->m_roi->GetEntity();

			if (entity != NULL) {
				entity->SetROI(NULL, FALSE, FALSE);
			}

			RemoveROI(character->m_roi);

			delete[] (*it).first;
			delete (*it).second;

			m_characters->erase(it);

			if (info != NULL) {
				if (info->m_actor != NULL) {
					info->m_actor->ClearFlag(LegoEntity::c_managerOwned);
					delete info->m_actor;
				}
				else if (entity != NULL && entity->GetFlagsIsSet(LegoEntity::c_managerOwned)) {
					entity->ClearFlag(LegoEntity::c_managerOwned);
					delete entity;
				}

				info->m_roi = NULL;
				info->m_actor = NULL;
			}
		}
	}
}

// FUNCTION: LEGO1 0x10083db0
void LegoCharacterManager::ReleaseActor(LegoROI* p_roi)
{
	LegoCharacter* character = NULL;
	LegoCharacterMap::iterator it;

	for (it = m_characters->begin(); it != m_characters->end(); it++) {
		character = (*it).second;

		if (character->m_roi == p_roi) {
			if (character->RemoveRef() == 0) {
				LegoActorInfo* info = GetActorInfo(character->m_roi->GetName());
				LegoEntity* entity = character->m_roi->GetEntity();

				if (entity != NULL) {
					entity->SetROI(NULL, FALSE, FALSE);
				}

				RemoveROI(character->m_roi);

				delete[] (*it).first;
				delete (*it).second;

				m_characters->erase(it);

				if (info != NULL) {
					if (info->m_actor != NULL) {
						info->m_actor->ClearFlag(LegoEntity::c_managerOwned);
						delete info->m_actor;
					}
					else if (entity != NULL && entity->GetFlagsIsSet(LegoEntity::c_managerOwned)) {
						entity->ClearFlag(LegoEntity::c_managerOwned);
						delete entity;
					}

					info->m_roi = NULL;
					info->m_actor = NULL;
				}
			}

			return;
		}
	}
}

// FUNCTION: LEGO1 0x10083f10
void LegoCharacterManager::ReleaseAutoROI(LegoROI* p_roi)
{
	LegoCharacter* character = NULL;
	LegoCharacterMap::iterator it;

	for (it = m_characters->begin(); it != m_characters->end(); it++) {
		character = (*it).second;

		if (character->m_roi == p_roi) {
			if (character->RemoveRef() == 0) {
				LegoEntity* entity = character->m_roi->GetEntity();

				if (entity != NULL) {
					entity->SetROI(NULL, FALSE, FALSE);
				}

				RemoveROI(character->m_roi);

				delete[] (*it).first;
				delete (*it).second;

				m_characters->erase(it);

				if (entity != NULL && entity->GetFlagsIsSet(LegoEntity::c_managerOwned)) {
					entity->ClearFlag(LegoEntity::c_managerOwned);
					delete entity;
				}
			}

			return;
		}
	}
}

// FUNCTION: LEGO1 0x10084010
// FUNCTION: BETA10 0x10074e20
void LegoCharacterManager::RemoveROI(LegoROI* p_roi)
{
	VideoManager()->Get3DManager()->Remove(*p_roi);
}

// FUNCTION: LEGO1 0x10084030
// FUNCTION: BETA10 0x10074e4f
LegoROI* LegoCharacterManager::CreateActorROI(const char* p_key)
{
	MxBool success = FALSE;
	LegoROI* roi = NULL;
	BoundingSphere boundingSphere;
	BoundingBox boundingBox;
	MxMatrix mat;
	CompoundObject* comp;
	MxS32 i;

	Tgl::Renderer* renderer = VideoManager()->GetRenderer();
	ViewLODListManager* lodManager = GetViewLODListManager();
	LegoTextureContainer* textureContainer = TextureContainer();
	LegoActorInfo* info = GetActorInfo(p_key);

	if (info == NULL) {
		goto done;
	}

	if (!strcmpi(p_key, "pep")) {
		LegoActorInfo* pepper = GetActorInfo("pepper");

		info->m_sound = pepper->m_sound;
		info->m_move = pepper->m_move;
		info->m_mood = pepper->m_mood;

		for (i = 0; i < sizeOfArray(info->m_parts); i++) {
			info->m_parts[i] = pepper->m_parts[i];
		}
	}

	roi = new LegoROI(renderer);
	roi->SetName(p_key);

	boundingSphere.Center()[0] = g_actorLODs[c_topLOD].m_boundingSphere[0];
	boundingSphere.Center()[1] = g_actorLODs[c_topLOD].m_boundingSphere[1];
	boundingSphere.Center()[2] = g_actorLODs[c_topLOD].m_boundingSphere[2];
	boundingSphere.Radius() = g_actorLODs[c_topLOD].m_boundingSphere[3];
	roi->SetBoundingSphere(boundingSphere);

	boundingBox.Min()[0] = g_actorLODs[c_topLOD].m_boundingBox[0];
	boundingBox.Min()[1] = g_actorLODs[c_topLOD].m_boundingBox[1];
	boundingBox.Min()[2] = g_actorLODs[c_topLOD].m_boundingBox[2];
	boundingBox.Max()[0] = g_actorLODs[c_topLOD].m_boundingBox[3];
	boundingBox.Max()[1] = g_actorLODs[c_topLOD].m_boundingBox[4];
	boundingBox.Max()[2] = g_actorLODs[c_topLOD].m_boundingBox[5];
	roi->SetBoundingBox(boundingBox);

	comp = new CompoundObject();
	roi->SetComp(comp);

	for (i = 0; i < sizeOfArray(g_actorLODs) - 1; i++) {
		char lodName[256];
		LegoActorInfo::Part& part = info->m_parts[i];

		const char* parentName;
		if (i == 0 || i == 1) {
			parentName = part.m_partName[part.m_partNameIndices[part.m_partNameIndex]];
		}
		else {
			parentName = g_actorLODs[i + 1].m_parentName;
		}

		ViewLODList* lodList = lodManager->Lookup(parentName);
		assert(lodList);
		MxS32 lodSize = lodList->Size();
		sprintf(lodName, "%s%d", p_key, i);
		ViewLODList* dupLodList = lodManager->Create(lodName, lodSize);
		assert(dupLodList);

		for (MxS32 j = 0; j < lodSize; j++) {
			LegoLOD* lod = (LegoLOD*) (*lodList)[j];
			LegoLOD* clone = lod->Clone(renderer);
			dupLodList->PushBack(clone);
		}

		lodList->Release();
		lodList = dupLodList;

		LegoROI* childRoi = new LegoROI(renderer, lodList);
		assert(childRoi);
		lodList->Release();

		childRoi->SetName(g_actorLODs[i + 1].m_name);
		childRoi->SetParentROI(roi);

		BoundingSphere childBoundingSphere;
		childBoundingSphere.Center()[0] = g_actorLODs[i + 1].m_boundingSphere[0];
		childBoundingSphere.Center()[1] = g_actorLODs[i + 1].m_boundingSphere[1];
		childBoundingSphere.Center()[2] = g_actorLODs[i + 1].m_boundingSphere[2];
		childBoundingSphere.Radius() = g_actorLODs[i + 1].m_boundingSphere[3];
		childRoi->SetBoundingSphere(childBoundingSphere);

		BoundingBox childBoundingBox;
		childBoundingBox.Min()[0] = g_actorLODs[i + 1].m_boundingBox[0];
		childBoundingBox.Min()[1] = g_actorLODs[i + 1].m_boundingBox[1];
		childBoundingBox.Min()[2] = g_actorLODs[i + 1].m_boundingBox[2];
		childBoundingBox.Max()[0] = g_actorLODs[i + 1].m_boundingBox[3];
		childBoundingBox.Max()[1] = g_actorLODs[i + 1].m_boundingBox[4];
		childBoundingBox.Max()[2] = g_actorLODs[i + 1].m_boundingBox[5];
		childRoi->SetBoundingBox(childBoundingBox);

		CalcLocalTransform(
			Mx3DPointFloat(g_actorLODs[i + 1].m_position),
			Mx3DPointFloat(g_actorLODs[i + 1].m_direction),
			Mx3DPointFloat(g_actorLODs[i + 1].m_up),
			mat
		);
		childRoi->WrappedSetLocal2WorldWithWorldDataUpdate(mat);

		if (g_actorLODs[i + 1].m_flags & LegoActorLOD::c_useTexture &&
			(i != 0 || part.m_partNameIndices[part.m_partNameIndex] != 0)) {

			LegoTextureInfo* texture = textureContainer->Get(part.m_names[part.m_nameIndices[part.m_nameIndex]]);
			assert(texture);

			if (texture != NULL) {
				childRoi->SetTextureInfo(texture);
				childRoi->SetLodColor(1.0F, 1.0F, 1.0F, 0.0F);
			}
		}
		else if (g_actorLODs[i + 1].m_flags & LegoActorLOD::c_useColor || (i == 0 && part.m_partNameIndices[part.m_partNameIndex] == 0)) {
			LegoFloat red, green, blue, alpha;
			childRoi->GetRGBAColor(part.m_names[part.m_nameIndices[part.m_nameIndex]], red, green, blue, alpha);
			childRoi->SetLodColor(red, green, blue, alpha);
		}

		comp->push_back(childRoi);
	}

	CalcLocalTransform(
		Mx3DPointFloat(g_actorLODs[c_topLOD].m_position),
		Mx3DPointFloat(g_actorLODs[c_topLOD].m_direction),
		Mx3DPointFloat(g_actorLODs[c_topLOD].m_up),
		mat
	);
	roi->WrappedSetLocal2WorldWithWorldDataUpdate(mat);

	info->m_roi = roi;
	success = TRUE;

done:
	if (!success && roi != NULL) {
		delete roi;
		roi = NULL;
	}

	return roi;
}

// FUNCTION: LEGO1 0x100849a0
// FUNCTION: BETA10 0x10075b51
MxBool LegoCharacterManager::SetHeadTexture(LegoROI* p_roi, LegoTextureInfo* p_texture)
{
	LegoResult result = SUCCESS;
	LegoROI* head = FindChildROI(p_roi, g_actorLODs[c_headLOD].m_name);

	if (head != NULL) {
		char lodName[256];

		ViewLODList* lodList = GetViewLODListManager()->Lookup(g_actorLODs[c_headLOD].m_parentName);
		assert(lodList);

		MxS32 lodSize = lodList->Size();
		sprintf(lodName, "%s%s%d", p_roi->GetName(), "head", g_headTextureCounter++);
		ViewLODList* dupLodList = GetViewLODListManager()->Create(lodName, lodSize);
		assert(dupLodList);

		Tgl::Renderer* renderer = VideoManager()->GetRenderer();

		if (p_texture == NULL) {
			LegoActorInfo* info = GetActorInfo(p_roi->GetName());
			assert(info);

			LegoActorInfo::Part& part = info->m_parts[c_headPart];
			p_texture = TextureContainer()->Get(part.m_names[part.m_nameIndices[part.m_nameIndex]]);
			assert(p_texture);
		}

		for (MxS32 i = 0; i < lodSize; i++) {
			LegoLOD* lod = (LegoLOD*) (*lodList)[i];
			LegoLOD* clone = lod->Clone(renderer);

			if (p_texture != NULL) {
				clone->UpdateTextureInfo(p_texture);
			}

			dupLodList->PushBack(clone);
		}

		lodList->Release();
		lodList = dupLodList;

		if (head->GetToken() >= 0) {
			VideoManager()->Get3DManager()->GetLego3DView()->GetViewManager()->RemoveROIDetailFromScene(head);
		}

		head->SetLODList(lodList);
		lodList->Release();
	}

	return head != NULL;
}

// FUNCTION: LEGO1 0x10084c00
// FUNCTION: BETA10 0x10075e40
MxBool LegoCharacterManager::IsActor(const char* p_name)
{
	for (MxU32 i = 0; i < sizeOfArray(g_actorInfo); i++) {
		const char* name = g_actorInfo[i].m_name;

		if (!strcmpi(name, p_name)) {
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10084c40
// FUNCTION: BETA10 0x10075ea0
LegoExtraActor* LegoCharacterManager::GetExtraActor(const char* p_name)
{
	LegoActorInfo* info = GetActorInfo(p_name);

	if (info != NULL) {
		return info->m_actor;
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10084c60
// FUNCTION: BETA10 0x10075ede
LegoActorInfo* LegoCharacterManager::GetActorInfo(const char* p_name)
{
	MxU32 i;

	for (i = 0; i < sizeOfArray(g_actorInfo); i++) {
		const char* name = g_actorInfo[i].m_name;

		if (!strcmpi(name, p_name)) {
			break;
		}
	}

	if (i < sizeOfArray(g_actorInfo)) {
		return &g_actorInfo[i];
	}
	else {
		return NULL;
	}
}

// FUNCTION: LEGO1 0x10084cb0
// FUNCTION: BETA10 0x10075f66
LegoActorInfo* LegoCharacterManager::GetActorInfo(LegoROI* p_roi)
{
	MxU32 i;

	for (i = 0; i < sizeOfArray(g_actorInfo); i++) {
		LegoROI* roi = g_actorInfo[i].m_roi;

		if (roi == p_roi) {
			break;
		}
	}

	if (i < sizeOfArray(g_actorInfo)) {
		return &g_actorInfo[i];
	}
	else {
		return NULL;
	}
}

// FUNCTION: LEGO1 0x10084cf0
// FUNCTION: BETA10 0x10075fe2
LegoROI* LegoCharacterManager::FindChildROI(LegoROI* p_roi, const char* p_name)
{
#ifdef COMPAT_MODE
	CompoundObject::const_iterator it;
#else
	CompoundObject::iterator it;
#endif

	const CompoundObject* comp = p_roi->GetComp();

	for (it = comp->begin(); it != comp->end(); it++) {
		LegoROI* roi = (LegoROI*) *it;

		if (!strcmpi(p_name, roi->GetName())) {
			return roi;
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10084d50
// FUNCTION: BETA10 0x10076223
MxBool LegoCharacterManager::SwitchColor(LegoROI* p_roi, LegoROI* p_targetROI)
{
	MxS32 numParts = c_numParts;
	const char* targetName = p_targetROI->GetName();

	MxS32 partIndex;
	for (partIndex = 0; partIndex < numParts; partIndex++) {
		if (!strcmp(targetName, g_actorLODs[partIndex + 1].m_name)) {
			break;
		}
	}

	assert(partIndex < numParts);

	MxBool findChild = TRUE;
	if (partIndex == c_clawlftPart) {
		partIndex = c_armlftPart;
	}
	else if (partIndex == c_clawrtPart) {
		partIndex = c_armrtPart;
	}
	else if (partIndex == c_headPart) {
		partIndex = c_infohatPart;
	}
	else if (partIndex == c_bodyPart) {
		partIndex = c_infogronPart;
	}
	else {
		findChild = FALSE;
	}

	if (!(g_actorLODs[partIndex + 1].m_flags & LegoActorLOD::c_useColor)) {
		return FALSE;
	}

	LegoActorInfo* info = GetActorInfo(p_roi->GetName());

	if (info == NULL) {
		return FALSE;
	}

	if (findChild) {
		p_targetROI = FindChildROI(p_roi, g_actorLODs[partIndex + 1].m_name);
	}

	LegoActorInfo::Part& part = info->m_parts[partIndex];

	part.m_nameIndex++;
	if (part.m_nameIndices[part.m_nameIndex] == c_indexEnd) {
		part.m_nameIndex = 0;
	}

	LegoFloat red, green, blue, alpha;
	LegoROI::GetRGBAColor(part.m_names[part.m_nameIndices[part.m_nameIndex]], red, green, blue, alpha);
	p_targetROI->SetLodColor(red, green, blue, alpha);
	return TRUE;
}

// FUNCTION: LEGO1 0x10084ec0
// FUNCTION: BETA10 0x10076436
MxBool LegoCharacterManager::SwitchVariant(LegoROI* p_roi)
{
	LegoActorInfo* info = GetActorInfo(p_roi->GetName());

	if (info == NULL) {
		return FALSE;
	}

	LegoActorInfo::Part& part = info->m_parts[c_infohatPart];

	part.m_partNameIndex++;
	MxU8 partNameIndex = part.m_partNameIndices[part.m_partNameIndex];

	if (partNameIndex == c_indexEnd) {
		part.m_partNameIndex = 0;
		partNameIndex = part.m_partNameIndices[part.m_partNameIndex];
	}

	LegoROI* childROI = FindChildROI(p_roi, g_actorLODs[c_infohatLOD].m_name);

	if (childROI != NULL) {
		char lodName[256];

		ViewLODList* lodList = GetViewLODListManager()->Lookup(part.m_partName[partNameIndex]);
		assert(lodList);
		MxS32 lodSize = lodList->Size();
		sprintf(lodName, "%s%d", p_roi->GetName(), g_infohatVariantCounter++);
		ViewLODList* dupLodList = GetViewLODListManager()->Create(lodName, lodSize);
		assert(dupLodList);

		Tgl::Renderer* renderer = VideoManager()->GetRenderer();
		LegoFloat red, green, blue, alpha;
		LegoROI::GetRGBAColor(part.m_names[part.m_nameIndices[part.m_nameIndex]], red, green, blue, alpha);

		for (MxS32 i = 0; i < lodSize; i++) {
			LegoLOD* lod = (LegoLOD*) (*lodList)[i];
			LegoLOD* clone = lod->Clone(renderer);
			clone->SetColor(red, green, blue, alpha);
			dupLodList->PushBack(clone);
		}

		lodList->Release();
		lodList = dupLodList;

		if (childROI->GetToken() >= 0) {
			VideoManager()->Get3DManager()->GetLego3DView()->GetViewManager()->RemoveROIDetailFromScene(childROI);
		}

		childROI->SetLODList(lodList);
		lodList->Release();
	}

	return TRUE;
}

// FUNCTION: LEGO1 0x10085090
// FUNCTION: BETA10 0x100766f6
MxBool LegoCharacterManager::SwitchSound(LegoROI* p_roi)
{
	MxBool result = FALSE;
	LegoActorInfo* info = GetActorInfo(p_roi);

	if (info != NULL) {
		info->m_sound++;

		if (info->m_sound >= g_maxSound) {
			info->m_sound = 0;
		}

		result = TRUE;
	}

	return result;
}

// FUNCTION: LEGO1 0x100850c0
// FUNCTION: BETA10 0x10076754
MxBool LegoCharacterManager::SwitchMove(LegoROI* p_roi)
{
	MxBool result = FALSE;
	LegoActorInfo* info = GetActorInfo(p_roi);

	if (info != NULL) {
		info->m_move++;

		if (info->m_move >= g_maxMove) {
			info->m_move = 0;
		}

		result = TRUE;
	}

	return result;
}

// FUNCTION: LEGO1 0x100850f0
// FUNCTION: BETA10 0x100767b2
MxBool LegoCharacterManager::SwitchMood(LegoROI* p_roi)
{
	MxBool result = FALSE;
	LegoActorInfo* info = GetActorInfo(p_roi);

	if (info != NULL) {
		info->m_mood++;

		if (info->m_mood > c_maxMood) {
			info->m_mood = 0;
		}

		result = TRUE;
	}

	return result;
}

// FUNCTION: LEGO1 0x10085120
// FUNCTION: BETA10 0x1007680c
MxU32 LegoCharacterManager::GetAnimationId(LegoROI* p_roi)
{
	LegoActorInfo* info = GetActorInfo(p_roi);

	if (info != NULL) {
		return info->m_move + g_characterAnimationId;
	}
	else {
		return 0;
	}
}

// FUNCTION: LEGO1 0x10085140
// FUNCTION: BETA10 0x10076855
MxU32 LegoCharacterManager::GetSoundId(LegoROI* p_roi, MxBool p_basedOnMood)
{
	LegoActorInfo* info = GetActorInfo(p_roi);

	if (p_basedOnMood) {
		return info->m_mood + g_characterSoundIdMoodOffset;
	}

	if (info != NULL) {
		return info->m_sound + g_characterSoundIdOffset;
	}
	else {
		return 0;
	}
}

// FUNCTION: LEGO1 0x10085180
// FUNCTION: BETA10 0x100768c5
MxU8 LegoCharacterManager::GetMood(LegoROI* p_roi)
{
	LegoActorInfo* info = GetActorInfo(p_roi);

	if (info != NULL) {
		return info->m_mood;
	}
	else {
		return 0;
	}
}

// FUNCTION: LEGO1 0x100851a0
// FUNCTION: BETA10 0x10076908
void LegoCharacterManager::SetCustomizeAnimFile(const char* p_value)
{
	if (g_customizeAnimFile != NULL) {
		delete[] g_customizeAnimFile;
	}

	if (p_value != NULL) {
		g_customizeAnimFile = new char[strlen(p_value) + 1];

		if (g_customizeAnimFile != NULL) {
			strcpy(g_customizeAnimFile, p_value);
		}
	}
	else {
		g_customizeAnimFile = NULL;
	}
}

// FUNCTION: LEGO1 0x10085210
// FUNCTION: BETA10 0x10076995
LegoROI* LegoCharacterManager::CreateAutoROI(const char* p_name, const char* p_lodName, MxBool p_createEntity)
{
	LegoROI* roi = NULL;

	MxMatrix mat;
	Tgl::Renderer* renderer = VideoManager()->GetRenderer();
	ViewLODListManager* lodManager = GetViewLODListManager();
	LegoTextureContainer* textureContainer = TextureContainer();
	ViewLODList* lodList = lodManager->Lookup(p_lodName);

	if (lodList == NULL || lodList->Size() == 0) {
		return NULL;
	}

	roi = new LegoROI(renderer, lodList);

	const char* name;
	char buf[20];

	if (p_name != NULL) {
		name = p_name;
	}
	else {
		sprintf(buf, "autoROI_%d", g_autoRoiCounter++);
		name = buf;
	}

	roi->SetName(name);
	lodList->Release();

	if (roi != NULL && UpdateBoundingSphereAndBox(roi) != SUCCESS) {
		delete roi;
		roi = NULL;
	}

	if (roi != NULL) {
		roi->SetVisibility(FALSE);

		LegoCharacter* character = new LegoCharacter(roi);
		char* key = new char[strlen(name) + 1];

		if (key != NULL) {
			strcpy(key, name);
			(*m_characters)[key] = character;
			VideoManager()->Get3DManager()->Add(*roi);

			if (p_createEntity && roi->GetEntity() == NULL) {
				LegoEntity* entity = new LegoEntity();

				entity->SetROI(roi, FALSE, FALSE);
				entity->SetType(LegoEntity::e_autoROI);
				entity->SetFlag(LegoEntity::c_managerOwned);
			}
		}
	}

	return roi;
}

// FUNCTION: LEGO1 0x10085870
// FUNCTION: BETA10 0x10076d64
MxResult LegoCharacterManager::UpdateBoundingSphereAndBox(LegoROI* p_roi)
{
	MxResult result = FAILURE;

	BoundingSphere boundingSphere;
	BoundingBox boundingBox;

	ViewLOD* lod = (ViewLOD*) p_roi->GetLOD(0);
	const Tgl::MeshBuilder* meshBuilder = lod->GetMeshBuilder();

	if (meshBuilder != NULL) {
		float min[3], max[3];

		min[0] = min[1] = min[2] = 88888.0;
		max[0] = max[1] = max[2] = -88888.0;
		meshBuilder->GetBoundingBox(min, max);

		float center[3];
		center[0] = (min[0] + max[0]) / 2.0f;
		center[1] = (min[1] + max[1]) / 2.0f;
		center[2] = (min[2] + max[2]) / 2.0f;
		SET3(boundingSphere.Center(), center);

		float radius[3];
		VMV3(radius, max, min);
		boundingSphere.Radius() = sqrt(NORMSQRD3(radius)) / 2.0;

		p_roi->SetBoundingSphere(boundingSphere);

		SET3(boundingBox.Min(), min);
		SET3(boundingBox.Max(), max);

		p_roi->SetBoundingBox(boundingBox);

		p_roi->WrappedUpdateWorldData();

		result = SUCCESS;
	}

	return result;
}

// FUNCTION: LEGO1 0x10085a80
// FUNCTION: BETA10 0x10077011
LegoROI* LegoCharacterManager::FUN_10085a80(const char* p_name, const char* p_lodName, MxBool p_createEntity)
{
	return CreateAutoROI(p_name, p_lodName, p_createEntity);
}

// FUNCTION: LEGO1 0x10085aa0
// FUNCTION: BETA10 0x1007703d
CustomizeAnimFileVariable::CustomizeAnimFileVariable(const char* p_key)
{
	m_key = p_key;
	m_key.ToUpperCase();
}

// FUNCTION: LEGO1 0x10085b50
// FUNCTION: BETA10 0x100770c8
void CustomizeAnimFileVariable::SetValue(const char* p_value)
{
	// STRING: LEGO1 0x100fc4f4
	if (strcmp(m_key.GetData(), "CUSTOMIZE_ANIM_FILE") == 0) {
		CharacterManager()->SetCustomizeAnimFile(p_value);
		PlantManager()->SetCustomizeAnimFile(p_value);
		BuildingManager()->SetCustomizeAnimFile(p_value);
	}
}
