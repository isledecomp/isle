#include "legoplantmanager.h"

#include "3dmanager/lego3dmanager.h"
#include "legocharactermanager.h"
#include "legoentity.h"
#include "legoplants.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "misc/legostorage.h"
#include "mxdebug.h"
#include "mxmisc.h"
#include "mxticklemanager.h"
#include "mxtimer.h"
#include "scripts.h"
#include "sndanim_actions.h"
#include "viewmanager/viewmanager.h"

#include <assert.h>
#include <stdio.h>
#include <vec.h>
// Declaration-record carrier (dial campaign): samples this translation
// unit's accumulated declaration state. Neutral stand-in.
class RkD0 {};
class RkD1 {};
class RkD2 {};
class RkD3 {};
class RkD4 {};
// Declaration-record carrier (dial campaign): samples this translation
// unit's accumulated declaration state. Neutral stand-in.
class RkF0;
class RkF1;
class RkF2;
class RkF3;
class RkF4;
class RkF5;
class RkF6;
class RkF7;

DECOMP_SIZE_ASSERT(LegoPlantManager, 0x2c)
DECOMP_SIZE_ASSERT(LegoPlantManager::AnimEntry, 0x0c)
DECOMP_SIZE_ASSERT(LegoPlantInfo, 0x54)

// GLOBAL: LEGO1 0x100f1660
const char* g_plantLodNames[4][5] = {
	{"flwrwht", "flwrblk", "flwryel", "flwrred", "flwrgrn"},
	{"treewht", "treeblk", "treeyel", "treered", "tree"},
	{"bushwht", "bushblk", "bushyel", "bushred", "bush"},
	{"palmwht", "palmblk", "palmyel", "palmred", "palm"}
};

// GLOBAL: LEGO1 0x100f16b0
float g_heightPerCount[] = {0.1f, 0.7f, 0.5f, 0.9f};

// GLOBAL: LEGO1 0x100f16c0
MxU8 g_counters[] = {1, 2, 2, 3};

// GLOBAL: LEGO1 0x100f16c8
LegoPlantInfo g_plantInfoInit[81] = {
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "edg01_20",
	 1,
	 -70.0f,
	 8.0f,
	 -8.40763f,
	 NULL,
	 -73.75f,
	 8.0f,
	 -8.4375f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "edg00_20",
	 3,
	 -15.45f,
	 0.0f,
	 -41.32f,
	 NULL,
	 -16.8125f,
	 0.0f,
	 -41.2f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "edg01_24",
	 1,
	 -69.7176f,
	 7.0f,
	 -25.25f,
	 NULL,
	 -71.0f,
	 7.0f,
	 -25.0f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "edg02_27",
	 1,
	 82.75f,
	 4.0f,
	 29.24163f,
	 NULL,
	 82.6125f,
	 4.0f,
	 27.625f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "int18",
	 3,
	 28.15f,
	 2.0f,
	 29.27804f,
	 NULL,
	 29.8125f,
	 2.0f,
	 27.6875f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "int48",
	 0,
	 85.16238f,
	 9.0f,
	 -0.83761f,
	 NULL,
	 86.125f,
	 8.80447f,
	 0.3125f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "int18",
	 3,
	 24.31819f,
	 2.0f,
	 29.04404f,
	 NULL,
	 22.8125f,
	 2.0f,
	 27.6875f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "int56",
	 4,
	 -64.125f,
	 14.0f,
	 27.5f,
	 NULL,
	 -61.6875f,
	 14.0f,
	 28.0f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "int67",
	 3,
	 -23.3197f,
	 1.0f,
	 29.00803f,
	 NULL,
	 -21.9375f,
	 1.0f,
	 27.6875f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "edg02_79",
	 3,
	 9.15f,
	 0.0f,
	 -18.1854f,
	 NULL,
	 9.15f,
	 0.0f,
	 -19.9375f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "edg02_79",
	 1,
	 9.15f,
	 0.0f,
	 -14.5695f,
	 NULL,
	 9.15f,
	 0.0f,
	 -12.9375f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "edg00_151",
	 1,
	 -75.7186f,
	 4.0f,
	 44.60529f,
	 NULL,
	 -74.9375f,
	 4.0f,
	 44.3875f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "int53",
	 6,
	 -22.375f,
	 0.0f,
	 -81.875f,
	 NULL,
	 -21.625f,
	 0.0f,
	 -83.0f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg01_47",
	 1,
	 42.8125f,
	 0.0f,
	 -48.125f,
	 NULL,
	 47.75f,
	 -0.299f,
	 -58.125f,
	 0.6751f,
	 -0.1071f,
	 0.7299f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg00_155",
	 1,
	 -39.0f,
	 0.0f,
	 40.8125f,
	 NULL,
	 -41.0f,
	 0.0f,
	 39.5f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg03_05",
	 3,
	 -35.125f,
	 0.0f,
	 3.875f,
	 NULL,
	 -35.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_bush,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg00_128",
	 3,
	 -59.3624f,
	 14.0f,
	 22.86249f,
	 NULL,
	 -58.375f,
	 14.0f,
	 21.98749f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_bush,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "int48",
	 4,
	 87.9875f,
	 9.0f,
	 -1.125f,
	 NULL,
	 87.3f,
	 8.609336f,
	 1.125f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_bush,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg01_18",
	 1,
	 -69.6875f,
	 8.0f,
	 -3.5f,
	 NULL,
	 -73.8f,
	 8.0f,
	 -5.3f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_bush,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg02_85",
	 1,
	 -26.45f,
	 0.0f,
	 -48.5f,
	 NULL,
	 -25.45f,
	 0.0f,
	 -46.5f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_tree,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg00_123",
	 3,
	 -60.625f,
	 14.0f,
	 22.9375f,
	 NULL,
	 -60.0f,
	 14.0f,
	 24.0f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_tree,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg00_131",
	 1,
	 -63.7755f,
	 14.0f,
	 26.70394f,
	 NULL,
	 -65.0f,
	 14.0f,
	 26.0f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_tree,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg02_61",
	 3,
	 70.1875f,
	 1.0f,
	 -78.3125f,
	 NULL,
	 72.6875f,
	 1.0f,
	 -80.3125f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_tree,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg01_33",
	 1,
	 -64.1875f,
	 7.0f,
	 -45.25f,
	 NULL,
	 -64.1875f,
	 7.0f,
	 -43.4375f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg02_59",
	 1,
	 -47.8124f,
	 1.8634f,
	 -58.2624f,
	 NULL,
	 -47.8124f,
	 1.875f,
	 -60.2624f,
	 0.174f,
	 0.0f,
	 0.985f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "edg02_32",
	 1,
	 25.5f,
	 0.0f,
	 9.0f,
	 NULL,
	 22.8125f,
	 0.0f,
	 9.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "int25",
	 0,
	 27.1875f,
	 0.0f,
	 -16.3125f,
	 NULL,
	 29.8125f,
	 0.0f,
	 -14.3125f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "edg02_01",
	 1,
	 -19.625f,
	 0.0f,
	 -17.9375f,
	 NULL,
	 -19.625f,
	 0.0f,
	 -20.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "edg00_95",
	 3,
	 34.125f,
	 0.0f,
	 3.5125f,
	 NULL,
	 32.9375f,
	 0.0f,
	 2.95f,
	 -1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "int25",
	 1,
	 25.6875f,
	 0.0f,
	 -16.4375f,
	 NULL,
	 22.8125f,
	 0.0f,
	 -12.9375f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "int26",
	 1,
	 24.25f,
	 0.0f,
	 -44.5f,
	 NULL,
	 22.8125f,
	 0.0f,
	 -43.0625f,
	 0.707f,
	 0.0f,
	 0.707f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "int26",
	 6,
	 28.25f,
	 0.0f,
	 -47.3125f,
	 NULL,
	 29.8125f,
	 0.0f,
	 -45.875f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "int10",
	 1,
	 -69.125f,
	 7.0f,
	 -29.125f,
	 NULL,
	 -70.5625f,
	 7.0f,
	 -29.875f,
	 0.707f,
	 0.0f,
	 0.707f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "edg02_61",
	 3,
	 70.75f,
	 1.0f,
	 -76.5625f,
	 NULL,
	 73.5f,
	 1.0f,
	 -78.25f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "int04",
	 5,
	 -94.4f,
	 4.0f,
	 -15.3125f,
	 NULL,
	 -94.875f,
	 4.0f,
	 -13.3125f,
	 0.707f,
	 0.0f,
	 0.707f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "edg02_79",
	 1,
	 9.15f,
	 0.0f,
	 -14.5695f,
	 NULL,
	 9.15f,
	 0.0f,
	 -11.5625f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "edg01_58",
	 3,
	 66.2125f,
	 0.0f,
	 -17.5625f,
	 NULL,
	 65.33261f,
	 0.11868f,
	 -19.8125f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "int34",
	 4,
	 0.375f,
	 0.0f,
	 -44.8875f,
	 NULL,
	 -1.3125f,
	 0.0f,
	 -43.075f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "edg02_32",
	 1,
	 25.5f,
	 0.0f,
	 9.8f,
	 NULL,
	 22.8125f,
	 0.0f,
	 10.4875f,
	 0.707f,
	 0.0f,
	 0.707f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "int22",
	 6,
	 28.92499f,
	 0.0f,
	 6.45f,
	 NULL,
	 29.8f,
	 0.0f,
	 8.0125f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "edg02_28",
	 1,
	 85.5f,
	 4.0f,
	 22.25f,
	 NULL,
	 82.5625f,
	 4.0f,
	 26.25f,
	 0.707f,
	 0.0f,
	 0.707f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "edg00_176",
	 0,
	 73.875f,
	 1.0f,
	 -82.9375f,
	 NULL,
	 74.75f,
	 1.0f,
	 -81.25f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "edg02_35",
	 3,
	 26.25f,
	 0.0f,
	 -12.45f,
	 NULL,
	 22.8125f,
	 0.0f,
	 -11.575f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "edg02_79",
	 3,
	 9.15f,
	 0.0f,
	 -18.1854f,
	 NULL,
	 9.0875f,
	 0.0f,
	 -21.3125f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "edg02_01",
	 3,
	 -19.75f,
	 0.0f,
	 -15.3125f,
	 NULL,
	 -19.75f,
	 0.0f,
	 -12.875f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "edg01_56",
	 3,
	 72.8125f,
	 0.0f,
	 -25.9375f,
	 NULL,
	 70.6875f,
	 0.0f,
	 -26.5625f,
	 -0.9848f,
	 0.0f,
	 1.1736f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "int67",
	 0,
	 -26.9375f,
	 1.0f,
	 29.075f,
	 NULL,
	 -28.9375f,
	 1.0f,
	 27.7f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "int51",
	 3,
	 -2.125f,
	 0.0f,
	 -17.6875f,
	 NULL,
	 -3.25f,
	 0.0f,
	 -19.75f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "edg02_57",
	 1,
	 -23.875f,
	 0.0f,
	 -54.9375f,
	 NULL,
	 -25.1875f,
	 0.0f,
	 -52.625f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "int04",
	 5,
	 -94.0f,
	 4.0f,
	 -15.3125f,
	 NULL,
	 -95.9375f,
	 4.0f,
	 -14.25f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg02_36",
	 3,
	 18.6875f,
	 0.0f,
	 -14.6375f,
	 NULL,
	 18.75f,
	 0.0f,
	 -10.95f,
	 0.707f,
	 0.0f,
	 0.707f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg02_30",
	 1,
	 25.1375f,
	 2.0f,
	 25.5f,
	 NULL,
	 21.8875f,
	 1.84509f,
	 25.5f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg02_30",
	 3,
	 27.45f,
	 2.0f,
	 25.5f,
	 NULL,
	 30.95f,
	 2.0f,
	 25.5f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg00_78",
	 1,
	 64.35749f,
	 0.0f,
	 10.95579f,
	 NULL,
	 66.67f,
	 0.256506f,
	 10.95579f,
	 0.0f,
	 0.0f,
	 -1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg02_38",
	 1,
	 9.625f,
	 0.0f,
	 -45.375f,
	 NULL,
	 9.625f,
	 0.0f,
	 -40.0f,
	 0.5f,
	 0.0f,
	 0.866f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg00_76",
	 3,
	 65.0f,
	 0.0f,
	 7.0125f,
	 NULL,
	 62.0f,
	 0.0f,
	 2.825f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg02_35",
	 1,
	 27.4375f,
	 0.0f,
	 -8.125f,
	 NULL,
	 33.375f,
	 0.0f,
	 -8.125f,
	 0.342f,
	 0.0f,
	 0.94f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg02_23",
	 3,
	 18.825f,
	 1.7575f,
	 30.125f,
	 NULL,
	 18.825f,
	 1.0f,
	 25.5f,
	 0.707f,
	 0.0f,
	 0.707f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg00_130",
	 1,
	 -67.5f,
	 14.0f,
	 23.25f,
	 NULL,
	 -63.6875f,
	 14.0f,
	 21.4375f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg01_13",
	 3,
	 -92.75f,
	 4.0f,
	 2.5f,
	 NULL,
	 -95.625f,
	 4.0f,
	 2.5f,
	 0.707f,
	 0.0f,
	 0.707f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg01_09",
	 1,
	 -80.0f,
	 4.0f,
	 -52.6875f,
	 NULL,
	 -80.0f,
	 4.0f,
	 -55.875f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg02_53",
	 1,
	 -8.75f,
	 0.0f,
	 -45.5f,
	 NULL,
	 -8.75f,
	 0.0f,
	 -40.75f,
	 0.707f,
	 0.0f,
	 0.707f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg02_37",
	 3,
	 27.5f,
	 0.0f,
	 -32.0f,
	 NULL,
	 35.625f,
	 0.0f,
	 -32.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg00_127",
	 1,
	 -62.25f,
	 14.0f,
	 26.6875f,
	 NULL,
	 -61.0f,
	 14.0f,
	 26.8125f,
	 0.707f,
	 0.0f,
	 0.707f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg02_01",
	 1,
	 -16.0f,
	 0.0f,
	 -18.575f,
	 NULL,
	 -16.0f,
	 0.0f,
	 -22.45f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg01_17",
	 1,
	 -76.4325f,
	 8.0f,
	 5.875f,
	 NULL,
	 -78.0f,
	 8.0f,
	 2.375f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg01_38",
	 1,
	 -77.1875f,
	 7.0f,
	 -36.9375f,
	 NULL,
	 -72.0f,
	 7.0f,
	 -36.5f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg02_82",
	 1,
	 97.0f,
	 0.0f,
	 -42.125f,
	 NULL,
	 98.1875f,
	 0.0f,
	 -41.3125f,
	 0.707f,
	 0.0f,
	 0.707f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_palm,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg00_15",
	 3,
	 96.5f,
	 4.0f,
	 18.75f,
	 NULL,
	 97.5f,
	 4.0f,
	 18.25f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_tree,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "",
	 1,
	 0.0f,
	 0.0f,
	 0.0f,
	 NULL,
	 -67.5f,
	 14.0f,
	 23.25f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_tree,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "int48",
	 4,
	 87.9875f,
	 9.0f,
	 -1.125f,
	 NULL,
	 88.75f,
	 8.75f,
	 0.875f,
	 0.259f,
	 0.0f,
	 0.966f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_tree,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg01_01",
	 3,
	 -48.625f,
	 7.0f,
	 -23.1875f,
	 NULL,
	 -50.4375f,
	 7.0f,
	 -25.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_tree,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg01_01",
	 0,
	 -48.625f,
	 7.0f,
	 -23.1875f,
	 NULL,
	 -49.125f,
	 7.0f,
	 -25.8f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_tree,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg01_01",
	 3,
	 -48.625f,
	 7.0f,
	 -23.1875f,
	 NULL,
	 -51.25f,
	 7.0f,
	 -23.75f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_act1 | LegoPlantInfo::c_act2 | LegoPlantInfo::c_act3,
	 LegoPlantInfo::e_tree,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_green,
	 -1,
	 -1,
	 "edg00_129",
	 1,
	 -56.75f,
	 14.0f,
	 26.625f,
	 NULL,
	 -58.0f,
	 14.0f,
	 26.75f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_imain,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "",
	 1,
	 0.0f,
	 0.0f,
	 0.0f,
	 NULL,
	 -4.33403f,
	 -2.18029f,
	 -1.53595f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_imain,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "",
	 1,
	 0.0f,
	 0.0f,
	 0.0f,
	 NULL,
	 1.280536f,
	 -2.18024f,
	 -1.57823f,
	 0.0f,
	 0.0f,
	 -1.0f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_ielev,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "",
	 1,
	 0.0f,
	 0.0f,
	 0.0f,
	 NULL,
	 -1.52465f,
	 -0.52473f,
	 -11.1617f,
	 -0.0175f,
	 0.0f,
	 -0.9998f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_ielev,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "",
	 1,
	 0.0f,
	 0.0f,
	 0.0f,
	 NULL,
	 1.439563f,
	 -0.52554f,
	 -11.1846f,
	 0.866f,
	 0.0f,
	 -0.5f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_iisle,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_yellow,
	 -1,
	 -1,
	 "",
	 1,
	 0.0f,
	 0.0f,
	 0.0f,
	 NULL,
	 -1.82829f,
	 -0.52554f,
	 -11.7741f,
	 0.866f,
	 0.0f,
	 -0.5f,
	 0.0f,
	 1.0f,
	 0.0f},
	{NULL,
	 LegoPlantInfo::c_iisle,
	 LegoPlantInfo::e_flower,
	 3,
	 0,
	 1,
	 LegoPlantInfo::e_red,
	 -1,
	 -1,
	 "",
	 1,
	 0.0f,
	 0.0f,
	 0.0f,
	 NULL,
	 1.801479f,
	 -0.52473f,
	 -11.75f,
	 -0.0175f,
	 0.0f,
	 -0.9998f,
	 0.0f,
	 1.0f,
	 0.0f}
};

// GLOBAL: LEGO1 0x100f315c
MxU32 LegoPlantManager::g_maxSound = 8;

// GLOBAL: LEGO1 0x100f3160
MxU32 g_plantSoundIdOffset = 56;

// GLOBAL: LEGO1 0x100f3164
MxU32 g_plantSoundIdMoodOffset = 66;

// GLOBAL: LEGO1 0x100f3168
MxS32 LegoPlantManager::g_maxMove[4] = {3, 3, 3, 3};

// GLOBAL: LEGO1 0x100f3178
MxU32 g_plantAnimationId[4] = {30, 33, 36, 39};

// GLOBAL: LEGO1 0x100f3188
// GLOBAL: BETA10 0x101f4e70
char* LegoPlantManager::g_customizeAnimFile = NULL;

// GLOBAL: LEGO1 0x10103180
// GLOBAL: BETA10 0x1020f4c0
LegoPlantInfo g_plantInfo[81];

// FUNCTION: LEGO1 0x10026220
// FUNCTION: BETA10 0x100c4f90
LegoPlantManager::LegoPlantManager()
{
	// Note that Init() is inlined in BETA10 and the class did not inherit from MxCore,
	// so the BETA10 match is much better on Init().
	Init();
}

// FUNCTION: LEGO1 0x100262c0
// FUNCTION: BETA10 0x100c5002
LegoPlantManager::~LegoPlantManager()
{
	delete[] g_customizeAnimFile;
}

// // FUNCTION: BETA10 0x100c4f90 -- see the constructor
// FUNCTION: LEGO1 0x10026330
void LegoPlantManager::Init()
{
	for (MxS32 i = 0; i < sizeOfArray(g_plantInfo); i++) {
		g_plantInfo[i] = g_plantInfoInit[i];
	}

	m_worldId = LegoOmni::e_undefined;
	m_boundariesDetermined = FALSE;
	m_numEntries = 0;
}

// FUNCTION: LEGO1 0x10026360
// FUNCTION: BETA10 0x100c5032
void LegoPlantManager::LoadWorldInfo(LegoOmni::World p_worldId)
{
	m_worldId = p_worldId;
	LegoWorld* world = CurrentWorld();

	for (MxS32 i = 0; i < sizeOfArray(g_plantInfo); i++) {
		CreatePlant(i, world, p_worldId);
	}

	m_boundariesDetermined = FALSE;
}

// FUNCTION: LEGO1 0x100263a0
// FUNCTION: BETA10 0x100c5093
void LegoPlantManager::Reset(LegoOmni::World p_worldId)
{
	MxU32 i;
	DeleteObjects(g_sndAnimScript, SndanimScript::c_AnimC1, SndanimScript::c_AnimBld18);

	for (i = 0; i < m_numEntries; i++) {
		delete m_entries[i];
	}

	m_numEntries = 0;

	for (i = 0; i < sizeOfArray(g_plantInfo); i++) {
		RemovePlant(i, p_worldId);
	}

	m_worldId = LegoOmni::e_undefined;
	m_boundariesDetermined = FALSE;
}

// FUNCTION: LEGO1 0x10026410
// FUNCTION: BETA10 0x100c50e9
MxResult LegoPlantManager::DetermineBoundaries()
{
	// similar to LegoBuildingManager::FUN_10030630()

	LegoWorld* world = CurrentWorld();

	if (world == NULL) {
		return FAILURE;
	}

	for (MxS32 i = 0; i < sizeOfArray(g_plantInfo); i++) {
		if (g_plantInfo[i].m_entity != NULL && g_plantInfo[i].m_name != NULL) {
			g_plantInfo[i].m_boundary = world->FindPathBoundary(g_plantInfo[i].m_name);

			if (g_plantInfo[i].m_boundary != NULL) {
				Mx3DPointFloat position(g_plantInfo[i].m_x, g_plantInfo[i].m_y, g_plantInfo[i].m_z);
				LegoPathBoundary* boundary = g_plantInfo[i].m_boundary;

				for (MxS32 j = 0; j < boundary->GetNumEdges(); j++) {
					Mx4DPointFloat* normal = boundary->GetEdgeNormal(j);

					if (position.Dot(*normal, position) + (*normal).index_operator(3) < -0.001) {
						MxTrace(
							"Plant %d shot location (%g, %g, %g) is not in boundary %s.\n",
							i,
							position[0],
							position[1],
							position[2],
							boundary->GetName()
						);
						g_plantInfo[i].m_boundary = NULL;
						break;
					}
				}

				if (g_plantInfo[i].m_boundary != NULL) {
					Mx4DPointFloat& unk0x14 = *g_plantInfo[i].m_boundary->GetUp();

					if (position.Dot(position, unk0x14) + unk0x14.index_operator(3) > 0.001 ||
						position.Dot(position, unk0x14) + unk0x14.index_operator(3) < -0.001) {

						g_plantInfo[i].m_y =
							-((position[0] * unk0x14.index_operator(0) + unk0x14.index_operator(3) +
							   position[2] * unk0x14.index_operator(2)) /
							  unk0x14.index_operator(1));

						MxTrace(
							"Plant %d shot location (%g, %g, %g) is not on plane of boundary %s...adjusting to (%g, "
							"%g, "
							"%g)\n",
							i,
							position[0],
							position[1],
							position[2],
							g_plantInfo[i].m_boundary->GetName(),
							position[0],
							g_plantInfo[i].m_y,
							position[2]
						);
					}
				}
			}
			else {
				MxTrace("Plant %d is in boundary %s that does not exist.\n", i, g_plantInfo[i].m_name);
			}
		}
	}

	m_boundariesDetermined = TRUE;
	return SUCCESS;
}

// Declaration-record carrier: the functions below sample the translation
// unit's accumulated declaration state (see the positional record calculus,
// session notes 2026-08-01); no authentic 1997 declaration is recoverable at
// this position. Neutral stand-in pending better evidence.
class MxUnkRecordRH;
class MxUnkRecordRI;
class MxUnkRecordRJ;
class MxUnkRecordRK;

// FUNCTION: LEGO1 0x10026570
// FUNCTION: BETA10 0x100c55e0
LegoPlantInfo* LegoPlantManager::GetInfoArray(MxS32& p_length)
{
	if (!m_boundariesDetermined) {
		DetermineBoundaries();
	}

	p_length = sizeOfArray(g_plantInfo);
	return g_plantInfo;
}

// FUNCTION: LEGO1 0x10026590
// FUNCTION: BETA10 0x100c561e
LegoEntity* LegoPlantManager::CreatePlant(MxS32 p_index, LegoWorld* p_world, LegoOmni::World p_worldId)
{
	LegoEntity* entity = NULL;

	if (p_index < sizeOfArray(g_plantInfo)) {
		assert(p_worldId < 32);
		MxU32 world = 1 << (MxU8) p_worldId;

		if (g_plantInfo[p_index].m_worlds & world && g_plantInfo[p_index].m_counter != 0) {
			if (g_plantInfo[p_index].m_entity == NULL) {
				char name[256];
				char lodName[256];

				sprintf(name, "plant%d", p_index);
				sprintf(lodName, "%s", g_plantLodNames[g_plantInfo[p_index].m_variant][g_plantInfo[p_index].m_color]);

				LegoROI* roi = CharacterManager()->CreateAutoROI(name, lodName, TRUE);
				roi->SetVisibility(TRUE);

				entity = roi->GetEntity();
				assert(entity);
				entity->SetLocation(
					g_plantInfo[p_index].m_position,
					g_plantInfo[p_index].m_direction,
					g_plantInfo[p_index].m_up,
					FALSE
				);
				entity->SetType(LegoEntity::e_plant);
				g_plantInfo[p_index].m_entity = entity;
			}
			else {
				entity = g_plantInfo[p_index].m_entity;
			}
		}
	}

	return entity;
}

// FUNCTION: LEGO1 0x100266c0
// FUNCTION: BETA10 0x100c5859
void LegoPlantManager::RemovePlant(MxS32 p_index, LegoOmni::World p_worldId)
{
	if (p_index < sizeOfArray(g_plantInfo)) {
		assert(p_worldId < 32);
		MxU32 world = 1 << (MxU8) p_worldId;

		if (g_plantInfo[p_index].m_worlds & world && g_plantInfo[p_index].m_entity != NULL) {
			CharacterManager()->ReleaseAutoROI(g_plantInfo[p_index].m_entity->GetROI());
			g_plantInfo[p_index].m_entity = NULL;
		}
	}
}

// FUNCTION: LEGO1 0x10026720
// FUNCTION: BETA10 0x100c5918
MxResult LegoPlantManager::Write(LegoStorage* p_storage)
{
	MxResult result = FAILURE;

	for (MxS32 i = 0; i < sizeOfArray(g_plantInfo); i++) {
		LegoPlantInfo* info = &g_plantInfo[i];

		if (p_storage->Write(&info->m_variant, sizeof(info->m_variant)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_sound, sizeof(info->m_sound)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_move, sizeof(info->m_move)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_mood, sizeof(info->m_mood)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_color, sizeof(info->m_color)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Write(&info->m_initialCounter, sizeof(info->m_initialCounter)) != SUCCESS) {
			goto done;
		}
	}

	result = SUCCESS;

done:
	return result;
}

// FUNCTION: LEGO1 0x100267b0
// FUNCTION: BETA10 0x100c5a76
MxResult LegoPlantManager::Read(LegoStorage* p_storage)
{
	MxResult result = FAILURE;

	for (MxS32 i = 0; i < sizeOfArray(g_plantInfo); i++) {
		LegoPlantInfo* info = &g_plantInfo[i];

		if (p_storage->Read(&info->m_variant, sizeof(MxU8)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_sound, sizeof(MxU32)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_move, sizeof(MxU32)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_mood, sizeof(MxU8)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_color, sizeof(MxU8)) != SUCCESS) {
			goto done;
		}
		if (p_storage->Read(&info->m_counter, sizeof(MxS8)) != SUCCESS) {
			goto done;
		}

		info->m_initialCounter = info->m_counter;
		AdjustHeight(i);
	}

	result = SUCCESS;

done:
	return result;
}

// FUNCTION: LEGO1 0x10026860
// FUNCTION: BETA10 0x100c5be0
void LegoPlantManager::AdjustHeight(MxS32 p_index)
{
	MxS8 counter = g_plantInfo[p_index].m_counter;
	MxU8 variant = g_plantInfo[p_index].m_variant;

	if (counter >= 0) {
		float value = g_counters[variant] - counter;
		g_plantInfo[p_index].m_position[1] = g_plantInfoInit[p_index].m_position[1] - value * g_heightPerCount[variant];
	}
	else {
		g_plantInfo[p_index].m_position[1] = g_plantInfoInit[p_index].m_position[1];
	}
}

// FUNCTION: LEGO1 0x100268d0
// FUNCTION: BETA10 0x100c5c7a
MxS32 LegoPlantManager::GetNumPlants()
{
	return sizeOfArray(g_plantInfo);
}

// FUNCTION: LEGO1 0x100268e0
// FUNCTION: BETA10 0x100c5c95
LegoPlantInfo* LegoPlantManager::GetInfo(LegoEntity* p_entity)
{
	MxS32 i;

	for (i = 0; i < sizeOfArray(g_plantInfo); i++) {
		if (g_plantInfo[i].m_entity == p_entity) {
			break;
		}
	}

	if (i < sizeOfArray(g_plantInfo)) {
		return &g_plantInfo[i];
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10026920
// FUNCTION: BETA10 0x100c5dc9
MxBool LegoPlantManager::SwitchColor(LegoEntity* p_entity)
{
	LegoPlantInfo* info = GetInfo(p_entity);

	if (info == NULL) {
		return FALSE;
	}

	LegoROI* roi = p_entity->GetROI();
	info->m_color++;

	if (info->m_color > LegoPlantInfo::e_green) {
		info->m_color = LegoPlantInfo::e_white;
	}

	ViewLODList* lodList = GetViewLODListManager()->Lookup(g_plantLodNames[info->m_variant][info->m_color]);
	assert(lodList);

	if (roi->GetToken() >= 0) {
		VideoManager()->Get3DManager()->GetLego3DView()->GetViewManager()->RemoveROIDetailFromScene(roi);
	}

	roi->SetLODList(lodList);
	lodList->Release();
	CharacterManager()->UpdateBoundingSphereAndBox(roi);
	return TRUE;
}

// FUNCTION: LEGO1 0x100269e0
// FUNCTION: BETA10 0x100c5ee2
MxBool LegoPlantManager::SwitchVariant(LegoEntity* p_entity)
{
	LegoPlantInfo* info = GetInfo(p_entity);

	if (info == NULL || info->m_counter != -1) {
		return FALSE;
	}

	LegoROI* roi = p_entity->GetROI();
	info->m_variant++;

	if (info->m_variant > LegoPlantInfo::e_palm) {
		info->m_variant = LegoPlantInfo::e_flower;
	}

	ViewLODList* lodList = GetViewLODListManager()->Lookup(g_plantLodNames[info->m_variant][info->m_color]);
	assert(lodList);

	if (roi->GetToken() >= 0) {
		VideoManager()->Get3DManager()->GetLego3DView()->GetViewManager()->RemoveROIDetailFromScene(roi);
	}

	roi->SetLODList(lodList);
	lodList->Release();
	CharacterManager()->UpdateBoundingSphereAndBox(roi);

	if (info->m_move != 0 && info->m_move >= g_maxMove[info->m_variant]) {
		info->m_move = g_maxMove[info->m_variant] - 1;
	}

	return TRUE;
}

// FUNCTION: LEGO1 0x10026ad0
// FUNCTION: BETA10 0x100c6049
MxBool LegoPlantManager::SwitchSound(LegoEntity* p_entity)
{
	MxBool result = FALSE;
	LegoPlantInfo* info = GetInfo(p_entity);

	if (info != NULL) {
		info->m_sound++;

		if (info->m_sound >= g_maxSound) {
			info->m_sound = 0;
		}

		result = TRUE;
	}

	return result;
}

// FUNCTION: LEGO1 0x10026b00
// FUNCTION: BETA10 0x100c60a7
MxBool LegoPlantManager::SwitchMove(LegoEntity* p_entity)
{
	MxBool result = FALSE;
	LegoPlantInfo* info = GetInfo(p_entity);

	if (info != NULL) {
		info->m_move++;

		if (info->m_move >= g_maxMove[info->m_variant]) {
			info->m_move = 0;
		}

		result = TRUE;
	}

	return result;
}

// FUNCTION: LEGO1 0x10026b40
// FUNCTION: BETA10 0x100c610e
MxBool LegoPlantManager::SwitchMood(LegoEntity* p_entity)
{
	MxBool result = FALSE;
	LegoPlantInfo* info = GetInfo(p_entity);

	if (info != NULL) {
		info->m_mood++;

		if (info->m_mood > 3) {
			info->m_mood = 0;
		}

		result = TRUE;
	}

	return result;
}

// FUNCTION: LEGO1 0x10026b70
// FUNCTION: BETA10 0x100c6168
MxU32 LegoPlantManager::GetAnimationId(LegoEntity* p_entity)
{
	LegoPlantInfo* info = GetInfo(p_entity);

	if (info != NULL) {
		return g_plantAnimationId[info->m_variant] + info->m_move;
	}

	return 0;
}

// FUNCTION: LEGO1 0x10026ba0
// FUNCTION: BETA10 0x100c61ba
MxU32 LegoPlantManager::GetSoundId(LegoEntity* p_entity, MxBool p_basedOnMood)
{
	LegoPlantInfo* info = GetInfo(p_entity);

	if (p_basedOnMood) {
		return (info->m_mood & 1) + g_plantSoundIdMoodOffset;
	}

	if (info != NULL) {
		return info->m_sound + g_plantSoundIdOffset;
	}

	return 0;
}

// FUNCTION: LEGO1 0x10026be0
// FUNCTION: BETA10 0x100c62bc
void LegoPlantManager::SetCustomizeAnimFile(const char* p_value)
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

// FUNCTION: LEGO1 0x10026c50
// FUNCTION: BETA10 0x100c6349
MxBool LegoPlantManager::DecrementCounter(LegoEntity* p_entity)
{
	LegoPlantInfo* info = GetInfo(p_entity);

	if (info == NULL) {
		return FALSE;
	}

	return DecrementCounter(info - g_plantInfo);
}

// FUNCTION: LEGO1 0x10026c80
// FUNCTION: BETA10 0x100c63eb
MxBool LegoPlantManager::DecrementCounter(MxS32 p_index)
{
	if (p_index >= sizeOfArray(g_plantInfo)) {
		return FALSE;
	}

	LegoPlantInfo* info = &g_plantInfo[p_index];

	if (info == NULL) {
		return FALSE;
	}

	MxBool result = TRUE;

	if (info->m_counter < 0) {
		info->m_counter = g_counters[info->m_variant];
	}

	if (info->m_counter > 0) {
		LegoROI* roi = info->m_entity->GetROI();
		info->m_counter--;

		if (info->m_counter == 1) {
			info->m_counter = 0;
		}

		if (info->m_counter == 0) {
			roi->SetVisibility(FALSE);
		}
		else {
			AdjustHeight(info - g_plantInfo);
			info->m_entity->SetLocation(info->m_position, info->m_direction, info->m_up, FALSE);
		}
	}
	else {
		result = FALSE;
	}

	return result;
}

// FUNCTION: LEGO1 0x10026d70
void LegoPlantManager::ScheduleAnimation(LegoEntity* p_entity, MxLong p_length)
{
	m_world = CurrentWorld();

	if (m_numEntries == 0) {
		TickleManager()->RegisterClient(this, 50);
	}

	AnimEntry* entry = m_entries[m_numEntries] = new AnimEntry;
	m_numEntries++;

	entry->m_entity = p_entity;
	entry->m_roi = p_entity->GetROI();

	MxLong time = Timer()->GetTime();
	time += p_length;
	entry->m_time = time + 1000;

	AdjustCounter(p_entity, -1);
}

// FUNCTION: LEGO1 0x10026e00
MxResult LegoPlantManager::Tickle()
{
	MxLong time = Timer()->GetTime();

	if (m_numEntries != 0) {
		for (MxS32 i = 0; i < m_numEntries; i++) {
			AnimEntry** ppEntry = &m_entries[i];
			AnimEntry* entry = *ppEntry;

			if (m_world != CurrentWorld() || !entry->m_entity) {
				delete entry;
				m_numEntries--;

				if (m_numEntries != i) {
					m_entries[i] = m_entries[m_numEntries];
					m_entries[m_numEntries] = NULL;
				}

				break;
			}

			if (entry->m_time - time > 1000) {
				break;
			}

			MxMatrix local90;
			MxMatrix local48;

			MxMatrix locald8(entry->m_roi->GetLocal2World());
			Mx3DPointFloat localec(locald8[3]);

			ZEROVEC3(locald8[3]);

			locald8[1][0] = sin(((entry->m_time - time) * 2) * 0.0062832f) * 0.2;
			locald8[1][2] = sin(((entry->m_time - time) * 4) * 0.0062832f) * 0.2;
			locald8.Scale(1.03f, 0.95f, 1.03f);

			SET3(locald8[3], localec);

			entry->m_roi->SetLocal2World(locald8);
			entry->m_roi->WrappedUpdateWorldData();

			if (entry->m_time < time) {
				LegoPlantInfo* info = GetInfo(entry->m_entity);

				if (info->m_counter == 0) {
					entry->m_roi->SetVisibility(FALSE);
				}
				else {
					AdjustHeight(info - g_plantInfo);
					info->m_entity->SetLocation(info->m_position, info->m_direction, info->m_up, FALSE);
				}

				delete entry;
				m_numEntries--;

				if (m_numEntries != i) {
					i--;
					*ppEntry = m_entries[m_numEntries];
					m_entries[m_numEntries] = NULL;
				}
			}
		}
	}
	else {
		TickleManager()->UnregisterClient(this);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10027120
void LegoPlantManager::ClearCounters()
{
	LegoWorld* world = CurrentWorld();

	for (MxS32 i = 0; i < sizeOfArray(g_plantInfo); i++) {
		g_plantInfo[i].m_counter = -1;
		g_plantInfo[i].m_initialCounter = -1;
		AdjustHeight(i);

		if (g_plantInfo[i].m_entity != NULL) {
			g_plantInfo[i].m_entity->SetLocation(
				g_plantInfo[i].m_position,
				g_plantInfo[i].m_direction,
				g_plantInfo[i].m_up,
				FALSE
			);
		}
	}
}

// FUNCTION: LEGO1 0x100271b0
void LegoPlantManager::AdjustCounter(LegoEntity* p_entity, MxS32 p_adjust)
{
	LegoPlantInfo* info = GetInfo(p_entity);

	if (info != NULL) {
		if (info->m_counter < 0) {
			info->m_counter = g_counters[info->m_variant];
		}

		if (info->m_counter > 0) {
			info->m_counter += p_adjust;
			if (info->m_counter <= 1 && p_adjust < 0) {
				info->m_counter = 0;
			}
		}
	}
}

// FUNCTION: LEGO1 0x10027200
void LegoPlantManager::SetInitialCounters()
{
	for (MxU32 i = 0; i < sizeOfArray(g_plantInfo); i++) {
		g_plantInfo[i].m_initialCounter = g_plantInfo[i].m_counter;
	}
}
