#include "legonavcontroller.h"

#include "3dmanager/lego3dmanager.h"
#include "act3.h"
#include "infocenter.h"
#include "legoanimationmanager.h"
#include "legocameracontroller.h"
#include "legocharactermanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legolocations.h"
#include "legomain.h"
#include "legoplantmanager.h"
#include "legosoundmanager.h"
#include "legoutils.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "mxbackgroundaudiomanager.h"
#include "mxdebug.h"
#include "mxmisc.h"
#include "mxtimer.h"
#include "mxtransitionmanager.h"
#include "mxutilities.h"
#include "realtime/realtime.h"
#include "realtime/realtimeview.h"
#include "viewmanager/viewmanager.h"

#include <vec.h>

DECOMP_SIZE_ASSERT(LegoNavController, 0x70)
DECOMP_SIZE_ASSERT(LegoLocation, 0x60)
DECOMP_SIZE_ASSERT(LegoLocation::Boundary, 0x18)

// MSVC 4.20 didn't define a macro for this key
#ifndef VK_OEM_MINUS
#define VK_OEM_MINUS 0xBD
#endif

//////////////////////////////////////////////////////////////////////

#ifndef M_PI
#define M_PI 3.1416
#endif
#ifdef DTOR
#undef DTOR
#endif
#define DTOR(angle) ((angle) * M_PI / 180.)

//////////////////////////////////////////////////////////////////////

// GLOBAL: LEGO1 0x100f4c28
int LegoNavController::g_defdeadZone = 40;

// GLOBAL: LEGO1 0x100f4c2c
float LegoNavController::g_defzeroThreshold = 0.001f;

// GLOBAL: LEGO1 0x100f4c30
float LegoNavController::g_defmaxLinearVel = 40.0f;

// GLOBAL: LEGO1 0x100f4c34
float LegoNavController::g_defmaxRotationalVel = 20.0f;

// GLOBAL: LEGO1 0x100f4c38
float LegoNavController::g_defmaxLinearAccel = 15.0f;

// GLOBAL: LEGO1 0x100f4c3c
float LegoNavController::g_defmaxRotationalAccel = 30.0f;

// GLOBAL: LEGO1 0x100f4c40
float LegoNavController::g_defminLinearAccel = 4.0f;

// GLOBAL: LEGO1 0x100f4c44
float LegoNavController::g_defminRotationalAccel = 15.0f;

// GLOBAL: LEGO1 0x100f4c48
float LegoNavController::g_defmaxLinearDeccel = 50.0f;

// GLOBAL: LEGO1 0x100f4c4c
float LegoNavController::g_defmaxRotationalDeccel = 50.0f;

// GLOBAL: LEGO1 0x100f4c50
float LegoNavController::g_defrotSensitivity = 0.4f;

// GLOBAL: LEGO1 0x100f4c54
MxBool LegoNavController::g_defuseRotationalVel = FALSE;

// GLOBAL: LEGO1 0x100f4c58
MxBool g_isWorldActive = TRUE;

// GLOBAL: LEGO1 0x100f4c60
LegoLocation g_locations[] = {
	{0,
	 "look at origin from z=-8",
	 0.0f,
	 1.25f,
	 -8.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{1,
	 "LCAMBA1",
	 0.852546f,
	 1.25f,
	 -17.078703f,
	 0.990515f,
	 0.0f,
	 -0.137405f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"EDG02_13", 2, 0.75f, 0, 0.25f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 40},
	{2,
	 "LCAMBA2",
	 3.505301f,
	 1.25f,
	 -27.955006f,
	 -0.002102f,
	 0.0f,
	 0.999998f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"EDG02_37", 2, 0.75f, 0, 0.25f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 20},
	{3,
	 "LCAMBA3",
	 -7.472569f,
	 1.25f,
	 -16.129034f,
	 1.0f,
	 0.0f,
	 0.000926f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"EDG02_26", 0, 0.75f, 2, 0.25f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 20},
	{4,
	 "LCAMBA4",
	 38.55205f,
	 1.25f,
	 -16.129f,
	 -0.999997f,
	 0.0f,
	 0.002449f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"EDG00_146", 0, 0.5f, 2, 0.5f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 30},
	{5,
	 "LCAMCA1",
	 -36.778473f,
	 -1.996432f,
	 30.392212f,
	 0.001013f,
	 0.0f,
	 -0.999999f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"INT01", 2, 0.5f, 6, 0.5f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{6,
	 "LCAMCA2",
	 -36.774277f,
	 -1.996432f,
	 24.695135f,
	 -0.305789f,
	 0.001457f,
	 0.952098f,
	 0.000446f,
	 0.999999f,
	 -0.001387f,
	 {"EDG00_104", 0, 0.5f, 2, 0.5f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{7,
	 "LCAMCA3",
	 -36.888363f,
	 0.5625f,
	 33.169434f,
	 -0.091475f,
	 -0.001896f,
	 0.995806f,
	 -0.000173f,
	 0.999998f,
	 0.001888f,
	 {"EDG02_58", 2, 0.25f, 0, 0.75f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{8,
	 "LCAMGS1",
	 27.647768f,
	 1.25f,
	 -4.07201f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"EDG02_40", 2, 0.25f, 0, 0.25f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 70},
	{9,
	 "LCAMGS2",
	 25.153421f,
	 1.25f,
	 6.101026f,
	 0.0f,
	 0.0f,
	 -1.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"INT19", 1, 0.75f, 0, 0.75f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{10,
	 "LCAMGS3",
	 29.506308f,
	 1.25f,
	 -1.23529f,
	 -1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"EDG00_74", 0, 0.5f, 2, 0.5f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{11,
	 "LCAMHO1",
	 84.22306f,
	 4.78298f,
	 29.150623f,
	 0.779248f,
	 0.0f,
	 -0.626715f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 50},
	{12,
	 "LCAMHO2",
	 90.92687f,
	 4.78298f,
	 23.340658f,
	 -0.983254f,
	 0.0f,
	 0.182241f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{13,
	 "LCAMHO3",
	 87.66666f,
	 4.829471f,
	 20.905437f,
	 0.841755f,
	 -0.006868f,
	 0.539817f,
	 0.005781f,
	 0.999976f,
	 0.003708f,
	 {"EDG02_27", 1, 0.89f, 2, 0.89f, 0},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{14,
	 "LCAMHO4",
	 86.33506f,
	 4.814447f,
	 20.489912f,
	 0.948965f,
	 0.035898f,
	 0.313331f,
	 -0.034088f,
	 0.999355f,
	 -0.011255f,
	 {"EDG02_27", 1, 0.89f, 2, 0.89f, 0},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 100},
	{15,
	 "LCAMIC1",
	 80.11602f,
	 10.193289f,
	 -17.946644f,
	 0.664706f,
	 0.0f,
	 0.747105f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"EDG00_69", 2, 0.5f, 0, 0.5f, 0},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{16,
	 "LCAMIC2",
	 86.31804f,
	 10.193289f,
	 -11.24872f,
	 -0.936663f,
	 0.0f,
	 -0.350231f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"EDG02_66", 2, 0.5f, 0, 0.5f, 0},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{17,
	 "LCAMIC3",
	 86.82608f,
	 10.193289f,
	 -4.398705f,
	 0.466761f,
	 0.0f,
	 -0.884383f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"EDG02_68", 0, 0.5f, 2, 0.5f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 20},
	{18,
	 "LCAMJA1",
	 95.05279f,
	 1.318484f,
	 -46.451622f,
	 0.93196f,
	 0.006837f,
	 0.362497f,
	 -0.006372f,
	 0.999977f,
	 -0.002478f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 100},
	{19,
	 "LCAMJA2",
	 97.214066f,
	 1.318484f,
	 -49.035267f,
	 -0.892783f,
	 -0.012109f,
	 0.450324f,
	 -0.010811f,
	 0.999927f,
	 0.005453f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{20,
	 "LCAMJA3",
	 94.12146f,
	 1.25f,
	 -48.242523f,
	 -1.0f,
	 0.0f,
	 -0.000415f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"INT33", 1, 0.9f, 3, 0.9f, 0},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{21,
	 "LCAMJA4",
	 95.58649f,
	 1.17483f,
	 -43.42485f,
	 0.137268f,
	 0.010506f,
	 -0.990478f,
	 -0.001442f,
	 0.999945f,
	 0.010407f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{22,
	 "LCAMJA5",
	 91.586105f,
	 1.17483f,
	 -48.882996f,
	 0.702508f,
	 0.010117f,
	 0.711604f,
	 -0.007107f,
	 0.999949f,
	 -0.007199f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{23,
	 "LCAMJS1",
	 9.885858f,
	 0.154871f,
	 -54.080086f,
	 0.573803f,
	 -0.001138f,
	 -0.818993f,
	 0.000653f,
	 0.999999f,
	 -0.000932f,
	 {"INT26", 0, 0.5f, 3, 0.5f, 0},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 100},
	{24,
	 "LCAMJS2",
	 14.753909f,
	 0.125f,
	 -55.5238f,
	 -0.789437f,
	 0.0f,
	 -0.613832f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 100},
	{25,
	 "LCAMJS3",
	 12.373611f,
	 0.925977f,
	 -64.69941f,
	 0.114162f,
	 0.0f,
	 0.993462f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 100},
	{26,
	 "LCAMJS4",
	 27.136557f,
	 1.125f,
	 -41.8613f,
	 -0.187784f,
	 -0.001389f,
	 -0.982209f,
	 -0.000261f,
	 0.999999f,
	 -0.001364f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{27,
	 "LCAMMT1",
	 -63.277508f,
	 15.25f,
	 23.717245f,
	 -0.985194f,
	 0.0f,
	 0.171445f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 50},
	{28,
	 "LCAMMT2",
	 -58.28056f,
	 15.25f,
	 22.75f,
	 0.829409f,
	 0.0f,
	 -0.558642f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{29,
	 "LCAMPK1",
	 39.875f,
	 1.25f,
	 -1.0f,
	 0.587492f,
	 0.0f,
	 -0.80923f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"EDG00_83", 0, 0.9f, 2, 0.9f, 0},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 50},
	{30,
	 "LCAMPK2",
	 63.75f,
	 1.25f,
	 15.5625f,
	 -0.968277f,
	 0.0f,
	 -0.249878f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{31,
	 "LCAMPK4",
	 49.5625f,
	 1.25f,
	 0.0f,
	 -0.480011f,
	 0.0f,
	 -0.877262f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 25},
	{32,
	 "LCAMPO1",
	 -24.38507f,
	 1.25f,
	 -55.71749f,
	 -1.0f,
	 0.0f,
	 0.000066f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 20},
	{33,
	 "LCAMPO2",
	 -41.35899f,
	 1.790912f,
	 -56.728477f,
	 0.967347f,
	 0.0f,
	 0.253455f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"EDG00_191", 0, 0.5f, 2, 0.5f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{34,
	 "LCAMPS1",
	 63.1466f,
	 2.25f,
	 -81.58665f,
	 0.860361f,
	 0.0f,
	 -0.509685f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"EDG02_40", 0, 0.5f, 2, 0.5f, 0},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 25},
	{35,
	 "LCAMPS2",
	 70.99095f,
	 2.25f,
	 -87.82898f,
	 -0.746009f,
	 0.0f,
	 0.665936f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 25},
	{36,
	 "LCAMPS3",
	 73.92391f,
	 2.25f,
	 -71.65845f,
	 -0.480404f,
	 0.0f,
	 -0.877047f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"EDG02_66", 1, 0.15f, 2, 0.15f, 0},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 25},
	{37,
	 "LCAMPS4",
	 61.471172f,
	 1.829919f,
	 -74.37842f,
	 0.812146f,
	 0.0f,
	 -0.583455f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"EDG02_40", 0, 0.5f, 2, 0.5f, 0},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{38,
	 "LCAMPZ1",
	 -19.517637f,
	 1.25f,
	 -44.645412f,
	 -0.582251f,
	 0.0f,
	 0.813009f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 80},
	{39,
	 "LCAMPZ2",
	 -21.870003f,
	 1.25f,
	 -41.47747f,
	 0.310142f,
	 0.0f,
	 0.95069f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 90},
	{40,
	 "LCAMPZ3",
	 -21.860731f,
	 1.25f,
	 -41.47234f,
	 0.877738f,
	 0.0f,
	 -0.479141f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"EDG00_24", 0, 0.9f, 2, 0.9f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 100},
	{41,
	 "LCAMPZ4",
	 -20.492962f,
	 1.25f,
	 -43.951485f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{42,
	 "LCAMPZ5",
	 -11.0625f,
	 1.25f,
	 -45.75f,
	 -0.998358f,
	 0.0f,
	 -0.057283f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 50},
	{43,
	 "LCAMPZ6",
	 -14.837131f,
	 1.25f,
	 -41.580185f,
	 -0.485221f,
	 0.0f,
	 0.874392f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{44,
	 "LCAMPZ7",
	 -22.17942f,
	 1.25f,
	 -41.132347f,
	 0.697186f,
	 0.0f,
	 0.716891f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{45,
	 "LCAMRA1",
	 -68.90462f,
	 10.238018f,
	 -15.521397f,
	 -0.150999f,
	 -0.051266f,
	 -0.987204f,
	 -0.007751f,
	 0.998685f,
	 -0.050677f,
	 {"EDG00_03", 1, 0.5f, 3, 0.5f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{46,
	 "LCAMRA2",
	 -67.931305f,
	 7.883309f,
	 -28.911201f,
	 -0.596641f,
	 -0.000131f,
	 0.802509f,
	 -0.000078f,
	 1.0f,
	 0.000105f,
	 {"EDG01_17", 0, 0.5f, 3, 0.5f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 25},
	{47,
	 "LCAMRA3",
	 -57.06778f,
	 7.883309f,
	 -45.567757f,
	 -0.982252f,
	 -0.000114f,
	 0.187564f,
	 -0.000112f,
	 1.0f,
	 0.000021f,
	 {"EDG01_40", 2, 0.5f, 0, 0.5f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{48,
	 "LCAMRA4",
	 -72.23135f,
	 7.912604f,
	 -45.26192f,
	 0.993571f,
	 -0.036148f,
	 -0.10728f,
	 0.035939f,
	 0.999346f,
	 -0.00388f,
	 {"EDG01_27", 0, 0.5f, 2, 0.5f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 25},
	{49,
	 "LCAMRA5",
	 -84.27638f,
	 4.683791f,
	 -52.99282f,
	 0.976109f,
	 -0.025475f,
	 -0.215783f,
	 0.024875f,
	 0.999675f,
	 -0.005499f,
	 {"EDG01_08", 2, 0.7f, 0, 0.7f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 25},
	{50,
	 "LCAMRA6",
	 -86.96998f,
	 5.265254f,
	 -16.33013f,
	 -0.999696f,
	 0.000378f,
	 -0.024655f,
	 0.000378f,
	 1.0f,
	 0.000009f,
	 {"EDG01_13", 1, 0.2f, 0, 0.2f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{51,
	 "LCAMRT1",
	 -11.308265f,
	 1.25f,
	 9.629765f,
	 1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"EDG03_10", 0, 0.5f, 2, 0.5f, 0},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 80},
	{52,
	 "LCAMRT2",
	 -2.950222f,
	 1.25f,
	 12.345603f,
	 0.816763f,
	 0.0f,
	 -0.576974f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"EDG03_10", 0, 0.5f, 2, 0.5f, 0},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 100},
	{53,
	 "LCAMRT3",
	 -0.87654f,
	 1.25f,
	 11.844613f,
	 0.006162f,
	 0.0f,
	 -0.999981f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 100},
	{54,
	 "LCAMRT4",
	 0.4375f,
	 1.25f,
	 7.0f,
	 -0.748454f,
	 0.0f,
	 -0.663187f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{55,
	 "LCAMRT5",
	 -27.213715f,
	 1.25f,
	 13.280918f,
	 -0.670318f,
	 0.0f,
	 -0.742074f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"EDG03_05", 1, 0.5f, 2, 0.5f, 0},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{56,
	 "LCAMRT6",
	 -21.811115f,
	 1.25f,
	 9.006517f,
	 0.97496f,
	 0.0f,
	 0.222379f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"EDG03_10", 0, 0.5f, 2, 0.5f, 0},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 60},
	{57,
	 "LCAMST1",
	 -40.1615f,
	 2.02756f,
	 -56.701893f,
	 -0.958601f,
	 0.0f,
	 -0.284751f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 20},
	{58,
	 "LCAMST2",
	 -48.750553f,
	 2.703701f,
	 -55.472034f,
	 -0.032008f,
	 0.0f,
	 -0.999488f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{59,
	 "LCAMZG1",
	 31.694365f,
	 1.25f,
	 -2.814015f,
	 -0.650445f,
	 0.0f,
	 0.759553f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {"INT22", 0, 0.4f, 2, 0.4f, 1},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{60,
	 "LCAMZI1",
	 93.37283f,
	 10.1875f,
	 -10.382307f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{61,
	 "LCAMZI2",
	 93.37283f,
	 19.4375f,
	 -10.382307f,
	 0.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{62,
	 "LCAMZIE",
	 93.375f,
	 19.4375f,
	 -10.375f,
	 0.967075f,
	 -0.254493f,
	 0.0f,
	 0.254493f,
	 0.967075f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{63,
	 "LCAMZIN",
	 93.37283f,
	 19.4375f,
	 -10.382307f,
	 0.0f,
	 -0.254006f,
	 0.967203f,
	 0.0f,
	 0.967203f,
	 0.254006f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{64,
	 "LCAMZIS",
	 93.37283f,
	 19.4375f,
	 -10.382307f,
	 0.0f,
	 -0.254982f,
	 -0.966946f,
	 0.0f,
	 0.966946f,
	 -0.254982f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{65,
	 "LCAMZIW",
	 93.375f,
	 19.4375f,
	 -10.375f,
	 -0.967075f,
	 -0.254493f,
	 0.0f,
	 -0.254493f,
	 0.967075f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{66,
	 "LCAMZP1",
	 73.70144f,
	 2.25f,
	 -88.91317f,
	 -0.911398f,
	 0.0f,
	 0.411526f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{67,
	 "LCAMRT7",
	 -1.170637f,
	 1.25f,
	 5.082029f,
	 -1.0f,
	 0.0f,
	 -0.000599f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0},
	{68,
	 "LCAMJS5",
	 -1.734375f,
	 -0.625f,
	 -61.8125f,
	 -0.454574f,
	 0.0f,
	 -0.890709f,
	 0.0f,
	 1.0f,
	 0.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 100},
	{69,
	 "overhead",
	 0.0f,
	 135.0f,
	 0.0f,
	 0.0f,
	 -1.0f,
	 0.0f,
	 0.0f,
	 0.0f,
	 1.0f,
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 {NULL, 0, 0.0f, 0, 0.0f, FALSE},
	 FALSE,
	 0}
};

// GLOBAL: LEGO1 0x100f66a0
MxU32 g_changeLight = FALSE;

// GLOBAL: LEGO1 0x100f66a4
MxS32 g_locationCalcStep = 0;

// GLOBAL: LEGO1 0x100f66a8
MxS32 g_nextLocation = 0;

// GLOBAL: LEGO1 0x100f66ac
MxBool g_resetPlants = FALSE;

// GLOBAL: LEGO1 0x100f66b0
MxS32 g_animationCalcStep = 0;

// GLOBAL: LEGO1 0x100f66b4
MxS32 g_nextAnimation = 0;

// GLOBAL: LEGO1 0x100f66b8
MxU32 g_switchAct = FALSE;

// GLOBAL: LEGO1 0x100f66bc
LegoAnimationManager::PlayMode g_unk0x100f66bc = LegoAnimationManager::e_unk2;

// GLOBAL: LEGO1 0x100f66c0
char g_debugPassword[] = "OGEL";

// GLOBAL: LEGO1 0x100f66c8
char* g_currentInput = g_debugPassword;

// GLOBAL: LEGO1 0x100f66cc
MxS32 g_nextCharacter = -1;

// GLOBAL: LEGO1 0x100f66d0
MxBool g_enableMusic = TRUE;

// GLOBAL: LEGO1 0x100f66d4
MxU32 g_fpsEnabled = TRUE;

// FUNCTION: LEGO1 0x10054ac0
LegoNavController::LegoNavController()
{
	SetToDefaultParams();

	m_linearVel = 0.0f;
	m_rotationalVel = 0.0f;
	m_targetLinearVel = 0.0f;
	m_targetRotationalVel = 0.0f;
	m_linearAccel = 0.0f;
	m_rotationalAccel = 0.0f;
	m_trackDefault = FALSE;
	m_keyPressed = FALSE;
	m_isAccelerating = FALSE;
	m_additionalScale = 0.0f;
	m_additionalRotationY = 0.0f;
	m_additionalHeightOffset = 0.0f;

	m_lastTime = Timer()->GetTime();

	InputManager()->Register(this);
}

// FUNCTION: LEGO1 0x10054c30
LegoNavController::~LegoNavController()
{
	InputManager()->UnRegister(this);
}

// FUNCTION: LEGO1 0x10054ca0
void LegoNavController::SetControlMax(int p_hMax, int p_vMax)
{
	m_hMax = p_hMax;
	m_vMax = p_vMax;

	if (VideoManager()->GetVideoParam().Flags().GetFullScreen()) {
		m_hMax = 640;
		m_vMax = 480;
	}
}

// FUNCTION: LEGO1 0x10054cd0
// FUNCTION: BETA10 0x1009ad76
void LegoNavController::SetToDefaultParams()
{
	m_deadZone = g_defdeadZone;
	m_zeroThreshold = g_defzeroThreshold;
	m_maxRotationalAccel = g_defmaxRotationalAccel;
	m_maxLinearAccel = g_defmaxLinearAccel;
	m_minRotationalAccel = g_defminRotationalAccel;
	m_minLinearAccel = g_defminLinearAccel;
	m_maxRotationalDeccel = g_defmaxRotationalDeccel;
	m_maxLinearDeccel = g_defmaxLinearDeccel;
	m_maxRotationalVel = g_defmaxRotationalVel;
	m_maxLinearVel = g_defmaxLinearVel;
	m_useRotationalVel = g_defuseRotationalVel;
	m_rotSensitivity = g_defrotSensitivity;
}

// FUNCTION: LEGO1 0x10054d40
void LegoNavController::GetDefaults(
	int* p_dz,
	float* p_lv,
	float* p_rv,
	float* p_la,
	float* p_ra,
	float* p_ld,
	float* p_rd,
	float* p_lmina,
	float* p_rmina,
	float* p_rs,
	MxBool* p_urs
)
{
	*p_dz = g_defdeadZone;
	*p_lv = g_defmaxLinearVel;
	*p_rv = g_defmaxRotationalVel;
	*p_la = g_defmaxLinearAccel;
	*p_ra = g_defmaxRotationalAccel;
	*p_ld = g_defmaxLinearDeccel;
	*p_rd = g_defmaxRotationalDeccel;
	*p_lmina = g_defminLinearAccel;
	*p_rmina = g_defminRotationalAccel;
	*p_rs = g_defrotSensitivity;
	*p_urs = g_defuseRotationalVel;
}

// FUNCTION: LEGO1 0x10054dd0
void LegoNavController::SetDefaults(
	int p_dz,
	float p_lv,
	float p_rv,
	float p_la,
	float p_ra,
	float p_ld,
	float p_rd,
	float p_lmina,
	float p_rmina,
	float p_rs,
	MxBool p_urs
)
{
	g_defdeadZone = p_dz;
	g_defmaxLinearVel = p_lv;
	g_defmaxRotationalVel = p_rv;
	g_defmaxLinearAccel = p_la;
	g_defmaxRotationalAccel = p_ra;
	g_defmaxLinearDeccel = p_ld;
	g_defmaxRotationalDeccel = p_rd;
	g_defminLinearAccel = p_lmina;
	g_defminRotationalAccel = p_rmina;
	g_defrotSensitivity = p_rs;
	g_defuseRotationalVel = p_urs;
}

// FUNCTION: LEGO1 0x10054e40
void LegoNavController::SetTargets(int p_hPos, int p_vPos, MxBool p_accel)
{
	if (m_trackDefault != FALSE) {
		SetToDefaultParams();
	}

	if (p_accel != FALSE) {
		m_targetRotationalVel = CalculateNewTargetVel(p_hPos, m_hMax / 2, m_maxRotationalVel);
		m_targetLinearVel = CalculateNewTargetVel(m_vMax - p_vPos, m_vMax / 2, m_maxLinearVel);
		m_rotationalAccel = CalculateNewAccel(p_hPos, m_hMax / 2, m_maxRotationalAccel, (int) m_minRotationalAccel);
		m_linearAccel = CalculateNewAccel(m_vMax - p_vPos, m_vMax / 2, m_maxLinearAccel, (int) m_minLinearAccel);
	}
	else {
		m_targetRotationalVel = 0;
		m_targetLinearVel = 0;
		m_linearAccel = m_maxLinearDeccel;
		m_rotationalAccel = m_maxRotationalDeccel;
	}
}

// Declaration-record carrier (dial campaign): samples this translation
// unit's accumulated declaration state at this point. Neutral stand-in;
// no authentic 1997 declaration is recoverable here.
class MxUnkRecordWI;

// FUNCTION: LEGO1 0x10054f10
float LegoNavController::CalculateNewTargetVel(int p_pos, int p_center, float p_max)
{
	float newVel;
	int diff = p_pos - p_center;

	if (diff > m_deadZone) {
		newVel = (diff - m_deadZone) * p_max / (p_center - m_deadZone);
	}
	else if (diff < -m_deadZone) {
		newVel = (diff + m_deadZone) * p_max / (p_center - m_deadZone);
	}
	else {
		newVel = 0.0;
	}

	return newVel;
}

// FUNCTION: LEGO1 0x10054f90
float LegoNavController::CalculateNewAccel(int p_pos, int p_center, float p_max, int p_min)
{
	float newAccel;
	int diff = p_pos - p_center;

	newAccel = Abs(diff) * p_max / p_center;

	if (newAccel < p_min) {
		newAccel = (float) p_min;
	}

	return newAccel;
}

// FUNCTION: LEGO1 0x10054fe0
float LegoNavController::CalculateNewVel(float p_targetVel, float p_currentVel, float p_accel, float p_time)
{
	float newVel = p_currentVel;

	float velDiff = p_targetVel - p_currentVel;
	int vSign = velDiff > 0 ? 1 : -1;

	if (Abs(velDiff) > m_zeroThreshold) {
		float deltaVel = p_accel * p_time;
		newVel = p_currentVel + (deltaVel * vSign);

		if (vSign > 0) {
			newVel = Min(newVel, p_targetVel);
		}
		else {
			newVel = Max(newVel, p_targetVel);
		}
	}

	return newVel;
}

// Declaration-record carrier (dial campaign): samples this translation
// unit's accumulated declaration state at this point. Neutral stand-in;
// no authentic 1997 declaration is recoverable here.
class MxUnkRecordInstantiations000 {};
class MxUnkRecordInstantiations001;
class MxUnkRecordInstantiations002;

// FUNCTION: LEGO1 0x10055080
// FUNCTION: BETA10 0x1009b26b
MxBool LegoNavController::CalculateNewPosDir(
	const Vector3& p_curPos,
	const Vector3& p_curDir,
	Vector3& p_newPos,
	Vector3& p_newDir,
	const Vector3* p_up
)
{
	if (!g_isWorldActive) {
		return FALSE;
	}

	MxBool changed = FALSE;
	MxBool rotatedY = FALSE;

	MxTime currentTime = Timer()->GetTime();
	float deltaTime = (currentTime - m_lastTime) / 1000.0;
	m_lastTime = currentTime;

	if (ProcessKeyboardInput() == FAILURE) {
		ProcessJoystickInput(rotatedY);
	}

	if (m_useRotationalVel) {
		m_rotationalVel = CalculateNewVel(m_targetRotationalVel, m_rotationalVel, m_rotationalAccel * 40.0f, deltaTime);
	}
	else {
		m_rotationalVel = m_targetRotationalVel;
	}

	m_linearVel = CalculateNewVel(m_targetLinearVel, m_linearVel, m_linearAccel, deltaTime);

	if (rotatedY || (Abs(m_rotationalVel) > m_zeroThreshold) || (Abs(m_linearVel) > m_zeroThreshold)) {
		float rot_mat[3][3];
		Mx3DPointFloat delta_pos, new_dir, new_pos;

		if (m_linearVel < -(m_maxLinearVel * 0.4f)) {
			m_linearVel = -(m_maxLinearVel * 0.4f);
		}

		VXS3(delta_pos, p_curDir, m_linearVel * deltaTime);
		VPV3(p_newPos, p_curPos, delta_pos);

		float delta_rad;
		if (m_useRotationalVel) {
			delta_rad = DTOR(m_rotationalVel * deltaTime);
		}
		else {
			delta_rad = DTOR(m_rotationalVel * m_rotSensitivity);
		}

		if (p_up != NULL && (*p_up)[1] < 0.0f) {
			delta_rad = -delta_rad;
		}

		IDENTMAT3(rot_mat);
		rot_mat[0][0] = rot_mat[2][2] = cos(delta_rad);
		rot_mat[0][2] = rot_mat[2][0] = sin(delta_rad);
		rot_mat[0][2] *= -1.0f;
		VXM3(p_newDir, p_curDir, rot_mat);

		changed = TRUE;
	}

	if (m_keyPressed) {
		float rot_mat[3][3];
		Mx3DPointFloat delta_pos, new_pos, new_dir;

		if (changed) {
			SET3(new_pos, p_newPos);
			SET3(new_dir, p_newDir);
		}
		else {
			SET3(new_pos, p_curPos);
			SET3(new_dir, p_curDir);
		}

		if (m_additionalScale != 0.0f) {
			delta_pos[0] = new_dir[0] * m_additionalScale;
			delta_pos[1] = new_dir[1] * m_additionalScale;
			delta_pos[2] = new_dir[2] * m_additionalScale;
		}
		else {
			FILLVEC3(delta_pos, 0.0f);
		}

		delta_pos[1] += m_additionalHeightOffset;
		VPV3(p_newPos, new_pos, delta_pos);

		if (m_additionalRotationY != 0.0f) {
			float delta_rad = DTOR(m_additionalRotationY);
			IDENTMAT3(rot_mat);
			rot_mat[0][0] = rot_mat[2][2] = cos(delta_rad);
			rot_mat[0][2] = rot_mat[2][0] = sin(delta_rad);
			rot_mat[0][2] *= -1.0f;
			VXM3(p_newDir, new_dir, rot_mat);
		}
		else {
			SET3(p_newDir, new_dir);
		}

		m_additionalHeightOffset = m_additionalScale = m_additionalRotationY = 0.0f;
		m_keyPressed = FALSE;
		changed = TRUE;
	}

	return changed;
}

// Declaration-record carrier (dial campaign): samples this translation
// unit's accumulated declaration state at this point. Neutral stand-in;
// no authentic 1997 declaration is recoverable here.
class MxUnkRecordWJ {};
class MxUnkRecordWK {};

// FUNCTION: LEGO1 0x10055500
// FUNCTION: BETA10 0x1009bff8
MxResult LegoNavController::UpdateLocation(const char* p_location)
{
	MxResult result = FAILURE;

	for (MxS32 i = 0; i < (MxS32) sizeOfArray(g_locations); i++) {
		if (!strcmpi(p_location, g_locations[i].m_name)) {
			MxMatrix mat;
			LegoROI* viewROI = VideoManager()->GetViewROI();

			CalcLocalTransform(g_locations[i].m_position, g_locations[i].m_direction, g_locations[i].m_up, mat);

			Mx3DPointFloat vec;
			vec.Clear();

			viewROI->SetWorldVelocity(vec);
			viewROI->WrappedSetLocal2WorldWithWorldDataUpdate(mat);
			VideoManager()->Get3DManager()->Moved(*viewROI);

			SoundManager()->UpdateListener(
				viewROI->GetWorldPosition(),
				viewROI->GetWorldDirection(),
				viewROI->GetWorldUp(),
				viewROI->GetWorldVelocity()
			);

			result = SUCCESS;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10055620
// FUNCTION: BETA10 0x1009c145
MxResult LegoNavController::UpdateLocation(MxU32 p_location)
{
	MxResult result = FAILURE;

	if (p_location < sizeOfArray(g_locations)) {
		MxMatrix mat;
		LegoROI* viewROI = VideoManager()->GetViewROI();

		CalcLocalTransform(
			g_locations[p_location].m_position,
			g_locations[p_location].m_direction,
			g_locations[p_location].m_up,
			mat
		);

		Mx3DPointFloat vec;
		vec.Clear();

		viewROI->SetWorldVelocity(vec);
		viewROI->WrappedSetLocal2WorldWithWorldDataUpdate(mat);
		VideoManager()->Get3DManager()->Moved(*viewROI);

		SoundManager()->UpdateListener(
			viewROI->GetWorldPosition(),
			viewROI->GetWorldDirection(),
			viewROI->GetWorldUp(),
			viewROI->GetWorldVelocity()
		);

		result = SUCCESS;
	}

	return result;
}

// FUNCTION: LEGO1 0x10055720
// FUNCTION: BETA10 0x1009c259
LegoLocation* LegoNavController::GetLocation(MxU32 p_location)
{
	if (p_location < sizeOfArray(g_locations)) {
		return &g_locations[p_location];
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10055740
// FUNCTION: BETA10 0x1009c28c
MxS32 LegoNavController::GetNumCameras()
{
	return sizeOfArray(g_locations);
}

// FUNCTION: LEGO1 0x10055750
// FUNCTION: BETA10 0x1009c2a1
MxResult LegoNavController::ProcessJoystickInput(MxBool& p_rotatedY)
{
	LegoOmni* instance = LegoOmni::GetInstance();

	if (instance->GetInputManager()) {
		MxS32 joystickX;
		MxS32 joystickY;
		DWORD buttonState;
		MxS32 povPosition;

		if (instance->GetInputManager()
				->GetJoystickState((MxU32*) &joystickX, (MxU32*) &joystickY, &buttonState, (MxU32*) &povPosition) !=
			FAILURE) {
			MxU32 yVal = (joystickY * m_vMax) / 100;
			MxU32 xVal = (joystickX * m_hMax) / 100;

			if (joystickX <= 45 || joystickX >= 55 || joystickY <= 45 || joystickY >= 55) {
				m_targetLinearVel = CalculateNewTargetVel(m_vMax - yVal, m_vMax / 2, m_maxLinearVel);
				m_linearAccel = CalculateNewAccel(m_vMax - yVal, m_vMax / 2, m_maxLinearAccel, (int) m_minLinearAccel);
				m_targetRotationalVel = CalculateNewTargetVel(xVal, m_hMax / 2, m_maxRotationalVel);
				m_rotationalAccel =
					CalculateNewAccel(xVal, m_hMax / 2, m_maxRotationalAccel, (int) m_minRotationalAccel);
			}
			else {
				m_targetRotationalVel = 0.0;
				m_targetLinearVel = 0.0;
				m_linearAccel = m_maxLinearDeccel;
				m_rotationalAccel = m_maxRotationalDeccel;
			}

			if (povPosition >= 0) {
				LegoWorld* world = CurrentWorld();

				if (world && world->GetCameraController()) {
					world->GetCameraController()->RotateY(DTOR(povPosition));
					p_rotatedY = TRUE;
				}
			}

			return SUCCESS;
		}
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x100558b0
// FUNCTION: BETA10 0x1009c49a
MxResult LegoNavController::ProcessKeyboardInput()
{
	MxBool skipRotationVelAndAccelCalc = FALSE;
	MxBool skipLinearVelAndAccelCalc = FALSE;
	LegoInputManager* inputManager = LegoOmni::GetInstance()->GetInputManager();
	MxU32 keyFlags;

	if (inputManager == NULL || inputManager->GetNavigationKeyStates(keyFlags) == FAILURE) {
		return FAILURE;
	}

	if (keyFlags == 0) {
		if (m_isAccelerating) {
			m_targetRotationalVel = 0.0;
			m_targetLinearVel = 0.0;
			m_rotationalAccel = m_maxRotationalDeccel;
			m_linearAccel = m_maxLinearDeccel;
			m_isAccelerating = FALSE;
		}

		return FAILURE;
	}

	m_isAccelerating = TRUE;

	MxS32 hMax;
	switch (keyFlags & LegoInputManager::c_leftOrRight) {
	case LegoInputManager::c_left:
		hMax = 0;
		break;
	case LegoInputManager::c_right:
		hMax = m_hMax;
		break;
	default:
		m_targetRotationalVel = 0.0;
		m_rotationalAccel = m_maxRotationalDeccel;
		skipRotationVelAndAccelCalc = TRUE;
		break;
	}

	MxS32 vMax;
	switch (keyFlags & LegoInputManager::c_upOrDown) {
	case LegoInputManager::c_up:
		vMax = 0;
		break;
	case LegoInputManager::c_down:
		vMax = m_vMax;
		break;
	default:
		m_targetLinearVel = 0.0;
		m_linearAccel = m_maxLinearDeccel;
		skipLinearVelAndAccelCalc = TRUE;
		break;
	}

	MxFloat maxAccelDivisor = keyFlags & LegoInputManager::c_ctrl ? 1.0f : 4.0f;
	MxFloat minAccelDivisor = keyFlags & LegoInputManager::c_ctrl ? 1.0f : 2.0f;

	if (!skipRotationVelAndAccelCalc) {
		m_targetRotationalVel = CalculateNewTargetVel(hMax, m_hMax / 2, m_maxRotationalVel);
		m_rotationalAccel = CalculateNewAccel(
			hMax,
			m_hMax / 2,
			m_maxRotationalAccel / maxAccelDivisor,
			(int) (m_minRotationalAccel / minAccelDivisor)
		);
	}

	if (!skipLinearVelAndAccelCalc) {
		m_targetLinearVel = CalculateNewTargetVel(m_vMax - vMax, m_vMax / 2, m_maxLinearVel);
		m_linearAccel = CalculateNewAccel(
			m_vMax - vMax,
			m_vMax / 2,
			m_maxLinearAccel / maxAccelDivisor,
			(int) (m_minLinearAccel / minAccelDivisor)
		);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10055a60
// FUNCTION: BETA10 0x1009c712
MxLong LegoNavController::Notify(MxParam& p_param)
{
	if (((MxNotificationParam&) p_param).GetNotification() == c_notificationKeyPress) {
		m_keyPressed = TRUE;
		MxU8 key = ((LegoEventNotificationParam&) p_param).GetKey();

		switch (key) {
		case VK_PAUSE: // Pause game
			if (Lego()->IsPaused()) {
				Lego()->Resume();
			}
			else {
				Lego()->Pause();
			}
			break;
		case VK_ESCAPE: { // Return to infocenter
			LegoWorld* currentWorld = CurrentWorld();
			if (currentWorld != NULL) {
				InfocenterState* state = (InfocenterState*) GameState()->GetState("InfocenterState");

				if (state != NULL && state->m_step != InfocenterState::e_exitQueried && currentWorld->Escape()) {
					BackgroundAudioManager()->Stop();
					TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
					state->m_step = InfocenterState::e_exitQueried;
				}
			}
			break;
		}
		case VK_SPACE: // Interrupt/end animations or free navigation
			AnimationManager()->FUN_10061010(TRUE);
			break;
		case 'Z': { // Make nearby plants "dance"
			LegoOmni* omni = Lego();

			if (omni->GetCurrentWorld() != NULL && omni->GetCurrentWorld()->GetWorldId() == LegoOmni::e_act1) {
				LegoVideoManager* videoMgr = LegoOmni::GetInstance()->GetVideoManager();
				ViewROI* roi = videoMgr->GetViewROI();
				ViewManager* view = videoMgr->Get3DManager()->GetLego3DView()->GetViewManager();
				LegoPlantManager* plantMgr = LegoOmni::GetInstance()->GetPlantManager();
				Mx3DPointFloat viewPosition(roi->GetWorldPosition());
				MxS32 numPlants = plantMgr->GetNumPlants();

				for (MxS32 i = 0; i < numPlants; i++) {
					LegoEntity* entity = plantMgr->CreatePlant(i, NULL, LegoOmni::e_act1);

					if (entity != NULL && !entity->IsInteraction(LegoEntity::c_disabled)) {
						LegoROI* roi = entity->GetROI();

						if (roi != NULL && roi->GetVisibility()) {
							const BoundingBox& box = roi->GetWorldBoundingBox();

							if (view->IsBoundingBoxInFrustum(box)) {
								Mx3DPointFloat roiPosition(roi->GetWorldPosition());
								roiPosition -= viewPosition;

								if (roiPosition.LenSquared() < 2000.0 || roi->GetToken() > 0) {
									entity->ClickAnimation();
								}
							}
						}
					}
				}
			}
			break;
		}
		case VK_ADD:
		case VK_SUBTRACT: { // Cycles through characters and puts them in front of you
			if (g_nextCharacter == -1) {
				g_nextCharacter = 0;
			}
			else {
				CharacterManager()->ReleaseActor(CharacterManager()->GetActorName(g_nextCharacter));

				if (key == VK_ADD) {
					g_nextCharacter++;
					if (g_nextCharacter >= CharacterManager()->GetNumActors()) {
						g_nextCharacter = 0;
					}
				}
				else {
					g_nextCharacter--;
					if (g_nextCharacter < 0) {
						g_nextCharacter = CharacterManager()->GetNumActors() - 1;
					}
				}
			}

			LegoROI* roi = CharacterManager()->GetActorROI(CharacterManager()->GetActorName(g_nextCharacter), TRUE);
			if (roi != NULL) {
				MxMatrix mat;
				ViewROI* viewRoi = LegoOmni::GetInstance()->GetVideoManager()->GetViewROI();
				const float* position = viewRoi->GetWorldPosition();
				const float* direction = viewRoi->GetWorldDirection();
				const float* up = viewRoi->GetWorldUp();
				CalcLocalTransform(position, direction, up, mat);
				mat.TranslateBy(direction[0] * 2.0f, direction[1] - 1.0, direction[2] * 2.0f);
				roi->UpdateTransformationRelativeToParent(mat);
			}
			break;
		}
		case VK_F12: { // Saves the game
			InfocenterState* state = (InfocenterState*) GameState()->GetState("InfocenterState");
			assert(state);

			if (state && state->HasRegistered()) {
				GameState()->Save(0);
			}
			break;
		}
		default:
			// Check if the the key is part of the debug password
			if (!*g_currentInput) {
				// password "protected" debug shortcuts
				switch (((LegoEventNotificationParam&) p_param).GetKey()) {
				case VK_TAB:
					VideoManager()->ToggleFPS(g_fpsEnabled);
					if (g_fpsEnabled) {
						g_fpsEnabled = FALSE;
					}
					else {
						g_fpsEnabled = TRUE;
					}
				default:
					m_keyPressed = FALSE;
					break;
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
					if (g_changeLight && key <= '1') {
						LegoROI* roi = VideoManager()->GetViewROI();
						Tgl::FloatMatrix4 matrix;
						Matrix4 in(matrix);
						roi->GetLocalTransform(in);
						VideoManager()->Get3DManager()->GetLego3DView()->SetLightTransform(key - '0', matrix);
						g_changeLight = FALSE;
					}
					else if (g_locationCalcStep) {
						if (g_locationCalcStep == 1) {
							// Calculate base offset into g_locations
							g_nextLocation = (key - '0') * 10;
							g_locationCalcStep = 2;
						}
						else {
							// Add to base g_locations offset
							g_nextLocation += key - '0';
							g_locationCalcStep = 0;
							UpdateLocation(g_nextLocation);
						}
					}
					else if (g_animationCalcStep) {
						if (g_animationCalcStep == 1) {
							// Calculate base offset into possible animation object IDs (up to 999)
							g_nextAnimation = (key - '0') * 100;
							g_animationCalcStep = 2;
						}
						else if (g_animationCalcStep == 2) {
							// Add to animation object ID offset
							g_nextAnimation += (key - '0') * 10;
							g_animationCalcStep = 3;
						}
						else {
							// Add to animation object ID offset
							g_nextAnimation += key - '0';
							g_animationCalcStep = 0;
							AnimationManager()->FUN_10060dc0(
								g_nextAnimation,
								NULL,
								TRUE,
								g_unk0x100f66bc,
								NULL,
								TRUE,
								TRUE,
								TRUE,
								TRUE
							);

							g_unk0x100f66bc = LegoAnimationManager::e_unk2;
						}
					}

					if (g_switchAct && key >= '1' && key <= '5') {
						switch (GameState()->GetCurrentAct()) {
						case LegoGameState::e_act1:
							GameState()->m_currentArea = LegoGameState::e_isle;
							break;
						case LegoGameState::e_act2:
							GameState()->m_currentArea = LegoGameState::e_act2main;
							break;
						case LegoGameState::e_act3:
							GameState()->m_currentArea = LegoGameState::e_act3script;
							break;
						}

						switch (key) {
						case '1':
							GameState()->SetCurrentAct(LegoGameState::e_act1);
							GameState()->SwitchArea(LegoGameState::e_isle);
							break;
						case '2':
							GameState()->SwitchArea(LegoGameState::e_act2main);
							break;
						case '3':
							GameState()->SwitchArea(LegoGameState::e_act3script);
							break;
						case '4': {
							Act3State* act3State = (Act3State*) GameState()->GetState("Act3State");
							if (act3State == NULL) {
								act3State = new Act3State();
								assert(act3State);
								GameState()->RegisterState(act3State);
							}

							GameState()->SetCurrentAct(LegoGameState::e_act3);
							act3State->m_state = Act3State::e_goodEnding;
							GameState()->m_currentArea = LegoGameState::e_act3script;
							GameState()->SwitchArea(LegoGameState::e_infomain);
							break;
						}
						case '5': {
							Act3State* act3State = (Act3State*) GameState()->GetState("Act3State");
							if (act3State == NULL) {
								act3State = new Act3State();
								assert(act3State);
								GameState()->RegisterState(act3State);
							}

							GameState()->SetCurrentAct(LegoGameState::e_act3);
							act3State->m_state = Act3State::e_badEnding;
							GameState()->m_currentArea = LegoGameState::e_act3script;
							GameState()->SwitchArea(LegoGameState::e_infomain);
							break;
						}
						}

						g_switchAct = FALSE;
					}
					else {
						MxDSAction action;
						action.SetObjectId(key - '0');
						action.SetAtomId(MxAtomId("q:\\lego\\media\\model\\common\\common", e_lowerCase2));
						LegoOmni::GetInstance()->Start(&action);
					}
					break;
				case 'A':
					if (g_animationCalcStep == 1) {
						Lego()->m_initialized = TRUE;
						AnimationManager()->FUN_10060570(TRUE);
						g_animationCalcStep = 0;
					}
					else {
						LegoWorld* world = CurrentWorld();
						if (world != NULL) {
							MxDSAction action;
							action.SetObjectId(1);
							action.SetAtomId(world->GetAtomId());
							LegoOmni::GetInstance()->Start(&action);
						}
					}
					break;
				case 'C':
					g_locationCalcStep = 1;
					break;
				case 'D':
					m_additionalHeightOffset = -1.0;
					break;
				case 'F':
					RealtimeView::SetUserMaxLOD(0.0);
					break;
				case 'G':
					g_switchAct = TRUE;
					break;
				case 'H':
					RealtimeView::SetUserMaxLOD(5.0);
					break;
				case 'I': {
					LegoROI* roi = VideoManager()->GetViewROI();
					MxMatrix mat;
					mat.SetIdentity();
					mat.RotateX(0.2618f);
					roi->WrappedUpdateWorldDataWithTransform(mat);
					break;
				}
				case 'J': {
					LegoROI* roi = VideoManager()->GetViewROI();
					MxMatrix mat;
					mat.SetIdentity();
					mat.RotateZ(0.2618f);
					roi->WrappedUpdateWorldDataWithTransform(mat);
					break;
				}
				case 'K': {
					MxMatrix mat;
					LegoROI* roi = LegoOmni::GetInstance()->GetVideoManager()->GetViewROI();
					mat.SetIdentity();
					mat.RotateZ(-0.2618f);
					roi->WrappedUpdateWorldDataWithTransform(mat);
					break;
				}
				case 'L':
					g_changeLight = TRUE;
					break;
				case 'M': {
					LegoROI* roi = LegoOmni::GetInstance()->GetVideoManager()->GetViewROI();
					MxMatrix mat;
					mat.SetIdentity();
					mat.RotateX(-0.2618f);
					roi->WrappedUpdateWorldDataWithTransform(mat);
					break;
				}
				case 'N':
					if (VideoManager()) {
						VideoManager()->SetRender3D(!VideoManager()->GetRender3D());
					}
					break;
				case 'P':
					if (!g_resetPlants) {
						PlantManager()->LoadWorldInfo(LegoOmni::e_act1);
						g_resetPlants = TRUE;
					}
					else {
						PlantManager()->Reset(LegoOmni::e_act1);
						g_resetPlants = FALSE;
					}
					break;
				case 'S':
					g_enableMusic = g_enableMusic == FALSE;
					BackgroundAudioManager()->Enable(g_enableMusic);
					break;
				case 'U':
					m_additionalHeightOffset = 1.0;
					break;
				case 'V':
					if (g_nextAnimation > 0 && g_animationCalcStep == 0) {
						AnimationManager()->FUN_10061010(FALSE);
					}

					if (g_animationCalcStep != 0) {
						g_unk0x100f66bc = LegoAnimationManager::e_unk2;
					}

					g_nextAnimation = 0;
					g_animationCalcStep = 1;
					break;
				case 'W': {
					MxMatrix mat;
					LegoROI* roi = LegoOmni::GetInstance()->GetVideoManager()->GetViewROI();
					const float* position = roi->GetWorldPosition();
					const float* direction = roi->GetWorldDirection();
					const float* up = roi->GetWorldUp();

					MxTrace(
						"pos: %f, %f, %f\ndir: %f, %f, %f\nup: %f, %f, %f\n",
						EXPAND3(position),
						EXPAND3(direction),
						EXPAND3(up)
					);
					break;
				}
				case 'X':
					RealtimeView::SetUserMaxLOD(3.6);
					break;
				case VK_MULTIPLY: {
					MxU8 newActor = GameState()->GetActorId() + 1;

					if (newActor > LegoActor::e_laura) {
						newActor = LegoActor::e_pepper;
					}

					GameState()->SetActorId(newActor);
					break;
				}
				case VK_DIVIDE:
					GameState()->SetActorId(LegoActor::e_brickster);
					break;
				case VK_F11:
					if (GameState()->m_isDirty) {
						GameState()->m_isDirty = FALSE;
					}
					else {
						GameState()->m_isDirty = TRUE;
					}
					break;
				case VK_OEM_MINUS:
					g_unk0x100f66bc = LegoAnimationManager::e_unk1;
					break;
				}
			}
			else {
				if (*g_currentInput == ((LegoEventNotificationParam&) p_param).GetKey()) {
					g_currentInput++;
				}
				else {
					g_currentInput = g_debugPassword;
				}
			}
		}
	}

	return 0;
}
