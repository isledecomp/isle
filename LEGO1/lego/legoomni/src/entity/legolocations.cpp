#include "legolocations.h"

DECOMP_SIZE_ASSERT(LegoLocation, 0x60)
DECOMP_SIZE_ASSERT(LegoLocation::Boundary, 0x18)

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
	 1.5f,
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
