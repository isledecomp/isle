// This file was automatically generated by the actionheadergen tool.
// Please do not manually edit this file.
#ifndef GARAGE_ACTIONS_H
#define GARAGE_ACTIONS_H

namespace GarageScript
{
#if __cplusplus < 201103L
enum Script : int {
#else
enum Script {
#endif
	c_noneGarage = -1,

	c__StartUp = 0,
	c_LeftArrow_Ctl = 1,
	c_RightArrow_Ctl = 2,
	c_Info_Ctl = 3,
	c_Buggy_Ctl = 4,
	c_Nubby_Entity = 5,
	c_Nubby_Model = 6,
	c_Background_Bitmap = 7,
	c_TrackLed_Bitmap = 8,
	c_LeftArrow_Up_Bitmap = 9,
	c_LeftArrow_Down_Bitmap = 10,
	c_RightArrow_Up_Bitmap = 11,
	c_RightArrow_Down_Bitmap = 12,
	c_Info_Up_Bitmap = 13,
	c_Info_Down_Bitmap = 14,
	c_Buggy_Up_Bitmap = 15,
	c_Buggy_Down_Bitmap = 16,
	c_RadioOff_Bitmap = 17,
	c_Radio_Ctl = 18,
	c_RadioOn_Bitmap = 19,
	c_ConfigAnimation = 20,
	c_wgs002nu_Wav_500 = 21,
	c_wgs002nu_Pho_500 = 22,
	c_wgs002nu_0_sfx = 23,
	c_wgs002nu_1_sfx = 24,
	c_wgs002nu_Anim = 25,
	c_wgs003nu_Wav_501 = 26,
	c_wgs003nu_Pho_501 = 27,
	c_wgs003nu_0_sfx = 28,
	c_wgs003nu_1_sfx = 29,
	c_wgs003nu_2_sfx = 30,
	c_wgs003nu_Anim = 31,
	c_wgs004nu_Wav_502 = 32,
	c_wgs004nu_Pho_502 = 33,
	c_wgs004nu_0_sfx = 34,
	c_wgs004nu_Anim = 35,
	c_wgs006nu_Wav_503 = 36,
	c_wgs006nu_Pho_503 = 37,
	c_wgs006nu_0_sfx = 38,
	c_wgs006nu_Anim = 39,
	c_wgs007nu_Wav_504 = 40,
	c_wgs007nu_Pho_504 = 41,
	c_wgs007nu_Anim = 42,
	c_wgs005nu_Wav_505 = 43,
	c_wgs005nu_Pho_505 = 44,
	c_wgs008nu_Anim = 45,
	c_wgs009nu_Wav_506 = 46,
	c_wgs009nu_Pho_506 = 47,
	c_wgs009nu_0_sfx = 48,
	c_wgs009nu_1_sfx = 49,
	c_wgs009nu_Anim = 50,
	c_wgs010nu_Wav_507 = 51,
	c_wgs010nu_Pho_507 = 52,
	c_wgs010nu_0_sfx = 53,
	c_wgs010nu_Anim = 54,
	c_wgs012nu_Wav_508 = 55,
	c_wgs012nu_Pho_508 = 56,
	c_wgs012nu_Anim = 57,
	c_WGS014NU_Wav_509 = 58,
	c_WGS014NU_Pho_509 = 59,
	c_WGS016P1_Wav_509 = 60,
	c_wgs014nu_0_sfx = 61,
	c_wgs014nu_Anim = 62,
	c_WGS019NU_Wav_510 = 63,
	c_WGS019NU_Pho_510 = 64,
	c_WGS017NU_Wav_510 = 65,
	c_WGS017NU_Pho_510 = 66,
	c_wgs017nu_0_sfx = 67,
	c_wgs017nu_Anim = 68,
	c_WGS020NU_Wav_511 = 69,
	c_WGS020NU_Pho_511 = 70,
	c_wgs020nu_0_sfx = 71,
	c_wgs020nu_Anim = 72,
	c_WGS021NU_Wav_512 = 73,
	c_WGS021NU_Pho_512 = 74,
	c_wgs021nu_0_sfx = 75,
	c_wgs021nu_Anim = 76,
	c_WGS022NU_Wav_513 = 77,
	c_WGS022NU_Pho_513 = 78,
	c_wgs022nu_0_sfx = 79,
	c_wgs022nu_1_sfx = 80,
	c_wgs022nu_2_sfx = 81,
	c_wgs022nu_Anim = 82,
	c_WGS028NU_Wav_514 = 83,
	c_WGS028NU_Pho_514 = 84,
	c_WGS027NA_Wav_514 = 85,
	c_WGS027NA_Pho_514 = 86,
	c_WGS026NA_Wav_514 = 87,
	c_WGS026NA_Pho_514 = 88,
	c_WGS025NA_Wav_514 = 89,
	c_WGS025NA_Pho_514 = 90,
	c_WGS024NA_Wav_514 = 91,
	c_WGS024NA_Pho_514 = 92,
	c_wgs023nu_0_sfx = 93,
	c_wgs023nu_1_sfx = 94,
	c_wgs023nu_2_sfx = 95,
	c_wgs023nu_3_sfx = 96,
	c_wgs023nu_4_sfx = 97,
	c_wgs023nu_5_sfx = 98,
	c_wgs023nu_6_sfx = 99,
	c_wgs023nu_7_sfx = 100,
	c_wgs023nu_8_sfx = 101,
	c_wgs023nu_9_sfx = 102,
	c_wgs023nu_Anim = 103,
	c_wgs030nu_Wav_515 = 104,
	c_wgs030nu_Pho_515 = 105,
	c_wgs029nu_Wav_515 = 106,
	c_wgs029nu_Pho_515 = 107,
	c_wgs029nu_0_sfx = 108,
	c_wgs029nu_Anim = 109,
	c_wgs031nu_Wav_516 = 110,
	c_wgs031nu_Pho_516 = 111,
	c_wgs031nu_0_sfx = 112,
	c_wgs031nu_Anim = 113,

	c_wgs002nu_RunAnim = 500,
	c_wgs003nu_RunAnim = 501,
	c_wgs004nu_RunAnim = 502,
	c_wgs006nu_RunAnim = 503,
	c_wgs007nu_RunAnim = 504,
	c_wgs008nu_RunAnim = 505,
	c_wgs009nu_RunAnim = 506,
	c_wgs010nu_RunAnim = 507,
	c_wgs012nu_RunAnim = 508,
	c_wgs014nu_RunAnim = 509,
	c_wgs017nu_RunAnim = 510,
	c_wgs020nu_RunAnim = 511,
	c_wgs021nu_RunAnim = 512,
	c_wgs022nu_RunAnim = 513,
	c_wgs023nu_RunAnim = 514,
	c_wgs029nu_RunAnim = 515,
	c_wgs031nu_RunAnim = 516
};
} // namespace GarageScript

#endif // GARAGE_ACTIONS_H
