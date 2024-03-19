// This file was automatically generated by the actionheadergen tool.
// Please do not manually edit this file.
#ifndef DUNECAR_ACTIONS_H
#define DUNECAR_ACTIONS_H

namespace DunecarScript
{
#if __cplusplus < 201103L
enum Script : int {
#else
enum Script {
#endif
	c_noneDunecar = -1,

	c__StartUp = 0,

	c_DuneBugy_Actor = 2,

	c_Info_Ctl = 5,
	c_Exit_Ctl = 6,
	c_ShelfUp_Ctl = 7,
	c_Platform_Ctl = 8,

	c_DuneBugy_Model = 64,
	c_Background = 65,
	c_ColorBook_Bitmap = 66,
	c_ShelfUp_Up_Bitmap = 67,
	c_ShelfUp_Down_Bitmap = 68,
	c_PlatformUp_Bitmap = 69,
	c_PlatformLeft = 70,
	c_Rotate_Sound = 71,
	c_PlatformLeft_Bitmap = 72,
	c_Yellow_Ctl = 73,
	c_Yellow_Up_Bitmap = 74,
	c_Yellow_Down_Bitmap = 75,
	c_Red_Ctl = 76,
	c_Red_Up_Bitmap = 77,
	c_Red_Down_Bitmap = 78,
	c_Blue_Ctl = 79,
	c_Blue_Up_Bitmap = 80,
	c_Blue_Down_Bitmap = 81,
	c_Green_Ctl = 82,
	c_Green_Up_Bitmap = 83,
	c_Green_Down_Bitmap = 84,
	c_Gray_Ctl = 85,
	c_Gray_Up_Bitmap = 86,
	c_Gray_Down_Bitmap = 87,
	c_Black_Ctl = 88,
	c_Black_Up_Bitmap = 89,
	c_Black_Down_Bitmap = 90,
	c_Decals_Ctl = 91,
	c_Decal_State_0 = 92,
	c_Decal_State_0_Bitmap = 93,
	c_Decal_State_1 = 94,
	c_Decal_State_1_Bitmap = 95,
	c_Decal_Texture_1 = 96,
	c_Decal_State_2 = 97,
	c_Decal_State_2_Bitmap = 98,
	c_Decal_Texture_2 = 99,
	c_Decal_State_3 = 100,
	c_Decal_State_3_Bitmap = 101,
	c_Decal_Texture_3 = 102,
	c_Decal_State_4 = 103,
	c_Decal_State_4_Bitmap = 104,
	c_Decal_Texture_4 = 105,
	c_Info_Up_Bitmap = 106,
	c_Info_Down_Bitmap = 107,
	c_Exit_Up_Bitmap = 108,
	c_Exit_Down_Bitmap = 109,
	c_Shelf_Sound = 110,
	c_PlaceBrick_Sound = 111,
	c_GetBrick_Sound = 112,
	c_Paint_Sound = 113,
	c_Decal_Sound = 114,
	c_Build_Animation = 115,
	c_Build_Anim0 = 116,
	c_Build_Anim1 = 117,
	c_Build_Anim2 = 118,
	c_IGS001D3_Wav_500 = 119,
	c_IGS001D3_Pho_500 = 120,
	c_igs001d3_0_sfx = 121,
	c_igs001d3_1_sfx = 122,
	c_igs001d3_2_sfx = 123,
	c_igs001d3_3_sfx = 124,
	c_igs001d3_4_sfx = 125,
	c_igs001d3_5_sfx = 126,
	c_igs001d3_6_sfx = 127,
	c_igs001d3_7_sfx = 128,
	c_igs001d3_8_sfx = 129,
	c_igs001d3_9_sfx = 130,
	c_igs001d3_10_sfx = 131,
	c_igs001d3_11_sfx = 132,
	c_igs001d3_12_sfx = 133,
	c_igs001d3_13_sfx = 134,
	c_igs001d3_14_sfx = 135,
	c_igs001d3_15_sfx = 136,
	c_igs001d3_16_sfx = 137,
	c_igs001d3_17_sfx = 138,
	c_igs001d3_18_sfx = 139,
	c_igs001d3_19_sfx = 140,
	c_igs001d3_Anim = 141,
	c_IGSxx1D3_Wav_501 = 142,
	c_IGSxx1D3_Pho_501 = 143,
	c_igsxx1d3_0_sfx = 144,
	c_igsxx1d3_1_sfx = 145,
	c_igsxx1d3_2_sfx = 146,
	c_igsxx1d3_Anim = 147,
	c_IGS002D3_Wav_502 = 148,
	c_IGS002D3_Pho_502 = 149,
	c_igs002d3_0_sfx = 150,
	c_igs002d3_Anim = 151,
	c_IGS003D3_Wav_503 = 152,
	c_IGS003D3_Pho_503 = 153,
	c_igs003d3_0_sfx = 154,
	c_igs003d3_1_sfx = 155,
	c_igs003d3_2_sfx = 156,
	c_igs003d3_3_sfx = 157,
	c_igs003d3_4_sfx = 158,
	c_igs003d3_5_sfx = 159,
	c_igs003d3_6_sfx = 160,
	c_igs003d3_7_sfx = 161,
	c_igs003d3_8_sfx = 162,
	c_igs003d3_Anim = 163,
	c_IGS004D3_Wav_504 = 164,
	c_IGS004D3_Pho_504 = 165,
	c_igs004d3_0_sfx = 166,
	c_igs004d3_1_sfx = 167,
	c_igs004d3_2_sfx = 168,
	c_igs004d3_3_sfx = 169,
	c_igs004d3_4_sfx = 170,
	c_igs004d3_Anim = 171,
	c_IGS005D3_Wav_505 = 172,
	c_IGS005D3_Pho_505 = 173,
	c_igs005d3_0_sfx = 174,
	c_igs005d3_1_sfx = 175,
	c_igs005d3_2_sfx = 176,
	c_igs005d3_3_sfx = 177,
	c_igs005d3_4_sfx = 178,
	c_igs005d3_5_sfx = 179,
	c_igs005d3_Anim = 180,

	c_igs001d3_RunAnim = 500,
	c_igsxx1d3_RunAnim = 501,
	c_igs002d3_RunAnim = 502,
	c_igs003d3_RunAnim = 503,
	c_igs004d3_RunAnim = 504,
	c_igs005d3_RunAnim = 505
};
} // namespace DunecarScript

#endif // DUNECAR_ACTIONS_H
