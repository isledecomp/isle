// This file was automatically generated by the actionheadergen tool.
// Please do not manually edit this file.
#ifndef RACECAR_ACTIONS_H
#define RACECAR_ACTIONS_H

class RacecarScript {
public:
	enum Script {
		c_noneRacecar = -1,

		c__StartUp = 0,

		c_RaceCar_Actor = 4,
		c_Info_Ctl = 5,
		c_Exit_Ctl = 6,
		c_ShelfUp_Ctl = 7,
		c_Platform_Ctl = 8,

		c_Background = 64,
		c_ColorBook_Bitmap = 65,
		c_ShelfUp_Up_Bitmap = 66,
		c_ShelfUp_Down_Bitmap = 67,
		c_PlatformUp_Bitmap = 68,
		c_PlatformLeft = 69,
		c_Rotate_Sound = 70,
		c_PlatformLeft_Bitmap = 71,
		c_Yellow_Ctl = 72,
		c_Yellow_Down_Bitmap = 73,
		c_Yellow_Up_Bitmap = 74,
		c_Red_Ctl = 75,
		c_Red_Down_Bitmap = 76,
		c_Red_Up_Bitmap = 77,
		c_Blue_Ctl = 78,
		c_Blue_Down_Bitmap = 79,
		c_Blue_Up_Bitmap = 80,
		c_Green_Ctl = 81,
		c_Green_Down_Bitmap = 82,
		c_Green_Up_Bitmap = 83,
		c_Gray_Ctl = 84,
		c_Gray_Down_Bitmap = 85,
		c_Gray_Up_Bitmap = 86,
		c_Black_Ctl = 87,
		c_Black_Down_Bitmap = 88,
		c_Black_Up_Bitmap = 89,
		c_Decals_Ctl = 90,
		c_RCFRNT_State_0 = 91,
		c_RCFRNT_State_0_Bitmap = 92,
		c_RCFRNT_State_1 = 93,
		c_RCFRNT_State_1_Bitmap = 94,
		c_RCFRNT_Texture_1 = 95,
		c_RCFRNT_State_2 = 96,
		c_RCFRNT_State_2_Bitmap = 97,
		c_RCFRNT_Texture_2 = 98,
		c_RCFRNT_State_3 = 99,
		c_RCFRNT_State_3_Bitmap = 100,
		c_RCFRNT_Texture_3 = 101,
		c_RCFRNT_State_4 = 102,
		c_RCFRNT_State_4_Bitmap = 103,
		c_RCFRNT_Texture_4 = 104,
		c_Decals_Ctl1 = 105,
		c_RCBACK_State_0 = 106,
		c_RCBACK_State_0_Bitmap = 107,
		c_RCBACK_State_1 = 108,
		c_RCBACK_State_1_Bitmap = 109,
		c_RCBACK_Texture_1 = 110,
		c_RCBACK_State_2 = 111,
		c_RCBACK_State_2_Bitmap = 112,
		c_RCBACK_Texture_2 = 113,
		c_RCBACK_State_3 = 114,
		c_RCBACK_State_3_Bitmap = 115,
		c_RCBACK_Texture_3 = 116,
		c_RCBACK_State_4 = 117,
		c_RCBACK_State_4_Bitmap = 118,
		c_RCBACK_Texture_4 = 119,
		c_Decals_Ctl2 = 120,
		c_RCTAIL_State_0 = 121,
		c_RCTAIL_State_0_Bitmap = 122,
		c_RCTAIL_State_1 = 123,
		c_RCTAIL_State_1_Bitmap = 124,
		c_RCTAIL_Texture_1 = 125,
		c_RCTAIL_State_2 = 126,
		c_RCTAIL_State_2_Bitmap = 127,
		c_RCTAIL_Texture_2 = 128,
		c_RCTAIL_State_3 = 129,
		c_RCTAIL_State_3_Bitmap = 130,
		c_RCTAIL_Texture_3 = 131,
		c_RCTAIL_State_4 = 132,
		c_RCTAIL_State_4_Bitmap = 133,
		c_RCTAIL_Texture_4 = 134,
		c_Info_Up_Bitmap = 135,
		c_Info_Down_Bitmap = 136,
		c_Exit_Up_Bitmap = 137,
		c_Exit_Down_Bitmap = 138,
		c_Shelf_Sound = 139,
		c_PlaceBrick_Sound = 140,
		c_GetBrick_Sound = 141,
		c_Paint_Sound = 142,
		c_Decal_Sound = 143,
		c_Build_Animation = 144,
		c_Build_Anim0 = 145,
		c_Build_Anim1 = 146,
		c_Build_Anim2 = 147,
		c_Rcuser_Model = 148,
		c_IRT001D1_Wav_500 = 149,
		c_IRT001D1_Pho_500 = 150,
		c_irt001d1_0_sfx = 151,
		c_irt001d1_1_sfx = 152,
		c_irt001d1_2_sfx = 153,
		c_irt001d1_3_sfx = 154,
		c_irt001d1_4_sfx = 155,
		c_irt001d1_5_sfx = 156,
		c_irt001d1_Anim = 157,
		c_IRT002D1_Wav_501 = 158,
		c_IRT002D1_Pho_501 = 159,
		c_irt002d1_0_sfx = 160,
		c_irt002d1_1_sfx = 161,
		c_irt002d1_2_sfx = 162,
		c_irt002d1_Anim = 163,
		c_IRT003D1_Wav_502 = 164,
		c_IRT003D1_Pho_502 = 165,
		c_irt003d1_0_sfx = 166,
		c_irt003d1_1_sfx = 167,
		c_irt003d1_2_sfx = 168,
		c_irt003d1_3_sfx = 169,
		c_irt003d1_4_sfx = 170,
		c_irt003d1_5_sfx = 171,
		c_irt003d1_6_sfx = 172,
		c_irt003d1_7_sfx = 173,
		c_irt003d1_Anim = 174,
		c_IRT004D1_Wav_503 = 175,
		c_IRT004D1_Pho_503 = 176,
		c_irt004d1_0_sfx = 177,
		c_irt004d1_1_sfx = 178,
		c_irt004d1_2_sfx = 179,
		c_irt004d1_3_sfx = 180,
		c_irt004d1_4_sfx = 181,
		c_irt004d1_Anim = 182,
		c_IRTXX4D1_Wav_504 = 183,
		c_IRTXX4D1_Pho_504 = 184,
		c_irtxx4d1_0_sfx = 185,
		c_irtxx4d1_1_sfx = 186,
		c_irtxx4d1_2_sfx = 187,
		c_irtxx4d1_3_sfx = 188,
		c_irtxx4d1_4_sfx = 189,
		c_irtxx4d1_5_sfx = 190,
		c_irtxx4d1_6_sfx = 191,
		c_irtxx4d1_Anim = 192,
		c_IRT005D1_Wav_505 = 193,
		c_IRT005D1_Pho_505 = 194,
		c_irt005d1_0_sfx = 195,
		c_irt005d1_1_sfx = 196,
		c_irt005d1_2_sfx = 197,
		c_irt005d1_3_sfx = 198,
		c_irt005d1_4_sfx = 199,
		c_irt005d1_5_sfx = 200,
		c_irt005d1_6_sfx = 201,
		c_irt005d1_7_sfx = 202,
		c_irt005d1_8_sfx = 203,
		c_irt005d1_9_sfx = 204,
		c_irt005d1_10_sfx = 205,
		c_irt005d1_11_sfx = 206,
		c_irt005d1_12_sfx = 207,
		c_irt005d1_13_sfx = 208,
		c_irt005d1_Anim = 209,

		c_irt001d1_RunAnim = 500,
		c_irt002d1_RunAnim = 501,
		c_irt003d1_RunAnim = 502,
		c_irt004d1_RunAnim = 503,
		c_irtxx4d1_RunAnim = 504,
		c_irt005d1_RunAnim = 505
	};
};

#endif // RACECAR_ACTIONS_H
