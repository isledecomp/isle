// This file was automatically generated by the actionheadergen tool.
// Please do not manually edit this file.
#ifndef REGBOOK_ACTIONS_H
#define REGBOOK_ACTIONS_H

class RegbookScript {
public:
	enum Script {
		c_noneRegbook = -1,

		c__StartUp = 0,
		c_RB_Helicopter_Actor = 1,
		c_RB_DuneBugy_Actor = 2,
		c_RB_Jetski_Actor = 3,
		c_RB_RaceCar_Actor = 4,
		c_Alphabet_Ctl = 5,
		c_A_Bitmap = 6,
		c_B_Bitmap = 7,
		c_C_Bitmap = 8,
		c_D_Bitmap = 9,

		c_Infoman_Entity = 12,
		c_E_Bitmap = 13,
		c_F_Bitmap = 14,
		c_G_Bitmap = 15,
		c_H_Bitmap = 16,
		c_I_Bitmap = 17,
		c_J_Bitmap = 18,
		c_K_Bitmap = 19,
		c_L_Bitmap = 20,
		c_M_Bitmap = 21,
		c_N_Bitmap = 22,
		c_O_Bitmap = 23,
		c_P_Bitmap = 24,
		c_Q_Bitmap = 25,
		c_R_Bitmap = 26,
		c_S_Bitmap = 27,
		c_T_Bitmap = 28,
		c_U_Bitmap = 29,
		c_V_Bitmap = 30,
		c_W_Bitmap = 31,
		c_X_Bitmap = 32,
		c_Y_Bitmap = 33,
		c_Z_Bitmap = 34,
		c_Infoman_Model = 35,
		c_Background_Bitmap = 36,
		c_CheckHiLite_Bitmap = 37,
		c_Alphabet_Mask_Bitmap = 38,
		c_A_Down_Bitmap = 39,
		c_B_Down_Bitmap = 40,
		c_C_Down_Bitmap = 41,
		c_D_Down_Bitmap = 42,
		c_E_Down_Bitmap = 43,
		c_F_Down_Bitmap = 44,
		c_G_Down_Bitmap = 45,
		c_H_Down_Bitmap = 46,
		c_I_Down_Bitmap = 47,
		c_J_Down_Bitmap = 48,
		c_K_Down_Bitmap = 49,
		c_L_Down_Bitmap = 50,
		c_M_Down_Bitmap = 51,
		c_N_Down_Bitmap = 52,
		c_O_Down_Bitmap = 53,
		c_P_Down_Bitmap = 54,
		c_Textures = 55,
		c_Q_Down_Bitmap = 56,
		c_R_Down_Bitmap = 57,
		c_S_Down_Bitmap = 58,
		c_T_Down_Bitmap = 59,
		c_U_Down_Bitmap = 60,
		c_V_Down_Bitmap = 61,
		c_W_Down_Bitmap = 62,
		c_X_Down_Bitmap = 63,
		c_Y_Down_Bitmap = 64,
		c_Z_Down_Bitmap = 65,
		c_Back_Down_Bitmap = 66,
		c_Info_Down_Bitmap = 67,
		c_Check0_Ctl = 68,
		c_Check0_Bitmap = 69,
		c_Check0_Bitmap = 70,
		c_Check1_Ctl = 71,
		c_Check1_Bitmap = 72,
		c_Check1_Bitmap = 73,
		c_Check2_Ctl = 74,
		c_Check2_Bitmap = 75,
		c_Check2_Bitmap = 76,
		c_Check3_Ctl = 77,
		c_Check3_Bitmap = 78,
		c_Check3_Bitmap = 79,
		c_Check4_Ctl = 80,
		c_Check4_Bitmap = 81,
		c_Check4_Bitmap = 82,
		c_Check5_Ctl = 83,
		c_Check5_Bitmap = 84,
		c_Check5_Bitmap = 85,
		c_Check6_Ctl = 86,
		c_Check6_Bitmap = 87,
		c_Check6_Bitmap = 88,
		c_Check7_Ctl = 89,
		c_Check7_Bitmap = 90,
		c_Check7_Bitmap = 91,
		c_Check8_Ctl = 92,
		c_Check8_Bitmap = 93,
		c_Check8_Bitmap = 94,
		c_Check9_Ctl = 95,
		c_Check9_Bitmap = 96,
		c_Check9_Bitmap = 97,
		c_ConfigAnimation = 98,
		c_Chptr_Model = 99,
		c_DuneBugy_Model = 100,
		c_Jsuser_Model = 101,
		c_Rcuser_Model = 102,
		c_CHWIND_Texture_1 = 103,
		c_CHJETL_Texture_1 = 104,
		c_CHJETR_Texture_1 = 105,
		c_Decal_Texture_1 = 106,
		c_JSFRNT_Texture_1 = 107,
		c_JSWNSH_Texture_1 = 108,
		c_RCFRNT_Texture_1 = 109,
		c_RCBACK_Texture_1 = 110,
		c_RCTAIL_Texture_1 = 111,
		c_iic006in_Wav_500 = 112,
		c_iic006in_Pho_500 = 113,
		c_iic006in_0_sfx = 114,
		c_iic006in_1_sfx = 115,
		c_iic006in_2_sfx = 116,
		c_iic006in_3_sfx = 117,
		c_iic006in_Anim = 118,
		c_IIC010IN_Wav_501 = 119,
		c_IIC010IN_Pho_501 = 120,
		c_iic010in_0_sfx = 121,
		c_iic010in_1_sfx = 122,
		c_iic010in_2_sfx = 123,
		c_iic010in_3_sfx = 124,
		c_iic010in_4_sfx = 125,
		c_iic010in_5_sfx = 126,
		c_iic010in_6_sfx = 127,
		c_iic010in_7_sfx = 128,
		c_iic010in_8_sfx = 129,
		c_iic010in_9_sfx = 130,
		c_iic010in_Anim = 131,
		c_IIC012IN_Wav_502 = 132,
		c_IIC012IN_Pho_502 = 133,
		c_iic012in_0_sfx = 134,
		c_iic012in_1_sfx = 135,
		c_iic012in_2_sfx = 136,
		c_iic012in_3_sfx = 137,
		c_iic012in_4_sfx = 138,
		c_iic012in_5_sfx = 139,
		c_iic012in_6_sfx = 140,
		c_iic012in_7_sfx = 141,
		c_iic012in_Anim = 142,
		c_iic014in_Wav_503 = 143,
		c_iic014in_Pho_503 = 144,
		c_iic014in_0_sfx = 145,
		c_iic014in_1_sfx = 146,
		c_iic014in_2_sfx = 147,
		c_iic014in_3_sfx = 148,
		c_iic014in_4_sfx = 149,
		c_iic014in_5_sfx = 150,
		c_iic014in_6_sfx = 151,
		c_iic014in_7_sfx = 152,
		c_iic014in_8_sfx = 153,
		c_iic014in_Anim = 154,

		c_iic006in_RunAnim = 500,
		c_iic010in_RunAnim = 501,
		c_iic012in_RunAnim = 502,
		c_iic014in_RunAnim = 503,
		c_iic009in_PlayWav = 504,
		c_iic007in_PlayWav = 505,
		c_iic008in_PlayWav = 506
	};
};

#endif // REGBOOK_ACTIONS_H
