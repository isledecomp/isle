#include "mxpalette.h"

#include "mxomni.h"
#include "mxvideomanager.h"

// GLOBAL: LEGO1 0x10102188
PALETTEENTRY g_defaultPaletteEntries[256] = {
	{0u, 0u, 0u, 0u},       {128u, 0u, 0u, 0u},     {0u, 128u, 0u, 0u},     {128u, 128u, 0u, 0u},
	{0u, 0u, 128u, 0u},     {128u, 0u, 128u, 0u},   {0u, 128u, 128u, 0u},   {128u, 128u, 128u, 0u},
	{192u, 220u, 192u, 0u}, {166u, 202u, 240u, 0u}, {255u, 255u, 255u, 0u}, {250u, 250u, 250u, 0u},
	{239u, 239u, 239u, 0u}, {228u, 228u, 228u, 0u}, {217u, 217u, 217u, 0u}, {206u, 206u, 206u, 0u},
	{195u, 195u, 195u, 0u}, {185u, 185u, 185u, 0u}, {174u, 174u, 174u, 0u}, {163u, 163u, 163u, 0u},
	{152u, 152u, 152u, 0u}, {141u, 141u, 141u, 0u}, {130u, 130u, 130u, 0u}, {123u, 123u, 123u, 0u},
	{115u, 115u, 115u, 0u}, {108u, 108u, 108u, 0u}, {101u, 101u, 101u, 0u}, {93u, 93u, 93u, 0u},
	{86u, 86u, 86u, 0u},    {79u, 79u, 79u, 0u},    {71u, 71u, 71u, 0u},    {64u, 64u, 64u, 0u},
	{54u, 54u, 54u, 0u},    {43u, 43u, 43u, 0u},    {33u, 33u, 33u, 0u},    {22u, 22u, 22u, 0u},
	{12u, 12u, 12u, 0u},    {8u, 8u, 8u, 0u},       {4u, 4u, 4u, 0u},       {0u, 0u, 0u, 0u},
	{225u, 218u, 217u, 0u}, {195u, 182u, 179u, 0u}, {165u, 145u, 141u, 0u}, {134u, 108u, 102u, 0u},
	{104u, 72u, 64u, 0u},   {74u, 35u, 26u, 0u},    {59u, 28u, 21u, 0u},    {44u, 21u, 16u, 0u},
	{30u, 14u, 10u, 0u},    {15u, 7u, 5u, 0u},      {250u, 231u, 232u, 0u}, {240u, 185u, 189u, 0u},
	{233u, 154u, 160u, 0u}, {226u, 124u, 131u, 0u}, {219u, 93u, 102u, 0u},  {213u, 62u, 73u, 0u},
	{203u, 18u, 32u, 0u},   {172u, 15u, 27u, 0u},   {159u, 14u, 25u, 0u},   {146u, 13u, 23u, 0u},
	{133u, 12u, 21u, 0u},   {120u, 11u, 19u, 0u},   {107u, 10u, 17u, 0u},   {94u, 8u, 15u, 0u},
	{81u, 7u, 13u, 0u},     {68u, 6u, 11u, 0u},     {55u, 5u, 9u, 0u},      {42u, 4u, 7u, 0u},
	{29u, 3u, 5u, 0u},      {10u, 1u, 2u, 0u},      {227u, 236u, 242u, 0u}, {178u, 203u, 220u, 0u},
	{145u, 181u, 205u, 0u}, {112u, 159u, 191u, 0u}, {79u, 137u, 176u, 0u},  {30u, 104u, 154u, 0u},
	{0u, 84u, 140u, 0u},    {0u, 79u, 132u, 0u},    {0u, 72u, 119u, 0u},    {0u, 66u, 110u, 0u},
	{0u, 61u, 101u, 0u},    {0u, 55u, 92u, 0u},     {0u, 47u, 78u, 0u},     {0u, 39u, 65u, 0u},
	{0u, 34u, 56u, 0u},     {0u, 28u, 47u, 0u},     {0u, 23u, 38u, 0u},     {0u, 18u, 29u, 0u},
	{0u, 12u, 20u, 0u},     {0u, 4u, 7u, 0u},       {230u, 242u, 234u, 0u}, {180u, 215u, 193u, 0u},
	{147u, 198u, 166u, 0u}, {113u, 180u, 138u, 0u}, {80u, 162u, 111u, 0u},  {30u, 136u, 70u, 0u},
	{0u, 120u, 45u, 0u},    {0u, 114u, 43u, 0u},    {0u, 102u, 38u, 0u},    {0u, 95u, 35u, 0u},
	{0u, 83u, 31u, 0u},     {0u, 72u, 27u, 0u},     {0u, 63u, 24u, 0u},     {0u, 56u, 21u, 0u},
	{0u, 48u, 18u, 0u},     {0u, 36u, 14u, 0u},     {0u, 25u, 9u, 0u},      {0u, 17u, 6u, 0u},
	{0u, 9u, 3u, 0u},       {0u, 1u, 1u, 0u},       {254u, 244u, 220u, 0u}, {255u, 239u, 181u, 0u},
	{255u, 231u, 156u, 0u}, {255u, 222u, 132u, 0u}, {255u, 222u, 115u, 0u}, {255u, 214u, 99u, 0u},
	{255u, 206u, 66u, 0u},  {255u, 198u, 41u, 0u},  {255u, 185u, 0u, 0u},   {255u, 189u, 8u, 0u},
	{247u, 181u, 0u, 0u},   {222u, 156u, 0u, 0u},   {189u, 140u, 0u, 0u},   {173u, 123u, 0u, 0u},
	{148u, 107u, 0u, 0u},   {132u, 90u, 0u, 0u},    {107u, 74u, 0u, 0u},    {74u, 49u, 0u, 0u},
	{57u, 41u, 0u, 0u},     {33u, 24u, 0u, 0u},     {117u, 52u, 87u, 0u},   {176u, 158u, 50u, 0u},
	{122u, 165u, 29u, 0u},  {242u, 142u, 8u, 0u},   {164u, 43u, 36u, 0u},   {113u, 67u, 20u, 0u},
	{255u, 0u, 255u, 0u},   {255u, 0u, 255u, 0u},   {255u, 0u, 255u, 0u},   {255u, 0u, 255u, 0u},
	{255u, 0u, 255u, 0u},   {57u, 163u, 217u, 0u},  {255u, 255u, 255u, 0u}, {254u, 255u, 247u, 0u},
	{253u, 253u, 239u, 0u}, {248u, 247u, 247u, 0u}, {248u, 247u, 231u, 0u}, {240u, 240u, 240u, 0u},
	{239u, 239u, 218u, 0u}, {227u, 232u, 236u, 0u}, {224u, 221u, 209u, 0u}, {215u, 222u, 215u, 0u},
	{213u, 214u, 215u, 0u}, {214u, 214u, 203u, 0u}, {255u, 219u, 57u, 0u},  {206u, 206u, 206u, 0u},
	{206u, 206u, 198u, 0u}, {255u, 214u, 18u, 0u},  {207u, 203u, 186u, 0u}, {197u, 199u, 199u, 0u},
	{255u, 206u, 0u, 0u},   {207u, 198u, 159u, 0u}, {247u, 204u, 0u, 0u},   {189u, 198u, 189u, 0u},
	{189u, 189u, 189u, 0u}, {238u, 199u, 0u, 0u},   {189u, 189u, 181u, 0u}, {238u, 190u, 24u, 0u},
	{181u, 189u, 184u, 0u}, {161u, 186u, 224u, 0u}, {181u, 181u, 181u, 0u}, {231u, 189u, 0u, 0u},
	{173u, 182u, 173u, 0u}, {222u, 181u, 0u, 0u},   {173u, 173u, 173u, 0u}, {213u, 182u, 0u, 0u},
	{172u, 173u, 160u, 0u}, {214u, 173u, 0u, 0u},   {165u, 165u, 165u, 0u}, {206u, 173u, 0u, 0u},
	{160u, 168u, 151u, 0u}, {206u, 164u, 0u, 0u},   {198u, 165u, 0u, 0u},   {157u, 156u, 156u, 0u},
	{134u, 156u, 200u, 0u}, {153u, 156u, 144u, 0u}, {142u, 156u, 161u, 0u}, {189u, 156u, 0u, 0u},
	{148u, 148u, 148u, 0u}, {146u, 148u, 138u, 0u}, {133u, 143u, 161u, 0u}, {189u, 143u, 0u, 0u},
	{140u, 140u, 140u, 0u}, {177u, 147u, 0u, 0u},   {131u, 140u, 136u, 0u}, {146u, 130u, 126u, 0u},
	{170u, 137u, 0u, 0u},   {132u, 132u, 130u, 0u}, {123u, 125u, 125u, 0u}, {123u, 123u, 133u, 0u},
	{153u, 126u, 0u, 0u},   {114u, 116u, 118u, 0u}, {110u, 112u, 108u, 0u}, {97u, 109u, 136u, 0u},
	{127u, 108u, 6u, 0u},   {0u, 173u, 0u, 0u},     {100u, 99u, 101u, 0u},  {176u, 71u, 41u, 0u},
	{36u, 142u, 33u, 0u},   {98u, 91u, 75u, 0u},    {80u, 88u, 104u, 0u},   {252u, 0u, 0u, 0u},
	{78u, 71u, 73u, 0u},    {73u, 71u, 78u, 0u},    {62u, 63u, 61u, 0u},    {0u, 66u, 211u, 0u},
	{99u, 51u, 14u, 0u},    {198u, 0u, 0u, 0u},     {189u, 0u, 0u, 0u},     {0u, 57u, 206u, 0u},
	{181u, 0u, 0u, 0u},     {0u, 56u, 185u, 0u},    {173u, 0u, 0u, 0u},     {165u, 0u, 0u, 0u},
	{49u, 49u, 49u, 0u},    {0u, 49u, 165u, 0u},    {156u, 0u, 0u, 0u},     {42u, 45u, 60u, 0u},
	{148u, 0u, 0u, 0u},     {140u, 0u, 0u, 0u},     {41u, 41u, 41u, 0u},    {0u, 41u, 144u, 0u},
	{132u, 0u, 0u, 0u},     {123u, 0u, 0u, 0u},     {7u, 35u, 114u, 0u},    {34u, 36u, 32u, 0u},
	{115u, 0u, 0u, 0u},     {107u, 0u, 0u, 0u},     {90u, 0u, 0u, 0u},      {23u, 24u, 27u, 0u},
	{74u, 0u, 0u, 0u},      {15u, 15u, 16u, 0u},    {49u, 0u, 0u, 0u},      {16u, 12u, 4u, 0u},
	{7u, 8u, 8u, 0u},       {0u, 0u, 8u, 0u},       {255u, 251u, 240u, 0u}, {160u, 160u, 164u, 0u},
	{128u, 128u, 128u, 0u}, {255u, 0u, 0u, 0u},     {0u, 255u, 0u, 0u},     {255u, 255u, 0u, 0u},
	{0u, 0u, 255u, 0u},     {255u, 0u, 255u, 0u},   {0u, 255u, 255u, 0u},   {255u, 255u, 255u, 0u}
};

// FUNCTION: LEGO1 0x100bee30
MxPalette::MxPalette()
{
	this->m_overrideSkyColor = FALSE;
	this->m_palette = NULL;
	GetDefaultPalette(this->m_entries);
	this->m_skyColor = this->m_entries[141];
}

// FUNCTION: LEGO1 0x100beed0
MxPalette::MxPalette(const RGBQUAD* p_colors)
{
	this->m_overrideSkyColor = FALSE;
	this->m_palette = NULL;
	ApplySystemEntriesToPalette(this->m_entries);

	for (MxS32 i = 10; i < 246; i++) {
		this->m_entries[i].peRed = p_colors[i].rgbRed;
		this->m_entries[i].peGreen = p_colors[i].rgbGreen;
		this->m_entries[i].peBlue = p_colors[i].rgbBlue;
		this->m_entries[i].peFlags = 0;
	}

	this->m_skyColor = this->m_entries[141];
}

// FUNCTION: LEGO1 0x100bef90
MxPalette::~MxPalette()
{
	if (m_palette) {
		m_palette->Release();
	}
}

// FUNCTION: LEGO1 0x100bf000
LPDIRECTDRAWPALETTE MxPalette::CreateNativePalette()
{
	MxS32 i;
	if (this->m_palette == NULL) {
		for (i = 0; i < 10; i++)
			this->m_entries[i].peFlags = 0x80;
		for (i = 10; i < 136; i++)
			this->m_entries[i].peFlags = 0x44;
		for (i = 136; i < 140; i++)
			this->m_entries[i].peFlags = 0x84;
		this->m_entries[140].peFlags = 0x84;
		this->m_entries[141].peFlags = 0x44;
		for (i = 142; i < 246; i++)
			this->m_entries[i].peFlags = 0x84;
		for (i = 246; i < 256; i++)
			this->m_entries[i].peFlags = 0x80;

		if (MVideoManager() && MVideoManager()->GetDirectDraw()) {
			MVideoManager()->GetDirectDraw()->CreatePalette(4, this->m_entries, &this->m_palette, NULL);
		}
	}

	return this->m_palette;
}

// FUNCTION: LEGO1 0x100bf0b0
MxPalette* MxPalette::Clone()
{
	MxPalette* result = new MxPalette;
	this->GetEntries(result->m_entries);
	result->m_overrideSkyColor = this->m_overrideSkyColor;
	return result;
}

// FUNCTION: LEGO1 0x100bf150
MxResult MxPalette::GetEntries(LPPALETTEENTRY p_entries)
{
	memcpy(p_entries, this->m_entries, sizeof(this->m_entries));
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100bf170
MxResult MxPalette::SetEntries(LPPALETTEENTRY p_entries)
{
	MxS32 i;
	MxResult status = SUCCESS;

	if (this->m_palette) {
		for (i = 0; i < 10; i++)
			this->m_entries[i].peFlags = 0x80;
		for (i = 10; i < 136; i++) {
			this->m_entries[i].peFlags = 68;
			this->m_entries[i].peRed = p_entries[i].peRed;
			this->m_entries[i].peGreen = p_entries[i].peGreen;
			this->m_entries[i].peBlue = p_entries[i].peBlue;
		}
		for (i = 136; i < 140; i++) {
			this->m_entries[i].peFlags = 132;
			this->m_entries[i].peRed = p_entries[i].peRed;
			this->m_entries[i].peGreen = p_entries[i].peGreen;
			this->m_entries[i].peBlue = p_entries[i].peBlue;
		}
		if (!this->m_overrideSkyColor) {
			this->m_entries[140].peFlags = 0x44;
			this->m_entries[140].peRed = p_entries[140].peRed;
			this->m_entries[140].peGreen = p_entries[140].peGreen;
			this->m_entries[140].peBlue = p_entries[140].peBlue;
			this->m_entries[141].peFlags = 0x84;
			this->m_entries[141].peRed = p_entries[141].peRed;
			this->m_entries[141].peGreen = p_entries[141].peGreen;
			this->m_entries[141].peBlue = p_entries[141].peBlue;
		}

		for (i = 142; i < 246; i++) {
			this->m_entries[i].peFlags = 132;
			this->m_entries[i].peRed = p_entries[i].peRed;
			this->m_entries[i].peGreen = p_entries[i].peGreen;
			this->m_entries[i].peBlue = p_entries[i].peBlue;
		}

		for (i = 246; i < 256; i++)
			this->m_entries[i].peFlags = 0x80;

		if (this->m_palette->SetEntries(0, 0, 256, this->m_entries))
			status = FAILURE;
	}

	return status;
}

// FUNCTION: LEGO1 0x100bf2d0
MxResult MxPalette::SetSkyColor(LPPALETTEENTRY p_skyColor)
{
	MxResult status = 0;
	if (this->m_palette != NULL) {
		this->m_entries[141].peRed = p_skyColor->peRed;
		this->m_entries[141].peGreen = p_skyColor->peGreen;
		this->m_entries[141].peBlue = p_skyColor->peBlue;
		this->m_skyColor = this->m_entries[141];
		if (this->m_palette->SetEntries(0, 141, 1, &this->m_skyColor)) {
			status = -1;
		}
	}
	return status;
}

// FUNCTION: LEGO1 0x100bf330
void MxPalette::Detach()
{
	this->m_palette = NULL;
}

// FUNCTION: LEGO1 0x100bf340
MxBool MxPalette::operator==(MxPalette& p_other)
{
	for (MxS32 i = 0; i < 256; i++) {
		if (this->m_entries[i].peRed != p_other.m_entries[i].peRed)
			return FALSE;
		if (this->m_entries[i].peGreen != p_other.m_entries[i].peGreen)
			return FALSE;
		if (this->m_entries[i].peBlue != p_other.m_entries[i].peBlue)
			return FALSE;
	}
	return TRUE;
}

// FUNCTION: LEGO1 0x100bf390
void MxPalette::ApplySystemEntriesToPalette(LPPALETTEENTRY p_entries)
{
	HDC hdc;

	hdc = GetDC(0);
	if ((GetDeviceCaps(hdc, RASTERCAPS) & RC_PALETTE) != 0 && GetDeviceCaps(hdc, SIZEPALETTE) == 256) {
		GetSystemPaletteEntries(hdc, 0, 10, p_entries);
		GetSystemPaletteEntries(hdc, 246, 10, &p_entries[246]);
	}
	else {
		memcpy(p_entries, g_defaultPaletteEntries, sizeof(PALETTEENTRY) * 10);
		memcpy(&p_entries[246], &g_defaultPaletteEntries[246], sizeof(PALETTEENTRY) * 10);
	}
	ReleaseDC(0, hdc);
}

// FUNCTION: LEGO1 0x100bf420
void MxPalette::GetDefaultPalette(LPPALETTEENTRY p_entries)
{
	HDC hdc;

	hdc = GetDC(0);
	if ((GetDeviceCaps(hdc, RASTERCAPS) & RC_PALETTE) != 0 && GetDeviceCaps(hdc, SIZEPALETTE) == 256) {
		GetSystemPaletteEntries(hdc, 0, 256, p_entries);
		memcpy(&p_entries[10], &g_defaultPaletteEntries[10], sizeof(PALETTEENTRY) * 236);
	}
	else {
		memcpy(p_entries, g_defaultPaletteEntries, sizeof(PALETTEENTRY) * 256);
	}

	ReleaseDC(0, hdc);
}

// FUNCTION: LEGO1 0x100bf490
void MxPalette::Reset(MxBool p_ignoreSkyColor)
{
	if (this->m_palette != NULL) {
		GetDefaultPalette(this->m_entries);
		if (!p_ignoreSkyColor) {
			this->m_entries[140] = this->m_entries[141] = this->m_skyColor;
		}
		SetEntries(this->m_entries);
		this->m_palette->SetEntries(0, 0, 256, this->m_entries);
	}
}
