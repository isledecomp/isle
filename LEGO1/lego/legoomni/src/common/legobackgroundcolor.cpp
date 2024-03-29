#include "legobackgroundcolor.h"

#include "decomp.h"
#include "legoutils.h"
#include "legovideomanager.h"
#include "misc.h"

DECOMP_SIZE_ASSERT(LegoBackgroundColor, 0x30)

// GLOBAL: LEGO1 0x100f3fb0
// STRING: LEGO1 0x100f3a18
const char* g_delimiter = " \t";

// GLOBAL: LEGO1 0x100f3fb4
// STRING: LEGO1 0x100f3bf0
const char* g_set = "set";

// GLOBAL: LEGO1 0x100f3fb8
// STRING: LEGO1 0x100f0cdc
const char* g_reset = "reset";

// FUNCTION: LEGO1 0x1003bfb0
LegoBackgroundColor::LegoBackgroundColor(const char* p_key, const char* p_value)
{
	m_key = p_key;
	m_key.ToUpperCase();
	SetValue(p_value);
}

// FUNCTION: LEGO1 0x1003c070
void LegoBackgroundColor::SetValue(const char* p_colorString)
{
	m_value = p_colorString;
	m_value.ToLowerCase();

	LegoVideoManager* videomanager = VideoManager();
	if (!videomanager || !p_colorString) {
		return;
	}

	float convertedR, convertedG, convertedB;
	char* colorStringCopy = strcpy(new char[strlen(p_colorString) + 1], p_colorString);
	char* colorStringSplit = strtok(colorStringCopy, g_delimiter);

	if (!strcmp(colorStringSplit, g_set)) {
		colorStringSplit = strtok(0, g_delimiter);
		if (colorStringSplit) {
			m_h = (float) (atoi(colorStringSplit) * 0.01);
		}
		colorStringSplit = strtok(0, g_delimiter);
		if (colorStringSplit) {
			m_s = (float) (atoi(colorStringSplit) * 0.01);
		}
		colorStringSplit = strtok(0, g_delimiter);
		if (colorStringSplit) {
			m_v = (float) (atoi(colorStringSplit) * 0.01);
		}

		ConvertHSVToRGB(m_h, m_s, m_v, &convertedR, &convertedG, &convertedB);
		videomanager->SetSkyColor(convertedR, convertedG, convertedB);
	}
	else if (!strcmp(colorStringSplit, g_reset)) {
		ConvertHSVToRGB(m_h, m_s, m_v, &convertedR, &convertedG, &convertedB);
		videomanager->SetSkyColor(convertedR, convertedG, convertedB);
	}

	delete[] colorStringCopy;
}

// FUNCTION: LEGO1 0x1003c230
void LegoBackgroundColor::ToggleDayNight(MxBool p_sun)
{
	char buffer[30];

	if (p_sun) {
		m_s += 0.1;
		if (m_s > 0.9) {
			m_s = 1.0;
		}
	}
	else {
		m_s -= 0.1;
		if (m_s < 0.1) {
			m_s = 0.1;
		}
	}

	sprintf(buffer, "set %d %d %d", (MxU32) (m_h * 100.0f), (MxU32) (m_s * 100.0f), (MxU32) (m_v * 100.0f));
	m_value = buffer;

	float convertedR, convertedG, convertedB;
	ConvertHSVToRGB(m_h, m_s, m_v, &convertedR, &convertedG, &convertedB);
	VideoManager()->SetSkyColor(convertedR, convertedG, convertedB);
	SetLightColor(convertedR, convertedG, convertedB);
}

// FUNCTION: LEGO1 0x1003c330
void LegoBackgroundColor::ToggleSkyColor()
{
	char buffer[30];

	m_h += 0.05;
	if (m_h > 1.0) {
		m_h -= 1.0;
	}

	sprintf(buffer, "set %d %d %d", (MxU32) (m_h * 100.0f), (MxU32) (m_s * 100.0f), (MxU32) (m_v * 100.0f));
	m_value = buffer;

	float convertedR, convertedG, convertedB;
	ConvertHSVToRGB(m_h, m_s, m_v, &convertedR, &convertedG, &convertedB);
	VideoManager()->SetSkyColor(convertedR, convertedG, convertedB);
	SetLightColor(convertedR, convertedG, convertedB);
}

// FUNCTION: LEGO1 0x1003c400
void LegoBackgroundColor::SetLightColor(float p_r, float p_g, float p_b)
{
	if (!VideoManager()->GetVideoParam().Flags().GetF2bit0()) {
		// TODO: Computed constants based on what?
		p_r *= 4.3478260869565215;
		p_g *= 1.5873015873015872;
		p_b *= 1.1764705882352942;

		if (p_r > 1.0) {
			p_r = 1.0;
		}

		if (p_g > 1.0) {
			p_g = 1.0;
		}

		if (p_b > 1.0) {
			p_b = 1.0;
		}

		VideoManager()->Get3DManager()->GetLego3DView()->SetLightColor(FALSE, p_r, p_g, p_b);
		VideoManager()->Get3DManager()->GetLego3DView()->SetLightColor(TRUE, p_r, p_g, p_b);
	}
}

// FUNCTION: LEGO1 0x1003c4b0
void LegoBackgroundColor::SetLightColor()
{
	float convertedR, convertedG, convertedB;
	ConvertHSVToRGB(m_h, m_s, m_v, &convertedR, &convertedG, &convertedB);
	SetLightColor(convertedR, convertedG, convertedB);
}
