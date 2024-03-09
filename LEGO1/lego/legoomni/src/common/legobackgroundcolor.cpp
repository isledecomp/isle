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

// STUB: LEGO1 0x1003c400
void LegoBackgroundColor::SetLights(float p_r, float p_g, float p_b)
{
}

// FUNCTION: LEGO1 0x1003c4b0
void LegoBackgroundColor::SetLights()
{
	float convertedR, convertedG, convertedB;
	ConvertHSVToRGB(m_h, m_s, m_v, &convertedR, &convertedG, &convertedB);
	SetLights(convertedR, convertedG, convertedB);
}
