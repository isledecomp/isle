#include "legobackgroundcolor.h"

#include "legoomni.h"
#include "legoutil.h"
#include "legovideomanager.h"

const char *g_delimiter = "\t";
const char *g_set = "set";
const char *g_reset = "reset";

// OFFSET: LEGO1 0x1003bfb0
LegoBackgroundColor::LegoBackgroundColor(const char *p_name, const char *p_colorString)
{
  m_name = p_name;
  m_name.ToUpperCase();
  SetColorString(p_colorString);
}

// OFFSET: LEGO1 0x1003c070
void LegoBackgroundColor::SetColorString(const char *p_colorString)
{
  m_string = p_colorString;
  m_string.ToLowerCase();

  LegoVideoManager *videomanager = VideoManager();
  if (!videomanager || !p_colorString)
    return;

  float converted_r, converted_g, converted_b;
  char *colorStringCopy = strcpy(new char[strlen(p_colorString) + 1], p_colorString);
  char *colorStringSplit = strtok(colorStringCopy, g_delimiter);

  if (!strcmp(colorStringSplit, g_set)) {
    colorStringSplit = strtok(0, g_delimiter);
    if (colorStringSplit)
      h = (float) (atoi(colorStringSplit) * 0.01);
    colorStringSplit = strtok(0, g_delimiter);
    if (colorStringSplit)
      s = (float) (atoi(colorStringSplit) * 0.01);
    colorStringSplit = strtok(0, g_delimiter);
    if (colorStringSplit)
      v = (float) (atoi(colorStringSplit) * 0.01);

    ConvertHSVToRGB(this->h, this->s, this->v, &converted_r, &converted_g, &converted_b);
    videomanager->SetSkyColor(converted_r, converted_g, converted_b);
  }
  else if (!strcmp(colorStringSplit, g_reset)) {
    ConvertHSVToRGB(this->h, this->s, this->v, &converted_r, &converted_g, &converted_b);
    videomanager->SetSkyColor(converted_r, converted_g, converted_b);
  }

  delete[] colorStringCopy;
}
