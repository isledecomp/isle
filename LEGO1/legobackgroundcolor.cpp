#include "legobackgroundcolor.h"

#include "legoomni.h"
#include "legoutil.h"
#include "legovideomanager.h"

const char *delimiter = "\t";
const char *set = "set";
const char *reset = "reset";

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
  char *colorStringSplit = strtok(colorStringCopy, delimiter);

  if (!strcmp(colorStringSplit, set)) {
    colorStringSplit = strtok(0, delimiter);
    if (colorStringSplit)
      h = (float) (atoi(colorStringSplit) * 0.01);
    colorStringSplit = strtok(0, delimiter);
    if (colorStringSplit)
      s = (float) (atoi(colorStringSplit) * 0.01);
    colorStringSplit = strtok(0, delimiter);
    if (colorStringSplit)
      v = (float) (atoi(colorStringSplit) * 0.01);

    ConvertHSVToRGB(this->h, this->s, this->v, &converted_r, &converted_g, &converted_b);
    videomanager->SetSkyColor(converted_r, converted_g, converted_b);
  }
  else if (!strcmp(colorStringSplit, reset)) {
    ConvertHSVToRGB(this->h, this->s, this->v, &converted_r, &converted_g, &converted_b);
    videomanager->SetSkyColor(converted_r, converted_g, converted_b);
  }

  delete[] colorStringCopy;
}