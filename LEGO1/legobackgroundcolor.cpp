#include "legobackgroundcolor.h"

#include "legoomni.h"
#include "legoutil.h"
#include "legovideomanager.h"

const char *Delimiter = "\t";
const char *set = "set";
const char *reset = "reset";

// OFFSET: LEGO1 0x1003bfb0
LegoBackgroundColor::LegoBackgroundColor(const char *name, const char *colorString)
{
  m_name = name;
  m_name.ToUpperCase();
  SetColorString(colorString);
}

// OFFSET: LEGO1 0x1003c070
void LegoBackgroundColor::SetColorString(const char *colorString)
{
  m_string = colorString;
  m_string.ToLowerCase();

  LegoVideoManager *videomanager = VideoManager();
  if (!videomanager || !colorString)
    return;

  float converted_r, converted_g, converted_b;
  char *colorStringCopy = strcpy(new char[strlen(colorString) + 1], colorString);
  char *colorStringSplit = strtok(colorStringCopy, Delimiter);

  if (!strcmp(colorStringSplit, set)) {
    colorStringSplit = strtok(0, Delimiter);
    if (colorStringSplit)
      h = atoi(colorStringSplit) * 0.01;
    colorStringSplit = strtok(0, Delimiter);
    if (colorStringSplit)
      s = atoi(colorStringSplit) * 0.01;
    colorStringSplit = strtok(0, Delimiter);
    if (colorStringSplit)
      v = atoi(colorStringSplit) * 0.01;

    ConvertHSVToRGB(this->h, this->s, this->v, &converted_r, &converted_g, &converted_b);
    videomanager->SetSkyColor(converted_r, converted_g, converted_b);
  }
  else if (!strcmp(colorStringSplit, reset)) {
    ConvertHSVToRGB(this->h, this->s, this->v, &converted_r, &converted_g, &converted_b);
    videomanager->SetSkyColor(converted_r, converted_g, converted_b);
  }

  delete[] colorStringCopy;
}