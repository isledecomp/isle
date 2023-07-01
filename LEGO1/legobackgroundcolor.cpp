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
  m_name = colorString;
  m_string.ToLowerCase();

  float converted_r;
  float converted_b;
  float converted_g;
  LegoVideoManager *videomanager = VideoManager();

  if (videomanager && colorString)
  {
    int length = strlen(colorString) + 1;
    char *colorStringCopy = new char[length];
    strcpy(colorStringCopy, colorString);
    char *colorStringSplit = strtok(colorStringCopy, Delimiter);
    if (!strcmp(colorStringSplit, set))
    {
      char *hue = strtok(0, Delimiter);
      if (hue)
        h = atoi(hue) * 0.01;
      char *sat = strtok(0, Delimiter);
      if (sat)
        s = atoi(sat) * 0.01;
      char *val = strtok(0, Delimiter);
      if (val)
        v = atoi(val) * 0.01;
    }
    else if (!strcmp(colorStringSplit, reset))
    {
      // reset it
      ConvertHSVToRGB(this->h, this->s, this->v, &converted_r, &converted_g, &converted_b);
      videomanager->SetSkyColor(converted_r, converted_g, converted_b);
    }
    delete[] colorStringCopy;
  }
}
