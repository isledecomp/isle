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
  this->m_name.operator=(name);
  this->m_name.ToUpperCase();
  SetColorString(colorString);
}

// OFFSET: LEGO1 0x1003c070
void LegoBackgroundColor::SetColorString(const char *colorString)
{

  m_colorString.operator=(colorString);
  m_colorString.ToLowerCase();

  float converted_r;
  float converted_b;
  float converted_g;
  LegoVideoManager *videomanager = VideoManager();

  if (videomanager && colorString)
  {
    int length = strlen(colorString) + 1;
    char *colorStringCopy = (char *)malloc(length);
    strcpy(colorStringCopy, colorString);
    char *colorStringSplit = strtok(colorStringCopy, Delimiter);
    if (!strcmp(colorStringSplit, set))
    {
      //TODO: the names of these variables are incorrect as I can't figure out what color format ConvertColor() uses
      char *blue = strtok(0, Delimiter);
      if (blue)
        b = atoi(blue) * 0.01;
      char *green = strtok(0, Delimiter);
      if (green)
        g = atoi(green) * 0.01;
      char *red = strtok(0, Delimiter);
      if (red)
        r = atoi(red) * 0.01;
    }
    else if (!strcmp(colorStringSplit, reset))
    {
      // reset it

      ConvertColor(this->b, this->g, this->r, &converted_r, &converted_g, &converted_b);
      videomanager->SetSkyColor(converted_r, converted_g, converted_b);
    }
    free(colorStringCopy);
  }
}