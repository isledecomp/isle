#include "legofullscreenmovie.h"
#include "mxtypes.h"
#include "legoomni.h"
#include "decomp.h"

DECOMP_SIZE_ASSERT(LegoFullScreenMovie, 0x24)

// 0x100f3be8
const char *g_str_enable = "enable";

// 0x100f3bf4
const char *g_str_disable = "disable";

// OFFSET: LEGO1 0x1003c500
LegoFullScreenMovie::LegoFullScreenMovie(const char *p_key, const char *p_value)
{
  m_key = p_key;
  m_key.ToUpperCase();
  SetValue(p_value);
}

// OFFSET: LEGO1 0x1003c5c0
void LegoFullScreenMovie::SetValue(const char *p_option)
{
  m_value = p_option;
  m_value.ToLowerCase();

  LegoVideoManager *videomanager = VideoManager();
  if (videomanager) {

    if (!strcmp(m_value.GetData(), g_str_enable)) {
      videomanager->EnableFullScreenMovie(TRUE);
      return;
    }

    if (!strcmp(m_value.GetData(), g_str_disable)) {
      videomanager->EnableFullScreenMovie(FALSE);
      return;
    }
  }
}
