#ifndef MXVIDEOPARAMFLAGS_H
#define MXVIDEOPARAMFLAGS_H

class MxVideoParamFlags
{
public:
  enum LowFlags
  {
    FULL_SCREEN = 0x1,
    FLIP_SURFACES = 0x2,
    BACK_BUFFERS = 0x4,
    ENABLE_16BIT = 0x20,
    WIDE_VIEW_ANGLE = 0x40
  };

  enum HighFlags
  {
    UNKNOWN1 = 0x1,
    UNKNOWN2 = 0x2
  };

  __declspec(dllexport) MxVideoParamFlags();

  inline void EnableFullScreen(BOOL e)
  {
    if (e) {
      m_flags1 |= FULL_SCREEN;
    } else {
      m_flags1 &= ~FULL_SCREEN;
    }
  }

  inline void EnableFlipSurfaces(BOOL e)
  {
    if (e) {
      m_flags1 |= FLIP_SURFACES;
    } else {
      m_flags1 &= ~FLIP_SURFACES;
    }
  }

  inline void EnableBackBuffers(BOOL e)
  {
    if (e) {
      m_flags1 |= BACK_BUFFERS;
    } else {
      m_flags1 &= ~BACK_BUFFERS;
    }
  }

  inline void Enable16Bit(BOOL e)
  {
    if (e) {
      m_flags1 |= ENABLE_16BIT;
    } else {
      m_flags1 &= ~ENABLE_16BIT;
    }
  }

  inline void EnableWideViewAngle(BOOL e)
  {
    if (e) {
      m_flags1 |= WIDE_VIEW_ANGLE;
    } else {
      m_flags1 &= ~WIDE_VIEW_ANGLE;
    }
  }

  inline void EnableUnknown1(BOOL e)
  {
    if (e) {
      m_flags2 |= UNKNOWN1;
    } else {
      m_flags2 &= ~UNKNOWN1;
    }
  }

  inline void EnableUnknown2(BOOL e)
  {
    if (e) {
      m_flags2 |= UNKNOWN2;
    } else {
      m_flags2 &= ~UNKNOWN2;
    }
  }

private:
  unsigned char m_flags1;
  unsigned char m_flags2;

};

#endif // MXVIDEOPARAMFLAGS_H
