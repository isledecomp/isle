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
    WIDE_VIEW_ANGLE = 0x40,
    UNKNOWN3 = 0x80
  };

  enum HighFlags
  {
    UNKNOWN1 = 0x1,
    UNKNOWN2 = 0x2
  };

  __declspec(dllexport) MxVideoParamFlags();

  inline void EnableFullScreen(BOOL e)
  {
    m_flags1 = (m_flags1 ^ (e << 0)) & FULL_SCREEN ^ m_flags1;
  }

  inline void EnableFlipSurfaces(BOOL e)
  {
    m_flags1 = (m_flags1 ^ (e << 1)) & FLIP_SURFACES ^ m_flags1;
  }

  inline void EnableBackBuffers(BOOL e)
  {
    m_flags1 = (m_flags1 ^ ((!e) << 2)) & BACK_BUFFERS ^ m_flags1;
  }

  inline void SetUnknown3(BOOL e)
  {
    m_flags1 = (m_flags1 ^ (e << 7)) & UNKNOWN3 ^ m_flags1;
  }

  inline void Set8Bit()
  {
    m_flags1 &= ~ENABLE_16BIT;
  }

  inline void Set16Bit()
  {
    m_flags1 |= ENABLE_16BIT;
  }

  inline void Enable16Bit(unsigned char e)
  {
    m_flags1 = ((e << 5) ^ m_flags1) & ENABLE_16BIT ^ m_flags1;
  }

  inline void EnableWideViewAngle(BOOL e)
  {
    m_flags1 = (m_flags1 ^ (e << 6)) & WIDE_VIEW_ANGLE ^ m_flags1;
  }

  inline void EnableUnknown1(BOOL e)
  {
    m_flags2 = (m_flags2 ^ ((!e) << 0)) & UNKNOWN1 ^ m_flags2;
  }

  inline void EnableUnknown2(BOOL e)
  {
    m_flags2 = (m_flags2 ^ (e << 1)) & UNKNOWN2 ^ m_flags2;
  }

  inline void EnableUnknown2()
  {
    m_flags2 |= UNKNOWN2;
  }

private:
  unsigned char m_flags1;
  unsigned char m_flags2;

};

#endif // MXVIDEOPARAMFLAGS_H
