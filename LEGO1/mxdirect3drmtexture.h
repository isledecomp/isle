
#include "mxdirect3drmobject.h"

// No vtable, this is just a simple wrapper around D3DRMIMAGE
class MxD3DRMIMAGE
{
public:
  struct PaletteEntry
  {
    unsigned char r;
    unsigned char g;
    unsigned char b;
  };

  MxD3DRMIMAGE(int p_width, int p_height, int p_depth, void *p_buffer, int p_useBuffer, int p_paletteSize, PaletteEntry *p_palette);
  ~MxD3DRMIMAGE() { Destroy(); }
  
  int CreateBuffer(int p_width, int p_height, int p_depth, void *p_buffer, int p_useBuffer);
  void Destroy();
  void FillRowsOfTexture(int p_y, int p_height, char *p_content);
  int InitializePalette(int p_paletteSize, PaletteEntry *p_palette);

  D3DRMIMAGE m_image;
  int m_extra;
};

// VTABLE 0x100dbb68
class IMxDirect3DRMTexture : public IMxDirect3DRMObject
{
public:
  virtual ~IMxDirect3DRMTexture() {}

  virtual IUnknown **GetHandle() = 0;

  // vtable+0x08
  virtual int SetBuffer(int p_width, int p_height, int p_depth, void *p_buffer) = 0;
  virtual void FillRowsOfTexture(int p_y, int p_height, void *p_buffer) = 0;

  // vtable+0x10
  virtual int Changed(int p_pixelsChanged, int p_paletteChanged) = 0;
  virtual int GetBufferAndPalette(int *p_width, int *p_height, int *p_depth, void **p_buffer, int *p_paletteSize, MxD3DRMIMAGE::PaletteEntry **p_palette) = 0;
  virtual int InitializePalette(int p_paletteSize, MxD3DRMIMAGE::PaletteEntry *p_palette) = 0;
};

// VTABLE 0x100dbb48
class MxDirect3DRMTexture : public IMxDirect3DRMTexture
{
public:
  MxDirect3DRMTexture() {}
  virtual ~MxDirect3DRMTexture() {}

  virtual IUnknown **GetHandle();

  // vtable+0x08
  virtual int SetBuffer(int p_width, int p_height, int p_depth, void *p_buffer);
  virtual void FillRowsOfTexture(int p_y, int p_height, void *p_buffer);

  // vtable+0x10
  virtual int Changed(int p_pixelsChanged, int p_paletteChanged);
  virtual int GetBufferAndPalette(int *p_width, int *p_height, int *p_depth, void **p_buffer, int *p_paletteSize, MxD3DRMIMAGE::PaletteEntry **p_palette);
  virtual int InitializePalette(int p_paletteSize, MxD3DRMIMAGE::PaletteEntry *p_palette);

  // Not virtual
  void OnDestroyed();

private:
  inline MxD3DRMIMAGE *GetImageData()
  {
    return (MxD3DRMIMAGE*)m_pDirect3DRMTexture->GetAppData();
  }

  IDirect3DRMTexture *m_pDirect3DRMTexture;
};
