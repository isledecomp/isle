#ifndef MXDSFILE_H
#define MXDSFILE_H

class MxDSFile
{
public:
  __declspec(dllexport) MxDSFile(const char *,unsigned long);
  __declspec(dllexport) virtual ~MxDSFile();
  __declspec(dllexport) virtual long Close();
  __declspec(dllexport) virtual unsigned long GetBufferSize();
  __declspec(dllexport) virtual unsigned long GetStreamBuffersNum();
  __declspec(dllexport) virtual long Open(unsigned long);
  __declspec(dllexport) virtual long Read(unsigned char *,unsigned long);
  __declspec(dllexport) virtual long Seek(long,int);
private:
  char m_unknown[0x70];
  unsigned long m_buffersize;
};

#endif // MXDSFILE_H
