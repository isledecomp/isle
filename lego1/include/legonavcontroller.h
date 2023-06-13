#ifndef LEGONAVCONTROLLER_H
#define LEGONAVCONTROLLER_H

class LegoNavController
{
public:
  __declspec(dllexport) static void GetDefaults(int *,float *,float *,float *,float *,float *,float *,float *,float *,float *,unsigned char *);
  __declspec(dllexport) static void SetDefaults(int,float,float,float,float,float,float,float,float,float,unsigned char);
};

#endif // LEGONAVCONTROLLER_H
