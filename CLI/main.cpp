#include "stdio.h"
#include "string.h"
#include "stdlib.h"

#include "legogamestate.h"
#include "legoomni.h"
#include "infocenterstate.h"

void saveTo(char* arg)
{
  if (GameState()->Save(atoi(arg)) == FAILURE)
  {
    printf("Failed to save to slot %s\n", arg);
    exit(1);
  }
}

void loadFrom(char* arg)
{
  if (GameState()->Load(atoi(arg)) == FAILURE)
  {
    printf("Failed to load from slot %s\n", arg);
    exit(1);
  }
}

void printHelp()
{
  printf("LEGO Island save data testing CLI. Uses the parts of the decomp completed so\n");
  printf("far to save, load, and inspect \".GS\" save data files.\n\n");
  printf("Usage: cli.exe <command>\n");
  printf("Commands:\n");
  printf("  save <slotn>\n");
  printf("  load <slotn>\n");
}

int main(int argc, char* argv[])
{
  LegoOmni::CreateInstance();
  MxOmniCreateParam omniCreateParam(argv[0], NULL, MxVideoParam(), MxOmniCreateFlags());
  Lego()->Create(omniCreateParam);
  // Saving will only proceed if this is set
  InfocenterState *state = (InfocenterState *)GameState()->CreateState("InfocenterState");
  state->SetSomething(0, 1);
  for (int argn = 1; argn < argc; ++argn) {
    char* arg = argv[argn];
    if (!strcmp(arg, "save"))
    {
      if (argn + 1 >= argc)
      {
        printf("Missing argument for save\n");
        exit(1);
      }
      saveTo(argv[++argn]);
    }
    else if (!strcmp(arg, "load"))
    {
      if (argn + 1 >= argc)
      {
        printf("Missing argument for load\n");
        exit(1);
      }
      loadFrom(argv[++argn]);
    }
    else if (!strcmp(arg, "help"))
    {
      printHelp();
    }
    else
    {
      printf("Unknown command `%s`", arg);
      printHelp();
      exit(1);
    }
  }
  if (argc == 1)
  {
    printHelp();
  }
  return 0;
}