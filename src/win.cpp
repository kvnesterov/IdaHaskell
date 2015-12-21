#include "win.h"
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void addDLLHandle(wchar_t *, HINSTANCE);

#ifdef __cplusplus
}
#endif

void add_plugin_dll(){
  //TODO Add check?
  HMODULE hMod = GetModuleHandle("IdaHaskell.plw");
  addDLLHandle(L"IdaHaskell", hMod);
  hMod = GetModuleHandle("ida.wll");
  addDLLHandle(L"ida", hMod);
}
