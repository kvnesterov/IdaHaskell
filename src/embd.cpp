#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include "Ida_stub.h"

#ifdef __NT__
#include "win.h"
#endif

bool idaapi c_cli_execute_line(const char *line);

static const cli_t cli_haskell =
  {
    sizeof(cli_t),
    0,
    "Haskell",
    "Haskell - IDAHaskell plugin",
    "Enter any haskell expression",
    c_cli_execute_line,
    // h_cli_complete_line,
    NULL,
    NULL
  };

bool idaapi c_cli_execute_line(const char *line){
  // msg("c_cli_execute_line\n");
  h_cli_execute_line((void*)line);
  return true;
}

int __stdcall IDAP_init(void)
{
  char * p = NULL;
  char ** pp = &p;

  // Call it twise because of strange bug hs_init after last hs_exit
  // hs_init(0, &pp);
  hs_init(0, &pp);
#ifdef __NT__
  add_plugin_dll();
#endif
  h_ida_init();
  install_command_interpreter(&cli_haskell);

  return PLUGIN_KEEP;
}

void __stdcall IDAP_term(void)
{
  h_ida_term();
  remove_command_interpreter(&cli_haskell);
  hs_exit();
  return;
}

void __stdcall IDAP_run(int arg)
{
  // h_ida_run(arg);
  return;
}

char IDAP_comment[] 	= "This is plugin for loading plugins";
char IDAP_help[] 		  = "IdaHaskell";
char IDAP_name[] 		  = "IdaHaskell";

plugin_t PLUGIN =
  {
    IDP_INTERFACE_VERSION,
    PLUGIN_FIX,
    IDAP_init,
    IDAP_term,
    IDAP_run,
    IDAP_comment,
    IDAP_help,
    IDAP_name,
  };
