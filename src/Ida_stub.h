#include "HsFFI.h"
#ifdef __cplusplus
extern "C" {
#endif
extern void h_ida_init(void);
extern void h_ida_term(void);
extern void h_ida_run(HsInt32 a1);
extern HsBool h_cli_execute_line(HsPtr a1);
#ifdef __cplusplus
}
#endif

