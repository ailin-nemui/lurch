#include "lurch.h"

#include <purple.h>

#include "chat.h"
#include "jabber.h"
#include "jutil.h"
#include "pep.h"

#define JABBER_PROTOCOL_ID "prpl-jabber"

#define LURCH_PREF_ROOT              "/plugins/core/lurch"
#define LURCH_PREF_AXC_LOGGING       LURCH_PREF_ROOT "/axc_logging"
#define LURCH_PREF_AXC_LOGGING_LEVEL LURCH_PREF_AXC_LOGGING "/level"

#define debug_info(a, b, ...) purple_debug_info(a, b "\n" , ##__VA_ARGS__)

#define debug_warning(a, b, ...) purple_debug_warning(a, b "\n" , ##__VA_ARGS__)

#define debug_error(a, b, ...) purple_debug_error(a, b "\n" , ##__VA_ARGS__)

int topic_changed = 0;

PurpleCmdId lurch_cmd_id = 0;

