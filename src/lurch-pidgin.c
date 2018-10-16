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

#define USER_DIR() purple_user_dir()

#define PREFS_GET_BOOL(prefname) purple_prefs_get_bool(prefname)
#define PREFS_GET_INT(prefname) purple_prefs_get_int(prefname)

#define debug_info(a, b, ...) purple_debug_info(a, b "\n" , ##__VA_ARGS__)

#define debug_warning(a, b, ...) purple_debug_warning(a, b "\n" , ##__VA_ARGS__)

#define debug_error(a, b, ...) purple_debug_error(a, b "\n" , ##__VA_ARGS__)

int topic_changed = 0;

PurpleCmdId lurch_cmd_id = 0;

/**
 * For some reason pidgin returns account names with a trailing "/".
 * This function removes it.
 * All other functions asking for the username assume the "/" is already stripped.
 *
 * @param uname The username.
 * @return A duplicated string with the trailing "/" removed. free() when done.
 */
static char * lurch_uname_strip(const char * uname) {
  char ** split;
  char * stripped;

  split = g_strsplit(uname, "/", 2);
  stripped = g_strdup(split[0]);

  g_strfreev(split);

  return stripped;
}

