#include "irssi-module.h"

#include "lurch.h"

#include <mxml.h>

#include <irssi/src/common.h>
#include <irssi/src/core/window-item-def.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/channels.h>
#include <irssi/src/core/queries.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/expandos.h>
#include <irssi/src/core/nicklist.h>
#include <irssi/src/fe-common/core/printtext.h>

#include <loudmouth/loudmouth.h>

#define LURCH_PRE_KEYS_AMOUNT 21

#define LURCH_PREF_ROOT              "lurch"
#define LURCH_PREF_AXC_LOGGING       LURCH_PREF_ROOT "_axc_logging"
#define LURCH_PREF_AXC_LOGGING_LEVEL LURCH_PREF_AXC_LOGGING "_level"

#define debug_info(a, b, ...) \
  if (log_level >= AXC_LOG_INFO)					\
    printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "[" a "][INFO] " b , ##__VA_ARGS__)

#define debug_warning(a, b, ...) \
  if (log_level >= AXC_LOG_WARNING)					\
    printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE, "[" a "][WARNING] " b , ##__VA_ARGS__)

#define debug_error(a, b, ...) \
  if (log_level >= AXC_LOG_ERROR)					\
    printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "[" a "][ERROR] " b , ##__VA_ARGS__)

char * g_dl_ns = (void *) 0;
int log_level = -1;

static GHashTable * lurch_bundle_request_ht;
static GHashTable * lurch_peprequest_response_ht;
