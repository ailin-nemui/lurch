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

#define USER_DIR() get_irssi_dir()

#define PREFS_GET_BOOL(prefname) settings_get_bool(prefname)
#define PREFS_GET_INT(prefname) ( settings_get_choice(prefname) - 1 )

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

/**
 * lurch_get_bare_jid:
 *
 * @return (transfer full): the bare jid
 */
static char * lurch_get_bare_jid(const char * jid)
{
  char * resource = strrchr(jid, '/');

  if (resource == NULL) {
    return g_strdup(jid);
  } else {
    return g_strndup(jid, resource - jid);
  }
}

static char * lurch_irssi_nick_get_name(SERVER_REC * server, const char * nick)
{
  g_return_val_if_fail(server != NULL, NULL);

  if (strchr(nick, '@') != NULL) {
    return g_strdup(nick);
  } else {
    return g_strconcat(nick, "@", (server->connrec->chatnet != NULL ?
				   server->connrec->chatnet :
				   server->tag),
		       NULL);
  }
}

static char * lurch_irssi_conversation_get_name(WI_ITEM_REC * item)
{
  g_return_val_if_fail(item != NULL, NULL);

  if (strchr(item->name, '@') != NULL) {
    return g_strdup(item->name);
  } else {
    return g_strconcat(item->name, "@", (item->server != NULL ? item->server->connrec->chatnet != NULL ?
					 item->server->connrec->chatnet :
					 item->server->tag :
					 ((QUERY_REC *)item)->server_tag),
		       NULL);
  }
}

/**
 * lurch_get_account:
 *
 * @return (transfer full) (nullable):  The jabber account jid or the network tag. NULL on error
 */
static char * lurch_get_account(SERVER_REC * server, WI_ITEM_REC * item)
{
  char * nick;

  if (item != NULL && item->server != NULL) {
    server = item->server;
  }
  if (server == NULL) {
    return NULL;
  }

  nick = server->connrec->nick;
  if (nick != NULL && strchr(nick, '@') != NULL) {
    return g_strdup(nick);
  }

  if (server->connrec->chatnet != NULL) {
    return g_strconcat(server->connrec->username, "@", server->connrec->chatnet, NULL);
  }

  return g_strconcat(server->connrec->username, "@", server->tag, NULL);
}
