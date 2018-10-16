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

#define PREFS_ADD_NONE(prefname) purple_prefs_add_none(prefname)
#define PREFS_ADD_BOOL(prefname, default_value) purple_prefs_add_bool(prefname, default_value)
#define PREFS_ADD_CHOICE(prefname, default_value, choice_list) purple_prefs_add_int(prefname, default_value);

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

/**
 * lurch_get_uname:
 *
 * @return (transfer full) (nullable):  The jabber account jid or the network tag. NULL on error
 */
static char * lurch_get_uname(JabberStream * js_p)
{
  return lurch_uname_strip(purple_account_get_username(purple_connection_get_account(js_p)));
}


/**
 * Actions to perform on plugin load.
 * Inits the crypto and registers signal and PEP handlers.
 */
static gboolean lurch_plugin_load(PurplePlugin * plugin_p) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  char * dl_ns = (void *) 0;
  void * jabber_handle_p = (void *) 0;
  GList * accs_l_p = (void *) 0;
  GList * curr_p = (void *) 0;
  PurpleAccount * acc_p = (void *) 0;

  lurch_plugin_load_generic();

  ret_val = omemo_devicelist_get_pep_node_name(&dl_ns);
  if (ret_val) {
    err_msg_dbg = "failed to get devicelist pep node name";
    goto cleanup;
  }

  lurch_cmd_id = purple_cmd_register("lurch",
                                     "wwws",
                                     PURPLE_CMD_P_PLUGIN,
                                     PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
                                     JABBER_PROTOCOL_ID,
                                     lurch_cmd_func,
                                     "lurch &lt;help&gt;:  "
                                     "Interface to the lurch plugin. For details, use the 'help' argument.",
                                     (void *) 0);

  // register handlers
  jabber_handle_p = purple_plugins_find_with_id(JABBER_PROTOCOL_ID);

  (void) purple_signal_connect_priority(jabber_handle_p, "jabber-receiving-xmlnode", plugin_p, PURPLE_CALLBACK(lurch_xml_received_cb), NULL, PURPLE_PRIORITY_HIGHEST - 100);
  (void) purple_signal_connect_priority(jabber_handle_p, "jabber-sending-xmlnode", plugin_p, PURPLE_CALLBACK(lurch_xml_sent_cb), NULL, PURPLE_PRIORITY_HIGHEST - 100);

  jabber_pep_register_handler(dl_ns, lurch_pep_devicelist_event_handler);
  jabber_add_feature(dl_ns, jabber_pep_namespace_only_when_pep_enabled_cb);

  // manually call init code if there are already accounts connected, e.g. when plugin is loaded manually
  accs_l_p = purple_accounts_get_all_active();
  for (curr_p = accs_l_p; curr_p; curr_p = curr_p->next) {
    acc_p = (PurpleAccount *) curr_p->data;
    if (purple_account_is_connected(acc_p)) {
      if (!g_strcmp0(purple_account_get_protocol_id(acc_p), JABBER_PROTOCOL_ID)) {
        lurch_account_connect_cb(acc_p);
      }
    }
  }

  // register install callback
  (void) purple_signal_connect(purple_accounts_get_handle(), "account-signed-on", plugin_p, PURPLE_CALLBACK(lurch_account_connect_cb), NULL);
  (void) purple_signal_connect(purple_conversations_get_handle(), "conversation-created", plugin_p, PURPLE_CALLBACK(lurch_conv_created_cb), NULL);
  (void) purple_signal_connect(purple_conversations_get_handle(), "conversation-updated", plugin_p, PURPLE_CALLBACK(lurch_conv_updated_cb), NULL);

cleanup:
  free(dl_ns);
  g_list_free(accs_l_p);
  if (ret_val) {
    debug_error("lurch", "%s: %s (%i)", __func__, err_msg_dbg, ret_val);
    omemo_default_crypto_teardown();
    return FALSE;
  }

  return TRUE;
}

static gboolean lurch_plugin_unload(PurplePlugin * plugin_p) {
  lurch_plugin_unload_generic();

  return TRUE;
}

static PurplePluginPrefFrame * lurch_get_plugin_pref_frame(PurplePlugin * plugin_p) {
  PurplePluginPrefFrame * frame_p;
  PurplePluginPref * ppref_p;

  frame_p = purple_plugin_pref_frame_new();
  ppref_p = purple_plugin_pref_new_with_label("Extended logging");
  purple_plugin_pref_frame_add(frame_p, ppref_p);

  ppref_p = purple_plugin_pref_new_with_name_and_label(
                  LURCH_PREF_AXC_LOGGING,
                  "Show log output from underlying libraries");
  purple_plugin_pref_frame_add(frame_p, ppref_p);

  ppref_p = purple_plugin_pref_new_with_name_and_label(
                    LURCH_PREF_AXC_LOGGING_LEVEL,
                    "Log level");
  purple_plugin_pref_set_type(ppref_p, PURPLE_PLUGIN_PREF_CHOICE);
  purple_plugin_pref_add_choice(ppref_p, "ERROR", GINT_TO_POINTER(AXC_LOG_ERROR));
  purple_plugin_pref_add_choice(ppref_p, "WARNING", GINT_TO_POINTER(AXC_LOG_WARNING));
  purple_plugin_pref_add_choice(ppref_p, "NOTICE", GINT_TO_POINTER(AXC_LOG_NOTICE));
  purple_plugin_pref_add_choice(ppref_p, "INFO", GINT_TO_POINTER(AXC_LOG_INFO));
  purple_plugin_pref_add_choice(ppref_p, "DEBUG", GINT_TO_POINTER(AXC_LOG_DEBUG));
  purple_plugin_pref_frame_add(frame_p, ppref_p);

  return frame_p;
}

static PurplePluginUiInfo prefs_info = {
  lurch_get_plugin_pref_frame,
  0,    /* page_num (Reserved) */
  NULL, /* frame (Reserved) */

  /* padding */
  NULL,
  NULL,
  NULL,
  NULL
};

static PurplePluginInfo info = {
    PURPLE_PLUGIN_MAGIC,
    PURPLE_MAJOR_VERSION,
    PURPLE_MINOR_VERSION,
    PURPLE_PLUGIN_STANDARD,
    NULL,
    0,
    NULL,
    PURPLE_PRIORITY_DEFAULT,

    "core-riba-lurch",
    "lurch",
    LURCH_VERSION,

    "Implements OMEMO for libpurple.",
    "End-to-end encryption using the Signal protocol, adapted for XMPP.",
    LURCH_AUTHOR,
    "https://github.com/gkdr/lurch",

    lurch_plugin_load,
    lurch_plugin_unload,
    NULL,

    NULL,
    NULL,
    &prefs_info, // plugin config, see libpurple/plugins/pluginpref_example.c
    NULL,        // plugin actions, see https://developer.pidgin.im/wiki/CHowTo/PluginActionsHowTo
    NULL,
    NULL,
    NULL,
    NULL
};

static void
lurch_plugin_init(PurplePlugin * plugin_p) {
  PurplePluginInfo * info_p = plugin_p->info;

  info_p->dependencies = g_list_prepend(info_p->dependencies, "prpl-jabber");

  lurch_plugin_init_generic();
}

PURPLE_INIT_PLUGIN(lurch, lurch_plugin_init, info)
