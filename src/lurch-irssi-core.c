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

#define PREFS_ADD_NONE(prefname) /* not needed */
#define PREFS_ADD_BOOL(prefname, default_value) settings_add_bool("misc", prefname, default_value)
#define PREFS_ADD_CHOICE(prefname, default_value, choice_list) settings_add_choice("misc", prefname, default_value + 1, choice_list);

#define debug_info(a, b, ...) \
  if (log_level >= AXC_LOG_INFO)					\
    printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "[" a "][INFO] " b , ##__VA_ARGS__)

#define debug_warning(a, b, ...) \
  if (log_level >= AXC_LOG_WARNING)					\
    printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE, "[" a "][WARNING] " b , ##__VA_ARGS__)

#define debug_error(a, b, ...) \
  if (log_level >= AXC_LOG_ERROR)					\
    printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "[" a "][ERROR] " b , ##__VA_ARGS__)

typedef struct _JabberStream {
  SERVER_REC * gc;
  WI_ITEM_REC * wi;
} JabberStream;

#define JS_TO_SERVER(a) (a)->gc

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
 * lurch_get_uname:
 *
 * @return (transfer full) (nullable):  The jabber account jid or the network tag. NULL on error
 */
static char * lurch_get_uname(SERVER_REC * server, WI_ITEM_REC * item)
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

static char * lurch_fp_printable_x(const guchar * data, gsize len)
{
  int i;
  gchar * out = (void *) 0;

  out = g_malloc(len * 2 + len / 4 + 2);
  for (i = 1; i < len; ++i) {
    g_snprintf(&out[(i - 1) * 2 + (i - 1) / 4], 3, "%02hhx", data[i]);
    if (i % 4 == 0) {
      g_snprintf(&out[(i - 1) * 2 + (i - 1) / 4 + 2], 2, " ");
    }
  }
  return out;
}

static void irssi_lurch_peppublish(SERVER_REC * server, const char * from, const char * xml)
{
  LmMessage * msg = lm_message_new_with_sub_type(NULL, LM_MESSAGE_TYPE_IQ, LM_MESSAGE_SUB_TYPE_SET);
  LmMessageNode * pubsub_node_p = lm_message_node_add_child(msg->node, "pubsub", NULL);
  lm_message_node_set_attribute(pubsub_node_p, "xmlns", "http://jabber.org/protocol/pubsub");

  lm_message_node_set_raw_mode(pubsub_node_p, TRUE);
  lm_message_node_set_value(pubsub_node_p, xml);

  signal_emit("xmpp send iq", 2, server, msg);

  lm_message_unref(msg);
}

static void irssi_lurch_send(SERVER_REC * server, const char * from, const char * xml)
{
  mxml_node_t * xml_p = (void *) 0;

  xml_p = mxmlLoadString((void *) 0, xml, MXML_OPAQUE_CALLBACK);

  //g_warning("sending xml: ##%s##", xml);

  int lm_type = LM_MESSAGE_SUB_TYPE_NOT_SET;
  const char * type = mxmlElementGetAttr(xml_p, "type");
  if (!g_strcmp0("chat", type)) {
    lm_type = LM_MESSAGE_SUB_TYPE_CHAT;
  } else if (!g_strcmp0("groupchat", type)) {
    lm_type = LM_MESSAGE_SUB_TYPE_GROUPCHAT;
  } else if (!g_strcmp0("headline", type)) {
    lm_type = LM_MESSAGE_SUB_TYPE_HEADLINE;
  } else {
    debug_warning("lurch", "irssi_lurch_send: unknown sub-type: %s", type);
  }

  LmMessage * msg = lm_message_new_with_sub_type(mxmlElementGetAttr(xml_p, "to"), LM_MESSAGE_TYPE_MESSAGE, lm_type);
  lm_message_node_set_attribute(msg->node, "id", mxmlElementGetAttr(xml_p, "id"));
  lm_message_node_set_raw_mode(msg->node, TRUE);

  GString * str = g_string_sized_new(strlen(xml));
  mxml_node_t * child = mxmlGetFirstChild(xml_p);
  mxml_node_t * sibling;
  for (sibling = child; sibling; sibling = mxmlGetNextSibling(sibling)) {
    mxml_node_t * next = sibling->next;
    mxml_node_t * parent = sibling->parent;
    sibling->parent = NULL;
    sibling->next = NULL;
    char * frag = mxmlSaveAllocString(sibling, MXML_NO_CALLBACK);
    g_string_append(str, frag);
    free(frag);
    sibling->parent = parent;
    sibling->next = next;
  }
  lm_message_node_set_value(msg->node, str->str);
  mxml_node_t * body_node_p = mxmlFindPath(xml_p, "body");
  if (!body_node_p) {
    lm_message_node_add_child(msg->node, "body", "[Encrypted with OMEMO]");
  }
  char * new_xml = lm_message_node_to_string(msg->node);
  //g_warning("I want to send ##%s##", new_xml);
  g_free(new_xml);
  signal_emit("xmpp send message", 2, server, msg);

  g_string_free(str, TRUE);
  lm_message_unref(msg);
  mxmlRelease(xml_p);
}

static void irssi_lurch_peprequest(SERVER_REC * server, const char * to, const char * node, void * callback_fn)
{
  LmMessage * jiq_p = lm_message_new_with_sub_type(to, LM_MESSAGE_TYPE_IQ, LM_MESSAGE_SUB_TYPE_GET);
  LmMessageNode * pubsub_node_p = lm_message_node_add_child(jiq_p->node, "pubsub", NULL);
  lm_message_node_set_attribute(pubsub_node_p, "xmlns", "http://jabber.org/protocol/pubsub");

  char * req_id;
  while (1) {
    char * rand_str = g_strdup_printf("%d", g_random_int());
    req_id = g_strconcat(to, "#", rand_str, NULL);
    if (g_hash_table_lookup(lurch_peprequest_response_ht, req_id) != NULL) {
      g_free(rand_str);
      g_free(req_id);
      continue;
    }
    break;
  }

  LmMessageNode * items_node_p = lm_message_node_add_child(pubsub_node_p, "items", NULL);
  lm_message_node_set_attribute(items_node_p, "node", node);
  lm_message_node_set_attribute(items_node_p, "max_items", "1");

  lm_message_node_set_attribute(jiq_p->node, "id", req_id);

  g_hash_table_insert(lurch_peprequest_response_ht, req_id, callback_fn);

  signal_emit("xmpp send iq", 2, server, jiq_p);

  lm_message_unref(jiq_p);
}

void irssi_lurch_read_settings(void)
{
  log_level = settings_get_choice(LURCH_PREF_AXC_LOGGING_LEVEL) - 1;
}

void lurch_peppublish_bundle(JabberStream * js_p, const char * uname, const char * bundle_xml)
{
  signal_emit("lurch peppublish bundle", 3, JS_TO_SERVER(js_p), uname, bundle_xml);
}


/**
 * Actions to perform on plugin load.
 * Inits the crypto and registers signal and PEP handlers.
 */
void lurch_core_init(void)
{
  GSList * tmp;
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  char * dl_ns = (void *) 0;
  GList * accs_l_p = (void *) 0;

  lurch_bundle_request_ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
  lurch_peprequest_response_ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

  lurch_plugin_load_generic();

  ret_val = omemo_devicelist_get_pep_node_name(&dl_ns);
  if (ret_val) {
    err_msg_dbg = "failed to get devicelist pep node name";
    goto cleanup;
  }

  settings_add_bool("misc", LURCH_PREF_AXC_LOGGING, TRUE);
  settings_add_choice("misc", LURCH_PREF_AXC_LOGGING_LEVEL, 5, "none;error;warning;notice;info;debug");

  expando_create("encryption_omemo", (EXPANDO_FUNC) lurch_expando_encryption_omemo,
		 "window changed", EXPANDO_ARG_NONE,
		 "window item changed", EXPANDO_ARG_WINDOW,
		 "lurch encryption changed", EXPANDO_ARG_WINDOW_ITEM,
		 NULL);

  command_bind("lurch", NULL, (SIGNAL_FUNC) lurch_cmd_func);
  signal_add("xmpp recv message", (SIGNAL_FUNC) lurch_xml_received_cb);
  signal_add("xmpp send message", (SIGNAL_FUNC) lurch_xml_sent_cb);

  signal_add("xmpp recv iq", (SIGNAL_FUNC) irssi_lurch_bundle_request_cb);
  signal_add("xmpp recv iq", (SIGNAL_FUNC) irssi_lurch_peprequest_cb);
  signal_add("xmpp recv message", (SIGNAL_FUNC) irssi_lurch_message_cb);
  signal_add("xmpp recv iq", (SIGNAL_FUNC) irssi_lurch_iq_cb);

  // too early :(
  //signal_add("chat protocol created", (SIGNAL_FUNC) irssi_lurch_register_features_cb);

  signal_emit("xmpp register feature", 1, dl_ns);
  char * dl_ns_notify = g_strconcat(dl_ns , "+notify", NULL);
  signal_emit("xmpp register feature", 1, dl_ns_notify);
  g_free(dl_ns_notify);

  // jabber_pep_register_handler(dl_ns, lurch_pep_devicelist_event_handler);
  g_dl_ns = g_strdup(dl_ns);
  // jabber_add_feature(dl_ns, jabber_pep_namespace_only_when_pep_enabled_cb);

  // manually call init code if there are already accounts connected, e.g. when plugin is loaded manually
  for (tmp = servers; tmp != NULL; tmp = tmp->next) {
    SERVER_REC * server = tmp->data;
    if (server->connected) {
      lurch_account_connect_cb(server);
    }
  }

  // register install callback
  signal_add("server connected", (SIGNAL_FUNC) lurch_account_connect_cb);
  signal_add_last("query created", (SIGNAL_FUNC) lurch_conv_created_cb);
  signal_add_last("channel created", (SIGNAL_FUNC) lurch_conv_created_cb);
  // (void) purple_signal_connect(purple_conversations_get_handle(), "conversation-updated", plugin_p, PURPLE_CALLBACK(lurch_conv_updated_cb), NULL);

  signal_add("lurch peprequest bundle", (SIGNAL_FUNC) irssi_lurch_peprequest);
  signal_add("lurch peprequest own_devicelist", (SIGNAL_FUNC) irssi_lurch_peprequest);
  signal_add("lurch peprequest devicelist", (SIGNAL_FUNC) irssi_lurch_peprequest);

  signal_add("lurch peppublish bundle", (SIGNAL_FUNC) irssi_lurch_peppublish);
  signal_add("lurch send message", (SIGNAL_FUNC) irssi_lurch_send);
  signal_add("lurch send keytransport", (SIGNAL_FUNC) irssi_lurch_send);
  signal_add("lurch peppublish devicelist", (SIGNAL_FUNC) irssi_lurch_peppublish);

  signal_add("setup changed", (SIGNAL_FUNC) irssi_lurch_read_settings);
  irssi_lurch_read_settings();

cleanup:
  free(dl_ns);
  g_list_free(accs_l_p);
  if (ret_val) {
    debug_error("lurch", "%s: %s (%d)", __func__, err_msg_dbg, ret_val);
  }

  module_register("lurch", "core");
}

void lurch_core_deinit(void)
{
  command_unbind("lurch", (SIGNAL_FUNC) lurch_cmd_func);
  signal_remove("xmpp recv message", (SIGNAL_FUNC) lurch_xml_received_cb);
  signal_remove("xmpp send message", (SIGNAL_FUNC) lurch_xml_sent_cb);

  signal_remove("xmpp recv iq", (SIGNAL_FUNC) irssi_lurch_bundle_request_cb);
  signal_remove("xmpp recv iq", (SIGNAL_FUNC) irssi_lurch_peprequest_cb);
  signal_remove("xmpp recv message", (SIGNAL_FUNC) irssi_lurch_message_cb);
  signal_remove("xmpp recv iq", (SIGNAL_FUNC) irssi_lurch_iq_cb);

  signal_remove("server connected", (SIGNAL_FUNC) lurch_account_connect_cb);
  signal_remove("query created", (SIGNAL_FUNC) lurch_conv_created_cb);
  signal_remove("channel created", (SIGNAL_FUNC) lurch_conv_created_cb);

  signal_remove("lurch peprequest bundle", (SIGNAL_FUNC) irssi_lurch_peprequest);
  signal_remove("lurch peprequest own_devicelist", (SIGNAL_FUNC) irssi_lurch_peprequest);
  signal_remove("lurch peprequest devicelist", (SIGNAL_FUNC) irssi_lurch_peprequest);

  signal_remove("lurch peppublish bundle", (SIGNAL_FUNC) irssi_lurch_peppublish);
  signal_remove("lurch send message", (SIGNAL_FUNC) irssi_lurch_send);
  signal_remove("lurch send keytransport", (SIGNAL_FUNC) irssi_lurch_send);
  signal_remove("lurch peppublish devicelist", (SIGNAL_FUNC) irssi_lurch_peppublish);

  signal_remove("setup changed", (SIGNAL_FUNC) irssi_lurch_read_settings);

  omemo_default_crypto_teardown();

  expando_destroy("encryption_omemo", (EXPANDO_FUNC) lurch_expando_encryption_omemo);

  g_hash_table_unref(lurch_bundle_request_ht);
  g_hash_table_unref(lurch_peprequest_response_ht);
  g_free(g_dl_ns);
}

#ifdef IRSSI_ABI_VERSION
void
lurch_core_abicheck(int * version)
{
        *version = IRSSI_ABI_VERSION;
}
#endif
