#include "module.h"

#include <glib.h>

#include <inttypes.h>
#include <string.h>
#include <time.h>
#include <mxml.h>

#include "irssi/src/common.h"
#include "irssi/src/core/window-item-def.h"
#include "irssi/src/core/servers.h"
#include "irssi/src/core/channels.h"
#include "irssi/src/core/queries.h"
#include "irssi/src/core/settings.h"
#include "irssi/src/core/signals.h"
#include "irssi/src/core/levels.h"
#include "irssi/src/core/commands.h"
#include "irssi/src/core/expandos.h"
#include "irssi/src/core/nicklist.h"
#include "irssi/src/fe-common/core/printtext.h"

#include "loudmouth/loudmouth.h"

#include "libomemo.h"
#include "libomemo_crypto.h"
#include "libomemo_storage.h"

#include "axc.h"
#include "axc_store.h"

// included for error codes
#include "signal_protocol.h"

#include "lurch.h"

#ifdef _WIN32
#define strnlen(a, b) (MIN(strlen(a), (b)))
#endif

#define LURCH_PRE_KEYS_AMOUNT 21

// see https://www.ietf.org/rfc/rfc3920.txt
#define JABBER_MAX_LEN_NODE 1023
#define JABBER_MAX_LEN_DOMAIN 1023
#define JABBER_MAX_LEN_BARE JABBER_MAX_LEN_NODE + JABBER_MAX_LEN_DOMAIN + 1

#define LURCH_ACC_SETTING_INITIALIZED "lurch_initialised"

#define LURCH_DB_SUFFIX     "_db.sqlite"
#define LURCH_DB_NAME_OMEMO "omemo"
#define LURCH_DB_NAME_AXC   "axc"

#define LURCH_PREF_ROOT              "lurch"
#define LURCH_PREF_AXC_LOGGING       LURCH_PREF_ROOT "_axc_logging"
#define LURCH_PREF_AXC_LOGGING_LEVEL LURCH_PREF_AXC_LOGGING "_level"

#define LURCH_ERR           -1000000
#define LURCH_ERR_NOMEM     -1000001
#define LURCH_ERR_NO_BUNDLE -1000010

#define LURCH_ERR_STRING_ENCRYPT "There was an error encrypting the message and it was not sent. " \
                                 "You can try again, or try to find the problem by looking at the debug log."
#define LURCH_ERR_STRING_DECRYPT "There was an error decrypting an OMEMO message addressed to this device. " \
                                 "See the debug log for details."

#define debug_info(a, b, ...) g_warning("[" a "][INFO] " b , ##__VA_ARGS__)
#define debug_warning(a, b, ...) g_warning("[" a "][WARNING] " b , ##__VA_ARGS__)
#define debug_error(a, b, ...) g_warning("[" a "][ERROR] " b , ##__VA_ARGS__)

typedef struct lurch_addr {
  char * jid;
  uint32_t device_id;
} lurch_addr;

typedef struct lurch_queued_msg {
  omemo_message * om_msg_p;
  GList * recipient_addr_l_p;
  GList * no_sess_l_p;
  GHashTable * sess_handled_p;
} lurch_queued_msg;

omemo_crypto_provider crypto = {
    .random_bytes_func = omemo_default_crypto_random_bytes,
    .aes_gcm_encrypt_func = omemo_default_crypto_aes_gcm_encrypt,
    .aes_gcm_decrypt_func = omemo_default_crypto_aes_gcm_decrypt
};

int uninstall = 0;
char * g_dl_ns = (void *) 0;

static GHashTable * lurch_bundle_request_ht;
static GHashTable * lurch_peprequest_response_ht;

static void lurch_addr_list_destroy_func(gpointer data) {
  lurch_addr * addr_p = (lurch_addr *) data;
  free(addr_p->jid);
  free(addr_p);
}


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
 * Creates a queued msg.
 * Note that it just saves the pointers, so make sure they are not freed during
 * the lifetime of this struct and instead use the destroy function when done.
 *
 * @param om_msg_p Pointer to the omemo_message.
 * @param recipient_addr_l_p Pointer to the list of recipient addresses.
 * @param no_sess_l_p Pointer to the list that contains the addresses that do
 *                    not have sessions, i.e. for which bundles were requested.
 * @param cmsg_pp Will point to the pointer of the created queued msg struct.
 * @return 0 on success, negative on error.
 */
static int lurch_queued_msg_create(omemo_message * om_msg_p,
                                   GList * recipient_addr_l_p,
                                   GList * no_sess_l_p,
                                   lurch_queued_msg ** qmsg_pp) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  lurch_queued_msg * qmsg_p = (void *) 0;
  GHashTable * sess_handled_p = (void *) 0;

  qmsg_p = malloc(sizeof(lurch_queued_msg));
  if (!qmsg_p) {
    ret_val = LURCH_ERR_NOMEM;
    err_msg_dbg = g_strdup_printf("failed to malloc space for queued msg struct");
    goto cleanup;
  }

  sess_handled_p = g_hash_table_new(g_str_hash, g_str_equal);

  qmsg_p->om_msg_p = om_msg_p;
  qmsg_p->recipient_addr_l_p = recipient_addr_l_p;
  qmsg_p->no_sess_l_p = no_sess_l_p;
  qmsg_p->sess_handled_p = sess_handled_p;

  *qmsg_pp = qmsg_p;

cleanup:
  if (ret_val) {
    free(qmsg_p);
  }
  if (err_msg_dbg) {
    debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }
  return ret_val;
}

static int lurch_queued_msg_is_handled(const lurch_queued_msg * qmsg_p) {
  return (g_list_length(qmsg_p->no_sess_l_p) == g_hash_table_size(qmsg_p->sess_handled_p)) ? 1 : 0;
}

/**
 * Frees all the memory used by the queued msg.
 */
static void lurch_queued_msg_destroy(lurch_queued_msg * qmsg_p) {
  if (qmsg_p) {
    omemo_message_destroy(qmsg_p->om_msg_p);
    g_list_free_full(qmsg_p->recipient_addr_l_p, free);
    g_hash_table_destroy(qmsg_p->sess_handled_p);
    free(qmsg_p);
  }
}

static char * lurch_queue_make_key_string_s(const char * name, const char * device_id) {
  return g_strconcat(name, "/", device_id, NULL);
}

/**
 * Returns the db name, has to be g_free()d.
 *
 * @param uname The username.
 * @param which Either LURCH_DB_NAME_OMEMO or LURCH_DB_NAME_AXC
 * @return (transfer full): The path string.
 */
static char * lurch_uname_get_db_fn(const char * uname, char * which) {
  return g_strconcat(get_irssi_dir(), "/", uname, "_", which, LURCH_DB_SUFFIX, NULL);
}

static char * lurch_uname_strip(const char * uname) __attribute__((unused));
/**
 * For some reason pidgin returns account names with a trailing "/".
 * This function removes it.
 * All other functions asking for the username assume the "/" is already stripped.
 *
 * @param uname The username.
 * @return (transfer full): A duplicated string with the trailing "/" removed. free() when done.
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

/**
 * Log wrapper for AXC
 *
 * @param level	an AXC_LOG level
 * @param msg 	the log message
 * @param len	the length of the message
 * @param ctx_p	the axc context
 */
static void lurch_axc_log_func(int level, const char * msg, size_t len, void * user_data) {
  switch(level) {
    case AXC_LOG_ERROR:
      g_warning("lurch" "[AXC ERROR] %s\n", msg);
      break;
    case AXC_LOG_WARNING:
      g_warning("lurch" "[AXC WARNING] %s\n", msg);
      break;
    case AXC_LOG_NOTICE:
      g_warning("lurch" "[AXC NOTICE] %s\n", msg);
      break;
    case AXC_LOG_INFO:
      g_warning("lurch" "[AXC INFO] %s\n", msg);
      break;
    case AXC_LOG_DEBUG:
      g_warning("lurch" "[AXC DEBUG] %s\n", msg);
      break;
    default:
      g_warning("lurch" "[AXC %d] %s\n", level, msg);
      break;
  }
}

/**
 * Creates and initializes the axc context.
 *
 * @param uname The username.
 * @param ctx_pp Will point to an initialized axc context on success.
 * @return 0 on success, negative on error.
 */
static int lurch_axc_get_init_ctx(char * uname, axc_context ** ctx_pp) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  axc_context * ctx_p = (void *) 0;
  char * db_fn = (void *) 0;

  ret_val = axc_context_create(&ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to create axc context");
    goto cleanup;
  }

  db_fn = lurch_uname_get_db_fn(uname, LURCH_DB_NAME_AXC);
  ret_val = axc_context_set_db_fn(ctx_p, db_fn, strlen(db_fn));
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to set axc db filename");
    goto cleanup;
  }

  if (settings_get_bool(LURCH_PREF_AXC_LOGGING)) {
      axc_context_set_log_func(ctx_p, lurch_axc_log_func);
      axc_context_set_log_level(ctx_p, settings_get_choice(LURCH_PREF_AXC_LOGGING_LEVEL));
  }

  ret_val = axc_init(ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to init axc context");
    goto cleanup;
  }

  if (settings_get_bool(LURCH_PREF_AXC_LOGGING)) {
    signal_context_set_log_function(axc_context_get_axolotl_ctx(ctx_p), lurch_axc_log_func);
  }

  *ctx_pp = ctx_p;

cleanup:
  if (ret_val) {
    axc_context_destroy_all(ctx_p);
  }
  if (err_msg_dbg) {
    debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }

  free (db_fn);
  return ret_val;
}

/**
 * Does the first-time install of the axc DB.
 * As specified in OMEMO, it checks if the generated device ID already exists.
 * Therefore, it should be called at a point in time when other entries exist.
 *
 * @param uname The username.
 * @return 0 on success, negative on error.
 */
static int lurch_axc_prepare(char * uname) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  axc_context * axc_ctx_p = (void *) 0;
  uint32_t device_id = 0;
  char * db_fn_omemo = (void *) 0;

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get init axc ctx");
    goto cleanup;
  }

  ret_val = axc_get_device_id(axc_ctx_p, &device_id);
  if (!ret_val) {
    // already installed
    goto cleanup;
  }

  db_fn_omemo = lurch_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  while (1) {
    ret_val = axc_install(axc_ctx_p);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to install axc");
      goto cleanup;
    }

    ret_val = axc_get_device_id(axc_ctx_p, &device_id);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to get own device id");
      goto cleanup;
    }

    ret_val = omemo_storage_global_device_id_exists(device_id, db_fn_omemo);
    if (ret_val == 1)  {
      ret_val = axc_db_init_status_set(AXC_DB_NEEDS_ROLLBACK, axc_ctx_p);
      if (ret_val) {
        err_msg_dbg = g_strdup_printf("failed to set axc db to rollback");
        goto cleanup;
      }
    } else if (ret_val < 0) {
      err_msg_dbg = g_strdup_printf("failed to access the db %s", db_fn_omemo);
      goto cleanup;
    } else {
      break;
    }
  }

cleanup:
  if (err_msg_dbg) {
    debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }
  axc_context_destroy_all(axc_ctx_p);
  free(db_fn_omemo);

  return ret_val;
}

/**
 * Encrypts a data buffer, usually the omemo symmetric key, using axolotl.
 * Assumes a valid session already exists.
 *
 * @param recipient_addr_p Pointer to the lurch_addr of the recipient.
 * @param key_p Pointer to the key data.
 * @param key_len Length of the key data.
 * @param axc_ctx_p Pointer to the axc_context to use.
 * @param key_ct_pp Will point to a pointer to an axc_buf containing the key ciphertext on success.
 * @return 0 on success, negative on error
 */
static int lurch_key_encrypt(const lurch_addr * recipient_addr_p,
                             const uint8_t * key_p,
                             size_t key_len,
                             axc_context * axc_ctx_p,
                             axc_buf ** key_ct_buf_pp) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  axc_buf * key_buf_p = (void *) 0;
  axc_buf * key_ct_buf_p = (void *) 0;
  axc_address axc_addr = {0};

  debug_info("lurch", "%s: encrypting key for %s:%i\n", __func__, recipient_addr_p->jid, recipient_addr_p->device_id);

  key_buf_p = axc_buf_create(key_p, key_len);
  if (!key_buf_p) {
    err_msg_dbg = g_strdup_printf("failed to create buffer for the key");
    goto cleanup;
  }

  axc_addr.name = recipient_addr_p->jid;
  axc_addr.name_len = strnlen(axc_addr.name, JABBER_MAX_LEN_BARE);
  axc_addr.device_id = recipient_addr_p->device_id;

  ret_val = axc_message_encrypt_and_serialize(key_buf_p, &axc_addr, axc_ctx_p, &key_ct_buf_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to encrypt the key");
    goto cleanup;
  }

  *key_ct_buf_pp = key_ct_buf_p;

cleanup:
  if (ret_val) {
    axc_buf_free(key_ct_buf_p);
  }
  if (err_msg_dbg) {
    debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }
  axc_buf_free(key_buf_p);

  return ret_val;
}

/**
 * For each of the recipients, encrypts the symmetric key using the existing axc session,
 * then adds it to the omemo message.
 * If the session does not exist, the recipient is skipped.
 *
 * @param om_msg_p Pointer to the omemo message.
 * @param addr_l_p Pointer to the head of a list of the intended recipients' lurch_addrs.
 * @param axc_ctx_p Pointer to the axc_context to use.
 * @return 0 on success, negative on error.
 */
static int lurch_msg_encrypt_for_addrs(omemo_message * om_msg_p, GList * addr_l_p, axc_context * axc_ctx_p) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  GList * curr_l_p = (void *) 0;
  lurch_addr * curr_addr_p = (void *) 0;
  axc_address addr = {0};
  axc_buf * curr_key_ct_buf_p = (void *) 0;

  debug_info("lurch", "%s: trying to encrypt key for %i devices\n", __func__, g_list_length(addr_l_p));

  for (curr_l_p = addr_l_p; curr_l_p; curr_l_p = curr_l_p->next) {
    curr_addr_p = (lurch_addr *) curr_l_p->data;
    addr.name = curr_addr_p->jid;
    addr.name_len = strnlen(addr.name, JABBER_MAX_LEN_BARE);
    addr.device_id = curr_addr_p->device_id;

    ret_val = axc_session_exists_initiated(&addr, axc_ctx_p);
    if (ret_val < 0) {
      err_msg_dbg = g_strdup_printf("failed to check if session exists, aborting");
      goto cleanup;
    } else if (!ret_val) {
      continue;
    } else {
      ret_val = lurch_key_encrypt(curr_addr_p,
                                  omemo_message_get_key(om_msg_p),
                                  omemo_message_get_key_len(om_msg_p),
                                  axc_ctx_p,
                                  &curr_key_ct_buf_p);
      if (ret_val) {
        err_msg_dbg = g_strdup_printf("failed to encrypt key for %s:%i", curr_addr_p->jid, curr_addr_p->device_id);
        goto cleanup;
      }

      ret_val = omemo_message_add_recipient(om_msg_p,
                                            curr_addr_p->device_id,
                                            axc_buf_get_data(curr_key_ct_buf_p),
                                            axc_buf_get_len(curr_key_ct_buf_p));
      if (ret_val) {
        err_msg_dbg = g_strdup_printf("failed to add recipient to omemo msg");
        goto cleanup;
      }

      axc_buf_free(curr_key_ct_buf_p);
      curr_key_ct_buf_p = (void *) 0;
    }
  }

cleanup:
  if (err_msg_dbg) {
    debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }
  axc_buf_free(curr_key_ct_buf_p);

  return ret_val;
}

/**
 * Collects the information needed for a bundle and publishes it.
 *
 * @param uname The username.
 * @param js_p Pointer to the connection to use for publishing.
 */
static int lurch_bundle_publish_own(SERVER_REC * server) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  char * uname = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  axc_bundle * axcbundle_p = (void *) 0;
  omemo_bundle * omemobundle_p = (void *) 0;
  axc_buf * curr_buf_p = (void *) 0;
  axc_buf_list_item * next_p = (void *) 0;
  char * bundle_xml = (void *) 0;

  uname = lurch_get_account(server, NULL);

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to init axc ctx");
    goto cleanup;
  }

  ret_val = axc_bundle_collect(LURCH_PRE_KEYS_AMOUNT, axc_ctx_p, &axcbundle_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to collect axc bundle");
    goto cleanup;
  }

  ret_val = omemo_bundle_create(&omemobundle_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to create omemo_bundle");
    goto cleanup;
  }

  ret_val = omemo_bundle_set_device_id(omemobundle_p, axc_bundle_get_reg_id(axcbundle_p));
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to set device id in omemo bundle");
    goto cleanup;
  }

  curr_buf_p = axc_bundle_get_signed_pre_key(axcbundle_p);
  ret_val = omemo_bundle_set_signed_pre_key(omemobundle_p,
                                            axc_bundle_get_signed_pre_key_id(axcbundle_p),
                                            axc_buf_get_data(curr_buf_p),
                                            axc_buf_get_len(curr_buf_p));
  if(ret_val) {
    err_msg_dbg = g_strdup_printf("failed to set signed pre key in omemo bundle");
    goto cleanup;
  }

  curr_buf_p = axc_bundle_get_signature(axcbundle_p);
  ret_val = omemo_bundle_set_signature(omemobundle_p,
                                       axc_buf_get_data(curr_buf_p),
                                       axc_buf_get_len(curr_buf_p));
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to set signature in omemo bundle");
    goto cleanup;
  }

  curr_buf_p = axc_bundle_get_identity_key(axcbundle_p);
  ret_val = omemo_bundle_set_identity_key(omemobundle_p,
                                          axc_buf_get_data(curr_buf_p),
                                          axc_buf_get_len(curr_buf_p));
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to set public identity key in omemo bundle");
    goto cleanup;
  }

  next_p = axc_bundle_get_pre_key_list(axcbundle_p);
  while (next_p) {
    curr_buf_p = axc_buf_list_item_get_buf(next_p);
    ret_val = omemo_bundle_add_pre_key(omemobundle_p,
                                       axc_buf_list_item_get_id(next_p),
                                       axc_buf_get_data(curr_buf_p),
                                       axc_buf_get_len(curr_buf_p));
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to add public pre key to omemo bundle");
      goto cleanup;
    }
    next_p = axc_buf_list_item_get_next(next_p);
  }

  ret_val = omemo_bundle_export(omemobundle_p, &bundle_xml);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to export omemo bundle to xml");
    goto cleanup;
  }

  g_warning("pre_key bundle: ##%s##", bundle_xml);
  //publish_node_bundle_p = xmlnode_from_str(bundle_xml, -1);
  //jabber_pep_publish(js_p, publish_node_bundle_p);
  signal_emit("lurch peppublish bundle", 3, server, uname, bundle_xml);

  debug_info("lurch", "%s: published own bundle for %s\n", __func__, uname);

cleanup:
  if (err_msg_dbg) {
    debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }
  free(uname);
  axc_context_destroy_all(axc_ctx_p);
  axc_bundle_destroy(axcbundle_p);
  omemo_bundle_destroy(omemobundle_p);
  free(bundle_xml);

  return ret_val;
}

/**
 * Parses the device ID from a received bundle update.
 *
 * @param bundle_node_ns The node name.
 * @return The ID.
 */
static uint32_t lurch_bundle_name_get_device_id(const char * bundle_node_name) {
  char ** split = (void *) 0;
  uint32_t id = 0;

  split = g_strsplit(bundle_node_name, ":", -1);
  id = strtol(split[5], (void *) 0, 0);

  g_strfreev(split);

  return id;
}

/**
 * Creates an axc session from a received bundle.
 *
 * @param uname The own username.
 * @param from The sender of the bundle.
 * @param items_p The bundle update as received in the PEP request handler.
 */
static int lurch_bundle_create_session(const char * uname,
                                       const char * from,
                                       LmMessageNode * items_p,
                                       axc_context * axc_ctx_p) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  omemo_bundle * om_bundle_p = (void *) 0;
  axc_address remote_addr = {0};
  uint32_t pre_key_id = 0;
  uint8_t * pre_key_p = (void *) 0;
  size_t pre_key_len = 0;
  uint32_t signed_pre_key_id = 0;
  uint8_t * signed_pre_key_p = (void *) 0;
  size_t signed_pre_key_len = 0;
  uint8_t * signature_p = (void *) 0;
  size_t signature_len = 0;
  uint8_t * identity_key_p = (void *) 0;
  size_t identity_key_len = 0;
  axc_buf * pre_key_buf_p = (void *) 0;
  axc_buf * signed_pre_key_buf_p = (void *) 0;
  axc_buf * signature_buf_p = (void *) 0;
  axc_buf * identity_key_buf_p = (void *) 0;
  char * items_xml = (void *) 0;

  debug_info("lurch", "%s: creating a session between %s and %s from a received bundle\n", __func__, uname, from);

  items_xml = lm_message_node_to_string(items_p);
  ret_val = omemo_bundle_import(items_xml, &om_bundle_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to import xml into bundle");
    goto cleanup;
  }

  remote_addr.name = from;
  remote_addr.name_len = strnlen(from, JABBER_MAX_LEN_BARE);
  remote_addr.device_id = omemo_bundle_get_device_id(om_bundle_p);

  debug_info("lurch", "%s: bundle's device id is %i\n", __func__, remote_addr.device_id);

  ret_val = omemo_bundle_get_random_pre_key(om_bundle_p, &pre_key_id, &pre_key_p, &pre_key_len);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed get a random pre key from the bundle");
    goto cleanup;
  }
  ret_val = omemo_bundle_get_signed_pre_key(om_bundle_p, &signed_pre_key_id, &signed_pre_key_p, &signed_pre_key_len);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get the signed pre key from the bundle");
    goto cleanup;
  }
  ret_val = omemo_bundle_get_signature(om_bundle_p, &signature_p, &signature_len);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get the signature from the bundle");
    goto cleanup;
  }
  ret_val = omemo_bundle_get_identity_key(om_bundle_p, &identity_key_p, &identity_key_len);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get the public identity key from the bundle");
    goto cleanup;
  }

  pre_key_buf_p = axc_buf_create(pre_key_p, pre_key_len);
  signed_pre_key_buf_p = axc_buf_create(signed_pre_key_p, signed_pre_key_len);
  signature_buf_p = axc_buf_create(signature_p, signature_len);
  identity_key_buf_p = axc_buf_create(identity_key_p, identity_key_len);

  if (!pre_key_buf_p || !signed_pre_key_buf_p || !signature_buf_p || !identity_key_buf_p) {
    ret_val = LURCH_ERR;
    err_msg_dbg = g_strdup_printf("failed to create one of the buffers");
    goto cleanup;
  }

  ret_val = axc_session_from_bundle(pre_key_id, pre_key_buf_p,
                                    signed_pre_key_id, signed_pre_key_buf_p,
                                    signature_buf_p,
                                    identity_key_buf_p,
                                    &remote_addr,
                                    axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to create a session from a bundle");
    goto cleanup;
  }

cleanup:
  if (err_msg_dbg) {
    debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }
  g_free(items_xml);
  omemo_bundle_destroy(om_bundle_p);
  free(pre_key_p);
  free(signed_pre_key_p);
  free(signature_p);
  free(identity_key_p);
  axc_buf_free(pre_key_buf_p);
  axc_buf_free(signed_pre_key_buf_p);
  axc_buf_free(signature_buf_p);
  axc_buf_free(identity_key_buf_p);

  return ret_val;
}

/**
 * Wraps the omemo_message_export_encrypted message, so that it is called with the same options throughout.
 */
static int lurch_export_encrypted(omemo_message * om_msg_p, char ** xml_pp) {
  return omemo_message_export_encrypted(om_msg_p, OMEMO_ADD_MSG_EME, xml_pp);
}

/**
 * Implements JabberIqCallback.
 * Callback for a bundle request.
 */
static void lurch_bundle_request_cb(SERVER_REC * server, const char * from,
                                    /*JabberIqType*/ int type, const char * id,
                                    LmMessage * packet_p, gpointer data_p /*=qmsg_p*/) {
  int ret_val = 0;
  char * err_msg_conv = (void *) 0;
  char * err_msg_dbg = (void *) 0;

  char * uname = (void *) 0;
  char ** split = (void *) 0;
  char * device_id_str = (void *) 0;
  axc_address addr = {0};
  axc_context * axc_ctx_p = (void *) 0;
  char * recipient = (void *) 0;
  LmMessageNode * pubsub_node_p = (void *) 0;
  LmMessageNode * items_node_p = (void *) 0;
  int msg_handled = 0;
  char * addr_key = (void *) 0;
  char * msg_xml = (void *) 0;
  lurch_queued_msg * qmsg_p = (lurch_queued_msg *) data_p;

  uname = lurch_get_account(server, NULL);
  recipient = omemo_message_get_recipient_name_bare(qmsg_p->om_msg_p);

  if (!from) {
    // own user
    from = uname;
  }

  split = g_strsplit(id, "#", 3);
  device_id_str = split[1];

  debug_info("lurch", "%s: %s received bundle update from %s:%s\n", __func__, uname, from, device_id_str);

  addr.name = from;
  addr.name_len = strnlen(from, JABBER_MAX_LEN_BARE);
  addr.device_id = strtol(device_id_str, (void *) 0, 10);

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = "failed to get axc ctx";
    goto cleanup;
  }

  if (type == LM_MESSAGE_SUB_TYPE_ERROR) {
    err_msg_conv = g_strdup_printf("The device %s owned by %s does not have a bundle and will be skipped. "
                                   "The owner should fix this, or remove the device from the list.", device_id_str, from);

  } else {
    pubsub_node_p = lm_message_node_get_child(packet_p->node, "pubsub");
    if (!pubsub_node_p) {
      ret_val = LURCH_ERR;
      err_msg_dbg = "no <pubsub> node in response";
      goto cleanup;
    }

    items_node_p = lm_message_node_get_child(pubsub_node_p, "items");
    if (!items_node_p) {
      ret_val = LURCH_ERR;
      err_msg_dbg = "no <items> node in response";
      goto cleanup;
    }

    ret_val = axc_session_exists_initiated(&addr, axc_ctx_p);
    if (!ret_val) {
      ret_val = lurch_bundle_create_session(uname, from, items_node_p, axc_ctx_p);
      if (ret_val) {
        err_msg_dbg = "failed to create a session";
        goto cleanup;
      }
    } else if (ret_val < 0) {
      err_msg_dbg = "failed to check if session exists";
      goto cleanup;
    }
  }

  addr_key = lurch_queue_make_key_string_s(from, device_id_str);
  if (!addr_key) {
    err_msg_dbg = "failed to make a key string";
    ret_val = LURCH_ERR;
    goto cleanup;
  }

  (void) g_hash_table_replace(qmsg_p->sess_handled_p, addr_key, addr_key);

  if (lurch_queued_msg_is_handled(qmsg_p)) {
    msg_handled = 1;
  }

  if (msg_handled) {
    ret_val = lurch_msg_encrypt_for_addrs(qmsg_p->om_msg_p, qmsg_p->recipient_addr_l_p, axc_ctx_p);
    if (ret_val) {
      err_msg_dbg = "failed to encrypt the symmetric key";
      goto cleanup;
    }

    ret_val = lurch_export_encrypted(qmsg_p->om_msg_p, &msg_xml);
    if (ret_val) {
      err_msg_dbg = "failed to export the message to xml";
      goto cleanup;
    }

    //msg_node_p = xmlnode_from_str(msg_xml, -1);

    debug_info("lurch", "sending encrypted msg\n");
    signal_emit("lurch send message", 3, server, uname, msg_xml);
    //purple_signal_emit(purple_plugins_find_with_id("prpl-jabber"), "jabber-sending-xmlnode", ""/*js_p->gc*/, &msg_node_p);

    lurch_queued_msg_destroy(qmsg_p);
  }

cleanup:
  if (err_msg_conv) {
    printtext(server, recipient, MSGLEVEL_CLIENTERROR, "[lurch] %s", err_msg_conv);
    g_free(err_msg_conv);
  }
  if (err_msg_dbg) {
    printtext(server, recipient, MSGLEVEL_CLIENTERROR, "[lurch] %s", err_msg_dbg /* LURCH_ERR_STRING_ENCRYPT */);
    debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
  }

  free(uname);
  g_strfreev(split);
  axc_context_destroy_all(axc_ctx_p);
  free(addr_key);
  free(recipient);
  free(msg_xml);
    //xmlnode_free(msg_node_p);
}

typedef void (*PepCallbackFunc)(SERVER_REC *, const char *, LmMessageNode *);

static void irssi_lurch_peprequest_cb(SERVER_REC * server, LmMessage * lmsg, int type, const char * id, const char * from, const char * to)
{
  g_warning("incoming peprequest_cb - id: ##%s##", id);
  void * callback_p = g_hash_table_lookup(lurch_peprequest_response_ht, id);
  if (callback_p) {
    LmMessageNode * items = (void *) 0;
    LmMessageNode * node = lm_message_node_get_child(lmsg->node, "pubsub");
    if (node) {
      items = lm_message_node_get_child(node, "items");
    }
    ((PepCallbackFunc)(callback_p))(server, from, items);
    g_hash_table_remove(lurch_peprequest_response_ht, id);
  }
}

static void irssi_lurch_bundle_request_cb(SERVER_REC * server, LmMessage * lmsg, int type, const char * id, const char * from, const char * to)
{
  void * data_p = g_hash_table_lookup(lurch_bundle_request_ht, id);
  if (data_p) {
    char * xml = lm_message_node_to_string(lmsg->node);
    g_warning("found lurch_bundle_request with id ##%s##, message: ##%s##", id, xml);
    g_free(xml);
    
    lurch_bundle_request_cb(server, from,
			    type, id,
			    lmsg, data_p /*=qmsg_p*/);
    g_hash_table_remove(lurch_bundle_request_ht, id);
  }
}

/**
 * Requests a bundle.
 *
 * @param js_p Pointer to the JabberStream to use.
 * @param to The recipient of this request.
 * @param device_id The ID of the device whose bundle is needed.
 * @param qmsg_p Pointer to the queued message waiting on (at least) this bundle.
 * @return 0 on success, negative on error.
 */
// TODO
static int lurch_bundle_request_do(SERVER_REC * server,
                                   const char * to,
                                   uint32_t device_id,
                                   lurch_queued_msg * qmsg_p) {
  int ret_val = 0;

  LmMessage * jiq_p = (void *) 0;
  LmMessageNode * pubsub_node_p = (void *) 0;
  char * device_id_str = (void *) 0;
  char * rand_str = (void *) 0;
  char * req_id = (void *) 0;
  char * bundle_node_name = (void *) 0;
  /*xmlnode*/ void * items_node_p = (void *) 0;
  char * uname = (void *) 0;

  uname = lurch_get_account(server, NULL);
  debug_info("lurch", "%s: %s is requesting bundle from %s:%i\n", __func__, uname, to, device_id);

  jiq_p = lm_message_new_with_sub_type(to, LM_MESSAGE_TYPE_IQ, LM_MESSAGE_SUB_TYPE_GET);

  pubsub_node_p = lm_message_node_add_child(jiq_p->node, "pubsub", NULL);
  lm_message_node_set_attribute(pubsub_node_p, "xmlns", "http://jabber.org/protocol/pubsub");

  device_id_str = g_strdup_printf("%i", device_id);
  while (1) {
    char * rand_str = g_strdup_printf("%i", g_random_int());
    req_id = g_strconcat(to, "#", device_id_str, "#", rand_str, NULL);
    if (g_hash_table_lookup(lurch_bundle_request_ht, req_id) != NULL) {
      g_free(rand_str);
      g_free(req_id);
      continue;
    }
    break;
  }

  ret_val = omemo_bundle_get_pep_node_name(device_id, &bundle_node_name);
  if (ret_val) {
    debug_error("lurch", "%s: failed to get bundle pep node name for %s:%i\n", __func__, to, device_id);
    goto cleanup;
  }

  items_node_p = lm_message_node_add_child(pubsub_node_p, "items", NULL);
  lm_message_node_set_attribute(items_node_p, "node", bundle_node_name);
  lm_message_node_set_attribute(items_node_p, "max_items", "1");

  lm_message_node_set_attribute(jiq_p->node, "id", req_id);
  //jabber_iq_set_callback(jiq_p, lurch_bundle_request_cb, qmsg_p);
  g_hash_table_insert(lurch_bundle_request_ht, req_id, qmsg_p);

  signal_emit("xmpp send iq", 2, server, jiq_p);

  debug_info("lurch", "%s: ...request sent\n", __func__);

cleanup:
  if (jiq_p) {
    lm_message_unref(jiq_p);
  }
  g_free(uname);
  g_free(device_id_str);
  g_free(rand_str);
  g_free(req_id);
  g_free(bundle_node_name);

  return ret_val;
}

/**
 * A JabberPEPHandler function.
 * When a prekey message containing an invalid key ID is received,
 * the bundle of the sender is requested and a KeyTransport message is sent
 * in response so that a session can still be established.
 */
static void lurch_pep_bundle_for_keytransport(SERVER_REC * server, const char * from, LmMessageNode * items_p)
{
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  char * uname = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  uint32_t own_id = 0;
  omemo_message * msg_p = (void *) 0;
  axc_address addr = {0};
  lurch_addr laddr = {0};
  axc_buf * key_ct_buf_p = (void *) 0;
  char * msg_xml = (void *) 0;
  const char * bundle_node_name = (void *) 0;

  uname = lurch_get_account(server, NULL);

  addr.name = from;
  addr.name_len = strnlen(from, JABBER_MAX_LEN_BARE);
  if (!items_p) {
    err_msg_dbg = g_strdup_printf("invalid xml in bundle");
    goto cleanup;
  }
  bundle_node_name = lm_message_node_get_attribute(items_p, "node");
  addr.device_id = lurch_bundle_name_get_device_id(bundle_node_name);

  debug_info("lurch", "%s: %s received bundle from %s:%i\n", __func__, uname, from, addr.device_id);

  laddr.jid = g_strndup(addr.name, addr.name_len);
  laddr.device_id = addr.device_id;

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to init axc ctx");
    goto cleanup;
  }

  // make sure it's gonna be a pre_key_message
  ret_val = axc_session_delete(addr.name, addr.device_id, axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to delete possibly existing session");
    goto cleanup;
  }

  ret_val = lurch_bundle_create_session(uname, from, items_p, axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to create session");
    goto cleanup;
  }

  debug_info("lurch", "%s: %s created session with %s:%i\n", __func__, uname, from, addr.device_id);

  ret_val = axc_get_device_id(axc_ctx_p, &own_id);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get own device id");
    goto cleanup;
  }

  ret_val = omemo_message_create(own_id, &crypto, &msg_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to create omemo msg");
    goto cleanup;
  }

  ret_val = lurch_key_encrypt(&laddr,
                              omemo_message_get_key(msg_p),
                              omemo_message_get_key_len(msg_p),
                              axc_ctx_p,
                              &key_ct_buf_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to encrypt key for %s:%i", addr.name, addr.device_id);
    goto cleanup;
  }

  ret_val = omemo_message_add_recipient(msg_p,
                                        addr.device_id,
                                        axc_buf_get_data(key_ct_buf_p),
                                        axc_buf_get_len(key_ct_buf_p));
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to add %s:%i as recipient to message", addr.name, addr.device_id);
    goto cleanup;
  }

  // don't call wrapper function here as EME is not necessary
  ret_val = omemo_message_export_encrypted(msg_p, OMEMO_ADD_MSG_NONE, &msg_xml);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to export encrypted msg");
    goto cleanup;
  }

  signal_emit("lurch send keytransport", 3, server, from, msg_xml);
  debug_info("lurch", "%s: %s sent keytransportmsg to %s:%i\n", __func__, uname, from, addr.device_id);


cleanup:
  if (err_msg_dbg) {
    debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }
  free(laddr.jid);
  free(uname);
  axc_context_destroy_all(axc_ctx_p);
  omemo_message_destroy(msg_p);
  axc_buf_free(key_ct_buf_p);
  free(msg_xml);
}

/**
 * Processes a devicelist by updating the database with it.
 *
 * @param uname The username.
 * @param dl_in_p Pointer to the incoming devicelist.
 * @param js_p Pointer to the JabberStream.
 * @return 0 on success, negative on error.
 */
static int lurch_devicelist_process(char * uname, omemo_devicelist * dl_in_p, /* SERVER_REC */ void * server)
{
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  const char * from = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  omemo_devicelist * dl_db_p = (void *) 0;
  GList * add_l_p = (void *) 0;
  GList * del_l_p = (void *) 0;
  GList * curr_p = (void *) 0;
  uint32_t curr_id = 0;
  char * bundle_node_name = (void *) 0;

  char * debug_str = (void *) 0;

  from = omemo_devicelist_get_owner(dl_in_p);
  db_fn_omemo = lurch_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  debug_info("lurch", "%s: processing devicelist from %s for %s\n", __func__, from, uname);

  ret_val = omemo_storage_user_devicelist_retrieve(from, db_fn_omemo, &dl_db_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to retrieve cached devicelist for %s from db %s", from, db_fn_omemo);
    goto cleanup;
  }

  omemo_devicelist_export(dl_db_p, &debug_str);
  debug_info("lurch", "%s: %s\n%s\n", __func__, "cached devicelist is", debug_str);

  ret_val = omemo_devicelist_diff(dl_in_p, dl_db_p, &add_l_p, &del_l_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to diff devicelists");
    goto cleanup;
  }

  for (curr_p = add_l_p; curr_p; curr_p = curr_p->next) {
    curr_id = omemo_devicelist_list_data(curr_p);
    debug_info("lurch", "%s: saving %i for %s to db %s\n", __func__, curr_id, from, db_fn_omemo);
    ret_val = omemo_storage_user_device_id_save(from, curr_id, db_fn_omemo);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to save %i for %s to %s", curr_id, from, db_fn_omemo);
      goto cleanup;
    }
  }

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to init axc ctx");
    goto cleanup;
  }

  for (curr_p = del_l_p; curr_p; curr_p = curr_p->next) {
    curr_id = omemo_devicelist_list_data(curr_p);
    debug_info("lurch", "%s: deleting %i for %s to db %s\n", __func__, curr_id, from, db_fn_omemo);

    ret_val = omemo_storage_user_device_id_delete(from, curr_id, db_fn_omemo);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to delete %i for %s from %s", curr_id, from, db_fn_omemo);
      goto cleanup;
    }
  }

cleanup:
  if (err_msg_dbg) {
    debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }
  free(db_fn_omemo);
  omemo_devicelist_destroy(dl_db_p);
  axc_context_destroy_all(axc_ctx_p);
  g_list_free_full(add_l_p, free);
  g_list_free_full(del_l_p, free);
  free(bundle_node_name);
  free(debug_str);

  return ret_val;
}

/**
 * A JabberPEPHandler function.
 * Is used to handle the own devicelist and also perform install-time functions.
 */
static void lurch_pep_own_devicelist_request_handler(SERVER_REC * server, const char * from, LmMessageNode * items_p) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  char * uname = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  uint32_t own_id = 0;
  int needs_publishing = 1;
  omemo_devicelist * dl_p = (void *) 0;
  char * dl_xml = (void *) 0;

  uname = lurch_get_account(server, NULL);

  if (!uninstall) {
    debug_info("lurch", "%s: %s\n", __func__, "preparing installation...");
    ret_val = lurch_axc_prepare(uname);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to prepare axc");
      goto cleanup;
    }
    debug_info("lurch", "%s: %s\n", __func__, "...done");
  }

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to init axc ctx");
    goto cleanup;
  }
  ret_val = axc_get_device_id(axc_ctx_p, &own_id);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get own id");
    goto cleanup;
  }

  if (!items_p) {
    debug_info("lurch", "%s: %s\n", __func__, "no devicelist yet, creating it");
    ret_val = omemo_devicelist_create(uname, &dl_p);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to create devicelist");
      goto cleanup;
    }
    ret_val = omemo_devicelist_add(dl_p, own_id);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to add own id %i to devicelist", own_id);
      goto cleanup;
    }
  } else {
    char * items_xml = lm_message_node_to_string(items_p);
    debug_info("lurch", "%s: %s\n", __func__, "comparing received devicelist with cached one");
    ret_val = omemo_devicelist_import(items_xml, uname, &dl_p);
    g_free(items_xml);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to import received devicelist");
      goto cleanup;
    }

    ret_val = omemo_devicelist_contains_id(dl_p, own_id);
    if (ret_val == 1) {
      debug_info("lurch", "%s: %s\n", __func__, "own id was already contained in received devicelist, doing nothing");
      needs_publishing = 0;
    } else if (ret_val == 0) {
      if (!uninstall) {
        debug_info("lurch", "%s: %s\n", __func__, "own id was missing, adding it");
        ret_val = omemo_devicelist_add(dl_p, own_id);
        if (ret_val) {
          err_msg_dbg = g_strdup_printf("failed to add own id %i to devicelist", own_id);
          goto cleanup;
        }
      } else {
        needs_publishing = 0;
      }

    } else {
      err_msg_dbg = g_strdup_printf("failed to look up if the devicelist contains the own id");
      goto cleanup;
    }
  }

  if (needs_publishing) {
    debug_info("lurch", "%s: %s\n", __func__, "devicelist needs publishing...");
    ret_val = omemo_devicelist_export(dl_p, &dl_xml);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to export new devicelist");
      goto cleanup;
    }

    signal_emit("lurch peppublish devicelist", 3, server, from, dl_xml);
    // publish_node_dl_p = xmlnode_from_str(dl_xml, -1);
    // jabber_pep_publish(js_p, publish_node_dl_p);

    debug_info("lurch", "%s: \n%s:\n", __func__, "...done");
  }

  ret_val = lurch_bundle_publish_own(server);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to publish own bundle");
    goto cleanup;
  }

  ret_val = lurch_devicelist_process(uname, dl_p, server);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to process the devicelist");
    goto cleanup;
  }

cleanup:
  if (err_msg_dbg) {
    debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }
  g_free(uname);
  axc_context_destroy_all(axc_ctx_p);
  omemo_devicelist_destroy(dl_p);
  free(dl_xml);
}

/**
 * A JabberPEPHandler function.
 * On receiving a devicelist PEP updates the database entry.
 */
static void lurch_pep_devicelist_event_handler(SERVER_REC * server, const char * from, LmMessageNode * items_p) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;
  char * items_xml = (void *) 0;
  char * uname = (void *) 0;
  omemo_devicelist * dl_in_p = (void *) 0;

  uname = lurch_get_account(server, NULL);
  if (!strncmp(uname, from, strnlen(uname, JABBER_MAX_LEN_BARE))) {
    //own devicelist is dealt with in own handler
    lurch_pep_own_devicelist_request_handler(server, from, items_p);
    goto cleanup;
  }

  debug_info("lurch", "%s: %s received devicelist update from %s\n", __func__, uname, from);
  items_xml = lm_message_node_to_string(items_p);
  ret_val = omemo_devicelist_import(items_xml, from, &dl_in_p);
  g_free(items_xml);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to import devicelist");
    goto cleanup;
  }

  ret_val = lurch_devicelist_process(uname, dl_in_p, server);
  if(ret_val) {
    err_msg_dbg = g_strdup_printf("failed to process devicelist");
    goto cleanup;
  }

cleanup:
  if (err_msg_dbg) {
    debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    g_free(err_msg_dbg);
  }
  g_free(uname);
  omemo_devicelist_destroy(dl_in_p);
}

static void irssi_lurch_iq_cb(SERVER_REC * server, LmMessage * lmsg, int type, const char * id, const char * from, const char * to)
{
  LmMessageNode * events = lm_message_node_get_child(lmsg->node, "events");
  if (events) {
    LmMessageNode * items = lm_message_node_get_child(events, "items");
    const char * node = lm_message_node_get_attribute(items, "node");
    if (g_dl_ns != NULL && !g_strcmp0(node, g_dl_ns)) {
      lurch_pep_devicelist_event_handler(server, from, items);
    }
  }
}

/**
 * Set as callback for the "server connected" signal.
 * Requests the own devicelist, as that requires an active connection (as
 * opposed to just registering PEP handlers).
 * Also inits the msg queue hashtable.
 */
static void lurch_account_connect_cb(SERVER_REC * server)
{
  int ret_val = 0;

  char * uname = (void *) 0;
  char * dl_ns = (void *) 0;

  // purple_account_set_bool(acc_p, LURCH_ACC_SETTING_INITIALIZED, FALSE);

  //if (strncmp(purple_account_get_protocol_id(acc_p), JABBER_PROTOCOL_ID, strlen(JABBER_PROTOCOL_ID))) {
  //  return;
  //}

  ret_val = omemo_devicelist_get_pep_node_name(&dl_ns);
  if (ret_val) {
    debug_error("lurch", "%s: %s (%i)\n", __func__, "failed to get devicelist pep node name", ret_val);
    goto cleanup;
  }
  uname = lurch_get_account(server, NULL);
  //jabber_pep_request_item(js_p, uname, dl_ns, (void *) 0, lurch_pep_own_devicelist_request_handler);

  signal_emit("lurch peprequest own_devicelist", 4, server, uname, dl_ns, lurch_pep_own_devicelist_request_handler);

cleanup:
  g_free(uname);
  free(dl_ns);
}

/**
 * For a list of lurch_addrs, checks which ones do not have an active session.
 * Note that the structs are not copied, the returned list is just a subset
 * of the pointers of the input list.
 *
 * @param addr_l_p A list of pointers to lurch_addr structs.
 * @param axc_ctx_p The axc_context to use.
 * @param no_sess_l_pp Will point to a list that contains pointers to those
 *                     addresses that do not have a session.
 * @return 0 on success, negative on error.
 */
static int lurch_axc_sessions_exist(GList * addr_l_p, axc_context * axc_ctx_p, GList ** no_sess_l_pp)
{
  int ret_val = 0;

  GList * no_sess_l_p = (void *) 0;

  GList * curr_p;
  lurch_addr * curr_addr_p;
  axc_address curr_axc_addr = {0};
  for (curr_p = addr_l_p; curr_p; curr_p = curr_p->next) {
    curr_addr_p = (lurch_addr *) curr_p->data;

    curr_axc_addr.name = curr_addr_p->jid;
    curr_axc_addr.name_len = strnlen(curr_axc_addr.name, JABBER_MAX_LEN_BARE);
    curr_axc_addr.device_id = curr_addr_p->device_id;

    ret_val = axc_session_exists_initiated(&curr_axc_addr, axc_ctx_p);
    if (ret_val < 0) {
      debug_error("lurch", "%s: %s (%i)\n", __func__, "failed to see if session exists", ret_val);
      goto cleanup;
    } else if (ret_val > 0) {
      ret_val = 0;
      continue;
    } else {
      no_sess_l_p = g_list_prepend(no_sess_l_p, curr_addr_p);
      ret_val = 0;
    }
  }

  *no_sess_l_pp = no_sess_l_p;

cleanup:
  return ret_val;
}

/**
 * Adds an omemo devicelist to a GList of lurch_addrs.
 *
 * @param addrs_p Pointer to the list to add to. Remember NULL is a valid GList *.
 * @param dl_p Pointer to the omemo devicelist to add.
 * @param exclude_id_p Pointer to an ID that is not to be added. Useful when adding the own devicelist. Can be NULL.
 * @return Pointer to the updated GList on success, NULL on error.
 */
static GList * lurch_addr_list_add(GList * addrs_p, const omemo_devicelist * dl_p, const uint32_t * exclude_id_p) {
  int ret_val = 0;

  GList * new_l_p = addrs_p;
  GList * dl_l_p = (void *) 0;
  GList * curr_p = (void *) 0;
  lurch_addr curr_addr = {0};
  uint32_t curr_id = 0;
  lurch_addr * temp_addr_p = (void *) 0;

  curr_addr.jid = g_strdup(omemo_devicelist_get_owner(dl_p));

  dl_l_p = omemo_devicelist_get_id_list(dl_p);

  for (curr_p = dl_l_p; curr_p; curr_p = curr_p->next) {
    curr_id = omemo_devicelist_list_data(curr_p);
    if (exclude_id_p && *exclude_id_p == curr_id) {
      continue;
    }

    curr_addr.device_id = curr_id;

    temp_addr_p = malloc(sizeof(lurch_addr));
    if (!temp_addr_p) {
      ret_val = LURCH_ERR_NOMEM;
      goto cleanup;
    }

    memcpy(temp_addr_p, &curr_addr, sizeof(lurch_addr));

    new_l_p = g_list_prepend(new_l_p, temp_addr_p);
  }

cleanup:
  g_list_free_full(dl_l_p, free);

  if (ret_val) {
    g_list_free_full(new_l_p, lurch_addr_list_destroy_func);
    return (void *) 0;
  } else {
    return new_l_p;
  }
}

/**
 * Does the final steps of encrypting the message.
 * If all devices have sessions, does the actual encrypting.
 * If not, saves it and sends bundle request to the missing devices so that the message can be sent at a later time.
 *
 * Note that if msg_stanza_pp points to NULL, both om_msg_p and addr_l_p must not be freed by the calling function.
 *
 * @param js_p          Pointer to the JabberStream to use.
 * @param axc_ctx_p     Pointer to the axc_context to use.
 * @param om_msg_p      Pointer to the omemo message.
 * @param addr_l_p      Pointer to a GList of lurch_addr structs that are supposed to receive the message.
 * @param msg_stanza_pp Pointer to the pointer to the <message> stanza.
 *                      Is either changed to point to the encrypted message, or to NULL if the message is to be sent later.
 * @return 0 on success, negative on error.
 *
 */
static int lurch_msg_finalize_encryption(SERVER_REC * server, axc_context * axc_ctx_p, omemo_message * om_msg_p, GList * addr_l_p, LmMessage * lmsg) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  GList * no_sess_l_p = (void *) 0;
  char * xml = (void *) 0;
  lurch_queued_msg * qmsg_p = (void *) 0;
  GList * curr_item_p = (void *) 0;
  lurch_addr curr_addr = {0};

  ret_val = lurch_axc_sessions_exist(addr_l_p, axc_ctx_p, &no_sess_l_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to check if sessions exist");
    goto cleanup;
  }

  if (!no_sess_l_p) {
    //LmMessageNodeAttribute * a = (void *) 0;
    ret_val = lurch_msg_encrypt_for_addrs(om_msg_p, addr_l_p, axc_ctx_p);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to encrypt symmetric key for addrs");
      goto cleanup;
    }

    ret_val = lurch_export_encrypted(om_msg_p, &xml);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to export omemo msg to xml");
      goto cleanup;
    }

    omemo_message_destroy(om_msg_p);
    
    //temp_node_p = xmlnode_from_str(xml, -1);
    lm_message_node_set_raw_mode(lmsg->node, TRUE);
    // for (a = lmsg->node->attributes; a; a = a->next) {
    //   gchar *escaped;

    //   escaped = g_markup_escape_text (a->value, -1);
    //   g_free(a->value);
    //   a->value = escaped;
    // }
    lm_message_node_set_value(lmsg->node, xml);
    //*msg_stanza_pp = xml;
  } else {
    LmMessageNode * l = (void *) 0;
    ret_val = lurch_queued_msg_create(om_msg_p, addr_l_p, no_sess_l_p, &qmsg_p);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to create queued message");
      goto cleanup;
    }

    for (curr_item_p = no_sess_l_p; curr_item_p; curr_item_p = curr_item_p->next) {
      curr_addr.jid = ((lurch_addr *)curr_item_p->data)->jid;
      curr_addr.device_id = ((lurch_addr *)curr_item_p->data)->device_id;

      debug_info("lurch", "%s: %s has device without session %i, requesting bundle\n", __func__, curr_addr.jid, curr_addr.device_id);

      lurch_bundle_request_do(server,
                              curr_addr.jid,
                              curr_addr.device_id,
                              qmsg_p);

    }
    for (l = lmsg->node->children; l; ) {
        LmMessageNode *next = l->next;
        lm_message_node_unref(l);
	l = next;
    }
    lmsg->node->children = NULL;
    //*msg_stanza_pp = (void *) 0;
  }

cleanup:
  if (err_msg_dbg) {
    debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
    //*msg_stanza_pp = (void *) 0;
  }
  if (!qmsg_p || ret_val) {
    free(qmsg_p);
  }

  free(xml);

  return ret_val;
}


/**
 * Set as callback for the "sending xmlnode" signal.
 * Encrypts the message body, if applicable.
 */
static void lurch_message_encrypt_im(SERVER_REC *server, LmMessage *lmsg)
{
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  char * uname = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  const char * to = (void *) 0;
  omemo_devicelist * dl_p = (void *) 0;
  GList * recipient_dl_p = (void *) 0;
  omemo_devicelist * user_dl_p = (void *) 0;
  GList * own_dl_p = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  uint32_t own_id = 0;
  omemo_message * msg_p = (void *) 0;
  GList * addr_l_p = (void *) 0;
  char * recipient = (void *) 0;
  char * tempxml = (void *) 0;

  recipient = lurch_get_bare_jid(lm_message_node_get_attribute(lmsg->node, "to"));

  uname = lurch_get_account(server, NULL);
  db_fn_omemo = lurch_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  ret_val = omemo_storage_chatlist_exists(recipient, db_fn_omemo);
  if (ret_val < 0) {
    err_msg_dbg = g_strdup_printf("failed to look up %s in DB %s", recipient, db_fn_omemo);
    goto cleanup;
  } else if (ret_val == 1) {
    debug_info("lurch", "%s: %s is on blacklist, skipping encryption\n", __func__, recipient);
    goto cleanup;
  }

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get axc ctx for %s", uname);
    goto cleanup;
  }

  ret_val = axc_get_device_id(axc_ctx_p, &own_id);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get device id");
    goto cleanup;
  }
  tempxml = lm_message_node_to_string(lmsg->node);
  ret_val = omemo_message_prepare_encryption(tempxml, own_id, &crypto, OMEMO_STRIP_ALL, &msg_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to construct omemo message");
    goto cleanup;
  }

  to = omemo_message_get_recipient_name_bare(msg_p);

  // determine if recipient is omemo user
  ret_val = omemo_storage_user_devicelist_retrieve(to, db_fn_omemo, &dl_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to retrieve devicelist for %s", to);
    goto cleanup;
  }

  g_free(tempxml);
  ret_val = omemo_devicelist_export(dl_p, &tempxml);
  if(ret_val) {
    err_msg_dbg = g_strdup_printf("failed to export devicelist for %s", to);
    goto cleanup;
  }
  debug_info("lurch", "retrieved devicelist for %s:\n%s\n", to, tempxml);

  recipient_dl_p = omemo_devicelist_get_id_list(dl_p);
  if (!recipient_dl_p) {
    ret_val = axc_session_exists_any(to, axc_ctx_p);
    if (ret_val < 0) {
      err_msg_dbg = g_strdup_printf("failed to check if session exists for %s in %s's db\n", to, uname);
      goto cleanup;
    } else if (ret_val == 1) {
      printtext(server, recipient, MSGLEVEL_CLIENTNOTICE, "[lurch] %s", "Even though an encrypted session exists, the recipient's devicelist is empty."
		"The user probably uninstalled OMEMO, so you can add this conversation to the blacklist.");
    } else {
      goto cleanup;
    }
  }

  ret_val = omemo_storage_user_devicelist_retrieve(uname, db_fn_omemo, &user_dl_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to retrieve devicelist for %s", uname);
    goto cleanup;
  }
  omemo_devicelist_export(user_dl_p, &tempxml);
  debug_info("lurch", "retrieved own devicelist:\n%s\n", tempxml);
  own_dl_p = omemo_devicelist_get_id_list(user_dl_p);
  if (!own_dl_p) {
    err_msg_dbg = g_strdup_printf("no own devicelist");
    goto cleanup;
  }

  addr_l_p = lurch_addr_list_add(addr_l_p, user_dl_p, &own_id);
  if (g_strcmp0(uname, to)) {
    addr_l_p = lurch_addr_list_add(addr_l_p, dl_p, (void *) 0);
  }

  ret_val = lurch_msg_finalize_encryption(server, axc_ctx_p, msg_p, addr_l_p, lmsg);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to finalize omemo message");
    goto cleanup;
  }

cleanup:
  if (err_msg_dbg) {
    printtext(server, recipient, MSGLEVEL_CLIENTERROR, "[lurch] %s", err_msg_dbg /* LURCH_ERR_STRING_ENCRYPT */);
    debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
    //*msg_stanza_pp = (void *) 0;
  }
  if (ret_val) {
    omemo_message_destroy(msg_p);
    g_list_free_full(addr_l_p, lurch_addr_list_destroy_func);
  }
  free(recipient);
  free(uname);
  free(db_fn_omemo);
  omemo_devicelist_destroy(dl_p);
  g_list_free_full(recipient_dl_p, free);
  omemo_devicelist_destroy(user_dl_p);
  g_list_free_full(own_dl_p, free);
  axc_context_destroy_all(axc_ctx_p);
  free(tempxml);
}

static void lurch_message_encrypt_groupchat(SERVER_REC *server, LmMessage *lmsg)
{
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  char * uname = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  uint32_t own_id = 0;
  char * tempxml = (void *) 0;
  omemo_message * om_msg_p = (void *) 0;
  omemo_devicelist * user_dl_p = (void *) 0;
  GList * addr_l_p = (void *) 0;
  CHANNEL_REC * conv_p = (void *) 0;
  NICK_REC * curr_muc_member_p = (void *) 0;
  LmMessageNode * body_node_p = (void *) 0;
  GList * curr_item_p = (void *) 0;
  char * curr_muc_member_jid = (void *) 0;
  char * curr_muc_member_jid_bare = (void *) 0;
  omemo_devicelist * curr_dl_p = (void *) 0;

  const char * to = lm_message_node_get_attribute(lmsg->node, "to");

  uname = lurch_get_account(server, NULL);
  db_fn_omemo = lurch_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  ret_val = omemo_storage_chatlist_exists(to, db_fn_omemo);
  if (ret_val < 0) {
    err_msg_dbg = g_strdup_printf("failed to access db %s", db_fn_omemo);
    goto cleanup;
  } else if (ret_val == 0) {
    goto cleanup;
  }

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get axc ctx for %s", uname);
    goto cleanup;
  }

  ret_val = axc_get_device_id(axc_ctx_p, &own_id);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get device id");
    goto cleanup;
  }
  tempxml = lm_message_node_to_string(lmsg->node);
  ret_val = omemo_message_prepare_encryption(tempxml, own_id, &crypto, OMEMO_STRIP_ALL, &om_msg_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to construct omemo message");
    goto cleanup;
  }

  ret_val = omemo_storage_user_devicelist_retrieve(uname, db_fn_omemo, &user_dl_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to retrieve devicelist for %s", uname);
    goto cleanup;
  }

  addr_l_p = lurch_addr_list_add(addr_l_p, user_dl_p, &own_id);

  conv_p = channel_find(server, to);
  if (!conv_p) {
    err_msg_dbg = g_strdup_printf("could not find groupchat %s", to);
    goto cleanup;
  }

  for (curr_item_p = g_hash_table_get_values(conv_p->nicks); curr_item_p; curr_item_p = curr_item_p->next) {
    curr_muc_member_p = (NICK_REC *) curr_item_p->data;
    curr_muc_member_jid = strchr(to, '@') != NULL ? g_strdup(curr_muc_member_p->host) : lurch_irssi_nick_get_name(server, curr_muc_member_p->nick);
    curr_muc_member_jid_bare = lurch_get_bare_jid(curr_muc_member_jid);

    if (!g_strcmp0(to, curr_muc_member_jid_bare)) {
      err_msg_dbg = g_strdup_printf("Could not find the JID for %s - the channel needs to be non-anonymous!", curr_muc_member_p->nick);
      printtext(server, to, MSGLEVEL_CLIENTERROR, "[lurch] %s", err_msg_dbg);
      g_free(err_msg_dbg);
      err_msg_dbg = (void *) 0;

      g_free(curr_muc_member_jid_bare);
      g_free(curr_muc_member_jid);
      continue;
    }

    // libpurple (rightly) assumes that in MUCs the message will come back anyway so it's not written to the chat
    // but encrypting and decrypting for yourself should not be done with the double ratchet, so the own device is skipped
    // and the typed message written to the chat window manually without sending
    if (!g_strcmp0(curr_muc_member_jid, uname)) {
      body_node_p = lm_message_node_get_child(lmsg->node, "body");

      if (body_node_p) {
	signal_emit("message xmpp own_public", 3, server, lm_message_node_get_value(body_node_p), conv_p->name);
      }
      
      g_free(curr_muc_member_jid_bare);
      g_free(curr_muc_member_jid);
      continue;
    }

    ret_val = omemo_storage_user_devicelist_retrieve(curr_muc_member_jid, db_fn_omemo, &curr_dl_p);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("Could not retrieve the devicelist for %s from %s", curr_muc_member_jid, db_fn_omemo);

      g_free(curr_muc_member_jid_bare);
      g_free(curr_muc_member_jid);
      goto cleanup;
    }

    if (omemo_devicelist_is_empty(curr_dl_p)) {
      err_msg_dbg = g_strdup_printf("User %s is no OMEMO user (does not have a devicelist). "
                                    "This user cannot read any incoming encrypted messages and will send his own messages in the clear!",
                                    curr_muc_member_jid);
      printtext(server, to, MSGLEVEL_CLIENTERROR, "[lurch] %s", err_msg_dbg);
      g_free(err_msg_dbg);
      err_msg_dbg = (void *) 0;

      g_free(curr_muc_member_jid_bare);
      g_free(curr_muc_member_jid);
      continue;
    }

    addr_l_p = lurch_addr_list_add(addr_l_p, curr_dl_p, (void *) 0);
    omemo_devicelist_destroy(curr_dl_p);
    curr_dl_p = (void *) 0;

    g_free(curr_muc_member_jid_bare);
    g_free(curr_muc_member_jid);
  }

  ret_val = lurch_msg_finalize_encryption(server, axc_ctx_p, om_msg_p, addr_l_p, lmsg);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to finalize msg");
    goto cleanup;
  }

  //TODO: properly handle this instead of removing the body completely, necessary for full EME support
  lm_message_node_set_value(lm_message_node_get_child(lmsg->node, "body"), "[Encrypted with OMEMO]");


cleanup:
  if (err_msg_dbg) {
    printtext(server, to, MSGLEVEL_CLIENTERROR, "[lurch] %s", err_msg_dbg /* LURCH_ERR_STRING_ENCRYPT */);
    debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
    //*msg_stanza_pp = (void *) 0;
  }
  if (ret_val) {
    omemo_message_destroy(om_msg_p);
    g_list_free_full(addr_l_p, lurch_addr_list_destroy_func);
  }

  free(uname);
  free(db_fn_omemo);
  axc_context_destroy_all(axc_ctx_p);
  g_free(tempxml);
  omemo_devicelist_destroy(user_dl_p);
}

static void lurch_xml_sent_cb(SERVER_REC *server, LmMessage *lmsg)
{
  LmMessageNode * body_node_p = (void *) 0;
  LmMessageNode * encrypted_node_p = (void *) 0;
  int type = lm_message_get_sub_type(lmsg);

  if (uninstall) {
    return;
  }

  body_node_p = lm_message_node_get_child(lmsg->node, "body");
  if (!body_node_p) {
    return;
  }

  encrypted_node_p = lm_message_node_get_child(lmsg->node, "encrypted");
  if (encrypted_node_p) {
    return;
  }

  if (type == LM_MESSAGE_SUB_TYPE_CHAT) {
    lurch_message_encrypt_im(server, lmsg);
  } else if (type == LM_MESSAGE_SUB_TYPE_GROUPCHAT) {
    lurch_message_encrypt_groupchat(server, lmsg);
  }
}

/**
 * Callback for the "receiving xmlnode" signal.
 * Decrypts message, if applicable.
 */
static void lurch_message_decrypt(SERVER_REC * server, LmMessage * lmsg, int type, const char * id, const char * from, const char * to) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  omemo_message * msg_p = (void *) 0;
  char * uname = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  uint32_t own_id = 0;
  uint8_t * key_p = (void *) 0;
  size_t key_len = 0;
  axc_buf * key_buf_p = (void *) 0;
  axc_buf * key_decrypted_p = (void *) 0;
  char * sender_name = (void *) 0;
  axc_address sender_addr = {0};
  char * bundle_node_name = (void *) 0;
  omemo_message * keytransport_msg_p = (void *) 0;
  char * xml = (void *) 0;
  char * sender = (void *) 0;
  char ** split = (void *) 0;
  char * room_name = (void *) 0;
  char * buddy_nick = (void *) 0;
  mxml_node_t * plaintext_msg_node_p = (void *) 0;
  mxml_node_t * body_node_p = (void *) 0;
  LmMessageNode * lm_body_node_p = (void *) 0;
  char * recipient_bare_jid = (void *) 0;
  CHANNEL_REC * conv_p = (void *) 0;
  NICK_REC * muc_member_p = (void *) 0;

  if (uninstall) {
    goto cleanup;
  }

  uname = lurch_get_account(server, NULL);
  db_fn_omemo = lurch_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  // on prosody and possibly other servers, messages to the own account do not have a recipient
  if (!to) {
    recipient_bare_jid = g_strdup(uname);
  } else {
    recipient_bare_jid = lurch_get_bare_jid(to);
  }

  if (type == LM_MESSAGE_SUB_TYPE_CHAT) {
    sender = lurch_get_bare_jid(from);

    ret_val = omemo_storage_chatlist_exists(sender, db_fn_omemo);
    if (ret_val < 0) {
      err_msg_dbg = g_strdup_printf("failed to look up %s in %s", sender, db_fn_omemo);
      goto cleanup;
    } else if (ret_val == 1) {
      printtext(server, from, MSGLEVEL_CLIENTNOTICE, "[lurch] %s", "Received encrypted message in blacklisted conversation.");
    }
  } else if (type == LM_MESSAGE_SUB_TYPE_GROUPCHAT) {
    char * buddy_jid = (void *) 0;
    split = g_strsplit(from, "/", 2);
    room_name = split[0];
    buddy_nick = split[1];

    ret_val = omemo_storage_chatlist_exists(room_name, db_fn_omemo);
    if (ret_val < 0) {
      err_msg_dbg = g_strdup_printf("failed to look up %s in %s", room_name, db_fn_omemo);
      goto cleanup;
    } else if (ret_val == 0) {
      printtext(server, from, MSGLEVEL_CLIENTNOTICE, "[lurch] %s", "Received encrypted message in non-OMEMO room.");
    }

    conv_p = channel_find(server, room_name);
    if (!conv_p) {
      err_msg_dbg = g_strdup_printf("could not find groupchat %s", room_name);
      goto cleanup;
    }

    muc_member_p = nicklist_find(conv_p, buddy_nick);
    if (!muc_member_p) {
      debug_info("lurch", "Received OMEMO message in MUC %s, but the sender %s is not present in the room, which can happen during history catchup. Skipping.\n", room_name, buddy_nick);
      goto cleanup;
    }

    buddy_jid = strchr(room_name, '@') != NULL ? g_strdup(muc_member_p->host) : lurch_irssi_nick_get_name(server, muc_member_p->nick);
    sender = lurch_get_bare_jid(buddy_jid);
    g_free(buddy_jid);

    if (!g_strcmp0(sender, room_name)) {
      err_msg_dbg = g_strdup_printf("jid for user %s in muc %s not found, is the room anonymous?", buddy_nick, room_name);
      goto cleanup;
    }
  }

  xml = lm_message_node_to_string(lmsg->node);
  ret_val = omemo_message_prepare_decryption(xml, &msg_p);
  g_free(xml);
  xml = (void *) 0;
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed import msg for decryption");
    goto cleanup;
  }

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get axc ctx for %s", uname);
    goto cleanup;
  }

  ret_val = axc_get_device_id(axc_ctx_p, &own_id);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get own device id");
    goto cleanup;
  }

  ret_val = omemo_message_get_encrypted_key(msg_p, own_id, &key_p, &key_len);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get key for own id %i", own_id);
    goto cleanup;
  }
  if (!key_p) {
    debug_info("lurch", "received omemo message that does not contain a key for this device, skipping\n");
    goto cleanup;
  }

  key_buf_p = axc_buf_create(key_p, key_len);
  if (!key_buf_p) {
    err_msg_dbg = g_strdup_printf("failed to create buf for key");
    goto cleanup;
  }

  sender_addr.name = sender;
  sender_addr.name_len = strnlen(sender_addr.name, JABBER_MAX_LEN_BARE);
  sender_addr.device_id = omemo_message_get_sender_id(msg_p);

  ret_val = axc_pre_key_message_process(key_buf_p, &sender_addr, axc_ctx_p, &key_decrypted_p);
  if (ret_val == AXC_ERR_NOT_A_PREKEY_MSG) {
    if (axc_session_exists_initiated(&sender_addr, axc_ctx_p)) {
      ret_val = axc_message_decrypt_from_serialized(key_buf_p, &sender_addr, axc_ctx_p, &key_decrypted_p);
      if (ret_val) {
        if (ret_val == SG_ERR_DUPLICATE_MESSAGE && !g_strcmp0(sender, uname) && !g_strcmp0(recipient_bare_jid, uname)) {
          // in combination with message carbons, sending a message to your own account results in it arriving twice
          debug_warning("lurch", "ignoring decryption error due to a duplicate message from own account to own account\n");
          //*msg_stanza_pp = (void *) 0; // XXX
          goto cleanup;
        } else {
          err_msg_dbg = g_strdup_printf("failed to decrypt key");
          goto cleanup;
        }
      }
    } else {
      debug_info("lurch", "received omemo message but no session with the device exists, ignoring\n");
      goto cleanup;
    }
  } else if (ret_val == AXC_ERR_INVALID_KEY_ID) {
    ret_val = omemo_bundle_get_pep_node_name(sender_addr.device_id, &bundle_node_name);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to get bundle pep node name");
      goto cleanup;
    }

    signal_emit("lurch peprequest bundle", 4, server, sender_addr.name, bundle_node_name, lurch_pep_bundle_for_keytransport);
    // jabber_pep_request_item(purple_connection_get_protocol_data(gc_p),
    //                         sender_addr.name, bundle_node_name,
    //                         (void *) 0,
    //                         lurch_pep_bundle_for_keytransport);

  } else if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to prekey msg");
    goto cleanup;
  } else {
    lurch_bundle_publish_own(server);
  }

  if (!omemo_message_has_payload(msg_p)) {
    debug_info("lurch", "received keytransportmsg\n");
    goto cleanup;
  }

  ret_val = omemo_message_export_decrypted(msg_p, axc_buf_get_data(key_decrypted_p), axc_buf_get_len(key_decrypted_p), &crypto, &xml);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to decrypt payload");
    goto cleanup;
  }

  plaintext_msg_node_p = mxmlLoadString((void *) 0, xml, MXML_OPAQUE_CALLBACK);

  // libpurple doesn't know what to do with incoming messages addressed to someone else, so they need to be written to the conversation manually
  // incoming messages from the own account in MUCs are fine though
  /* if (!g_strcmp0(sender, uname) && !g_strcmp0(type, "chat")) { */
  /*   conv_p = purple_find_conversation_with_account(5/\*PURPLE_CONV_TYPE_IM*\/, recipient_bare_jid, purple_connection_get_account(gc_p)); */
  /*   if (!conv_p) { */
  /*     conv_p = purple_conversation_new(5/\*PURPLE_CONV_TYPE_IM*\/, purple_connection_get_account(gc_p), recipient_bare_jid); */
  /*   } */
  /*   purple_conversation_write(conv_p, uname, xmlnode_get_data(xmlnode_get_child(plaintext_msg_node_p, "body")), 6/\*PURPLE_MESSAGE_SEND*\/, time((void *) 0)); */
  /*   *msg_stanza_pp = (void *) 0; */
  /* } else { */
  /*   *msg_stanza_pp = plaintext_msg_node_p; */
  /* } */

  g_warning("the decoded xml was: ##%s##", xml);
  body_node_p = mxmlFindPath(plaintext_msg_node_p, "body");
  if (!body_node_p) {
    goto cleanup;
  }

  lm_body_node_p = lm_message_node_get_child(lmsg->node, "body");
  if (!lm_body_node_p) {
    lm_body_node_p = lm_message_node_add_child(lmsg->node, "body", NULL);
  }
  lm_message_node_set_value(lm_body_node_p, mxmlGetOpaque(body_node_p));


cleanup:
  mxmlRelease(plaintext_msg_node_p);

  if (err_msg_dbg) {
    printtext(server, from, MSGLEVEL_CLIENTERROR, "[lurch] %s", err_msg_dbg /* LURCH_ERR_STRING_DECRYPT */);
    debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }

  g_free(xml);
  g_strfreev(split);
  free(sender);
  free(xml);
  free(bundle_node_name);
  free(sender_name);
  axc_buf_free(key_decrypted_p);
  axc_buf_free(key_buf_p);
  free(key_p);
  axc_context_destroy_all(axc_ctx_p);
  free(uname);
  free(db_fn_omemo);
  free(recipient_bare_jid);
  omemo_message_destroy(keytransport_msg_p);
  omemo_message_destroy(msg_p);
}

static void lurch_message_warn(SERVER_REC * server, LmMessage * lmsg, int type, const char * id, const char * from, const char * to)
{
  int ret_val = 0;

  /*xmlnode*/ void * temp_node_p = (void *) 0;
  char * uname = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  char * conv_name = (void *) 0;
  char ** split = (void *) 0;
  char * room_name = (void *) 0;

  uname = lurch_get_account(server, NULL);
  db_fn_omemo = lurch_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    goto cleanup;
  }

  temp_node_p = lm_message_node_get_child(lmsg->node, "body");
  if (!temp_node_p) {
    goto cleanup;
  }

  if (type == LM_MESSAGE_SUB_TYPE_CHAT) {
    conv_name = lurch_get_bare_jid(from);

    ret_val = axc_session_exists_any(conv_name, axc_ctx_p);
    if (ret_val < 0) {
      goto cleanup;
    } else if (ret_val == 0) {
      goto cleanup;
    } else if (ret_val == 1) {
      ret_val = omemo_storage_chatlist_exists(conv_name, db_fn_omemo);
      if (ret_val == 0) {
        printtext(server, from, MSGLEVEL_CLIENTNOTICE, "[lurch] %s",
                                  "Even though you have an encryption session with this user, you received a plaintext message.");
      }
    } else {
      debug_error("lurch", "%s: (%i)\n", __func__, ret_val);
    }
  } else if (type == LM_MESSAGE_SUB_TYPE_GROUPCHAT) {
    split = g_strsplit(from, "/", 2);
    room_name = split[0];

    ret_val = omemo_storage_chatlist_exists(room_name, db_fn_omemo);
    if (ret_val < 0) {
      goto cleanup;
    } else if (ret_val == 0) {
      goto cleanup;
    } else if (ret_val == 1) {
      printtext(server, room_name, MSGLEVEL_CLIENTNOTICE, "[lurch] %s",
                                "This groupchat is set to encrypted, but you received a plaintext message.");
    }
  }

cleanup:
  g_free(uname);
  free(db_fn_omemo);
  free(conv_name);
  g_strfreev(split);
  axc_context_destroy_all(axc_ctx_p);
}

static void lurch_xml_received_cb(SERVER_REC * server, LmMessage * lmsg, int type, const char * id, const char * from, const char * to) {
  LmMessageNode * temp_node_p = (void *) 0;

  if (uninstall) {
    return;
  }

  temp_node_p = lm_message_node_get_child(lmsg->node, "encrypted");
  if (temp_node_p) {
    lurch_message_decrypt(server, lmsg, type, id, from, to);
  } else {
    lurch_message_warn(server, lmsg, type, id, from, to);
  }
}

static char * lurch_expando_encryption_omemo(SERVER_REC * server, WI_ITEM_REC * item, gboolean * free_ret)
{
  int ret_val = 0;

  char * uname = (void *) 0;
  char * partner_name = lurch_irssi_conversation_get_name(item);
  char * partner_name_bare = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  omemo_devicelist * dl_p = (void *) 0;

  char * new_title = (void *) 0;

  uname = lurch_get_account(server, item);
  db_fn_omemo = lurch_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);
  partner_name_bare = lurch_get_bare_jid(partner_name);

  if (uninstall) {
    goto cleanup;
  }

  ret_val = omemo_storage_chatlist_exists(partner_name_bare, db_fn_omemo);
  if (ret_val < 0 || ret_val > 0) {
    goto cleanup;
  }

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    goto cleanup;
  }

  ret_val = axc_session_exists_any(partner_name_bare, axc_ctx_p);
  if (ret_val < 0) {
    goto cleanup;
  } else if (ret_val) {
    new_title = g_strdup("OMEMO");

  } else {
    ret_val = omemo_storage_user_devicelist_retrieve(partner_name_bare, db_fn_omemo, &dl_p);
    if (ret_val) {
      goto cleanup;
    }

    if (!omemo_devicelist_is_empty(dl_p)) {
      new_title = g_strdup_printf("OMEMO available");
    }
  }

cleanup:
  free(uname);
  free(new_title);
  axc_context_destroy_all(axc_ctx_p);
  free(db_fn_omemo);
  omemo_devicelist_destroy(dl_p);
  g_free(partner_name);
  free(partner_name_bare);

  if (new_title) {
    *free_ret = TRUE;
  }

  return new_title;
}

static void lurch_conv_created_cb(WI_ITEM_REC * item, gboolean automatic) {
  gboolean free_ret = FALSE;
  char * title = lurch_expando_encryption_omemo(item->server, item, &free_ret);
  char * name = lurch_irssi_conversation_get_name(item);
  printtext(item->server, item->name, MSGLEVEL_CLIENTNOTICE, "[lurch] %s (omemo status: %s)", name, title);
  g_free(name);
  if (free_ret) {
    g_free(title);
  }
}

static char * lurch_fp_printable_x(const guchar * data, gsize len)
{
  int i;
  gchar * out = (void *) 0;

  out = g_malloc(len * 2 + len / 4 + 1);
  for (i = 0; i < len; ++i) {
    g_snprintf(&out[i * 2 + i / 4], 3, "%02hhx", data[i]);
    if (i % 4 == 3) {
      g_snprintf(&out[i * 2 + i / 4 + 2], 2, " ");
    }
  }
  return out;
}

static char * lurch_fp_printable(const char * fp) __attribute__((unused));
/**
 * Creates a fingerprint which resembles the one displayed by Conversations etc.
 * Also useful for avoiding the smileys produced by ':d'...
 *
 * @param fp The fingerprint string as returned by purple_base16_encode_chunked
 * @return A newly allocated string which contains the fingerprint in printable format, or NULL.
 */
static char * lurch_fp_printable(const char * fp) {
  char ** split = (void *) 0;
  char * temp1 = (void *) 0;
  char * temp2 = (void *) 0;

  if (!fp) {
    return (void *) 0;
  }

  split = g_strsplit(fp, ":", 0);
  temp2 = g_strdup("");

  for (int i = 1; i <= 32; i += 4) {
    temp1 = g_strconcat(temp2, split[i], split[i+1], split[i+2], split[i+3], " ", NULL);
    g_free(temp2);
    temp2 = g_strdup(temp1);
    g_free(temp1);
  }

  g_strfreev(split);
  return temp2;
}

static void lurch_cmd_func(const char * data, SERVER_REC * server, WI_ITEM_REC * item)
{
  int ret_val = 0;
  char * err_msg = (void *) 0;

  char * uname = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  uint32_t id = 0;
  uint32_t remove_id = 0;
  axc_buf * key_buf_p = (void *) 0;
  gchar * fp = (void *) 0;
  char * fp_printable = (void *) 0;
  omemo_devicelist * own_dl_p = (void *) 0;
  omemo_devicelist * other_dl_p = (void *) 0;
  GList * own_l_p = (void *) 0;
  GList * other_l_p = (void *) 0;
  GList * curr_p = (void *) 0;
  char * temp_msg_1 = (void *) 0;
  char * temp_msg_2 = (void *) 0;
  char * temp_msg_3 = (void *) 0;
  char * bare_jid = (void *) 0;
  char * conversation_jid = (void *) 0;

  char * msg = (void *) 0;

  GError * error = (void *) 0;
  int argc = 0;
  char ** args = {0};
  if (!g_shell_parse_argv(data, &argc, &args, &error)) {
    err_msg = g_strdup(error->message);
    g_error_free(error);
    goto cleanup;
  }

  if (server == NULL && item == NULL && !!g_strcmp0(args[0], "help")) {
    err_msg = g_strdup("Not connected.");
    goto cleanup;
  }

  if (server != NULL || item != NULL) {
    uname = lurch_get_account(server, item);
    db_fn_omemo = lurch_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

    ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
    if (ret_val) {
      err_msg = g_strdup("Failed to create axc ctx.");
      goto cleanup;
    }

    ret_val = axc_get_device_id(axc_ctx_p, &id);
    if (ret_val) {
      err_msg = g_strdup_printf("Failed to access axc db %s. Does the path seem correct?", axc_context_get_db_fn(axc_ctx_p));
      goto cleanup;
    }
  }

  if (!g_strcmp0(args[0], "uninstall")) {
    if (!g_strcmp0(args[1], "yes")) {
      ret_val = omemo_devicelist_get_pep_node_name(&temp_msg_1);
      if (ret_val) {
        err_msg = g_strdup("Failed to get devicelist PEP node name.");
        goto cleanup;
      }

      ret_val = omemo_storage_user_devicelist_retrieve(uname, db_fn_omemo, &own_dl_p);
      if (ret_val) {
        err_msg = g_strdup_printf("Failed to access omemo db %s. Does the path seem correct?", db_fn_omemo);
        goto cleanup;
      }

      ret_val = axc_get_device_id(axc_ctx_p, &remove_id);
      if (ret_val) {
        err_msg = g_strdup_printf("Failed to get own ID from DB %s.", axc_context_get_db_fn(axc_ctx_p));
        goto cleanup;
      }

      ret_val = omemo_devicelist_remove(own_dl_p, remove_id);
      if (ret_val) {
        err_msg = g_strdup_printf("Failed to remove %i from the list in DB %s.", remove_id, db_fn_omemo);
        goto cleanup;
      }

      ret_val = omemo_devicelist_export(own_dl_p, &temp_msg_1);
      if (ret_val) {
        err_msg = g_strdup("Failed to export new devicelist to xml string.");
        goto cleanup;
      }

      uninstall = 1;
      signal_emit("lurch peppublish devicelist", 3, server, uname, temp_msg_1);

      //dl_node_p = xmlnode_from_str(temp_msg_1, -1);
      //jabber_pep_publish(purple_connection_get_protocol_data(purple_conversation_get_gc(conv_p)), dl_node_p);
      msg = g_strdup_printf("Published devicelist minus this device's ID. "
                            "You can deactivate the plugin now, otherwise it will be republished at the next startup. "
                            "To delete all existing data you also have to delete the DB files in your ~/.irssi folder.");
    } else {
      msg = g_strdup("To uninstall lurch for this device, type 'lurch uninstall yes'.");
    }
  } else if (!g_strcmp0(args[0], "help")) {
    msg = g_strdup("The following commands exist to interact with the lurch plugin:\n\n"
                   "In conversations with one user:\n"
                   " - '/lurch blacklist add': Adds conversation partner to blacklist.\n"
                   " - '/lurch blacklist remove': Removes conversation partner from blacklist.\n"
                   " - '/lurch show id own': Displays this device's ID.\n"
                   " - '/lurch show id list': Displays this account's devicelist.\n"
                   " - '/lurch show fp own': Displays this device's key fingerprint.\n"
                   " - '/lurch show fp conv': Displays the fingerprints of all participating devices.\n"
                   " - '/lurch remove id <id>': Removes a device ID from the own devicelist.\n"
                   "\n"
                   "In conversations with multiple users:\n"
                   " - '/lurch enable': Enables OMEMO encryption for the conversation.\n"
                   " - '/lurch disable': Disables OMEMO encryption for the conversation.\n"
                   "\n"
                   "In all types of conversations:\n"
                   " - '/lurch help': Displays this message.\n"
                   " - '/lurch uninstall': Uninstalls this device from OMEMO by removing its device ID from the devicelist.");
  } else {
    if(IS_QUERY(item)) {
      if (!g_strcmp0(args[0], "blacklist")) {
        if (!g_strcmp0(args[1], "add")) {
	  conversation_jid = lurch_irssi_conversation_get_name(item);
          temp_msg_1 = lurch_get_bare_jid(conversation_jid);
          ret_val = omemo_storage_chatlist_save(temp_msg_1, db_fn_omemo);
          if (ret_val) {
            err_msg = g_strdup_printf("Failed to look up %s in DB %s.", temp_msg_1, db_fn_omemo);
            goto cleanup;
          }

	  signal_emit("lurch encryption changed", 2, item, GINT_TO_POINTER(0));

          msg = g_strdup_printf("Added %s to your blacklist. Even if OMEMO is available, it will not be used.", temp_msg_1);
        } else if (!g_strcmp0(args[1], "remove")) {
	  conversation_jid = lurch_irssi_conversation_get_name(item);
          temp_msg_1 = lurch_get_bare_jid(conversation_jid);
          ret_val = omemo_storage_chatlist_delete(temp_msg_1, db_fn_omemo);
          if (ret_val) {
            err_msg = g_strdup_printf("Failed to delete %s in DB %s.", temp_msg_1, db_fn_omemo);
            goto cleanup;
          }

          msg = g_strdup_printf("Removed %s from your blacklist. If OMEMO is available, it will be used.", temp_msg_1);

	  signal_emit("lurch encryption changed", 2, item, GINT_TO_POINTER(-1));
        } else {
          msg = g_strdup("Valid arguments for 'lurch blacklist' are 'add' and 'remove'.");
        }
      } else if (!g_strcmp0(args[0], "show")) {
        if (!g_strcmp0(args[1], "id")) {
          if (!g_strcmp0(args[2], "own")) {
            msg = g_strdup_printf("Your own device ID is %i.", id);
          } else if (!g_strcmp0(args[2], "list")) {
            ret_val = omemo_storage_user_devicelist_retrieve(uname, db_fn_omemo, &own_dl_p);
            if (ret_val) {
              err_msg = g_strdup_printf("Failed to access omemo db %s.", db_fn_omemo);
              goto cleanup;
            }

            temp_msg_1 = g_strdup_printf("This user (%s) has the following devices:\n"
                                         "%i (this device)\n", uname, id);

            own_l_p = omemo_devicelist_get_id_list(own_dl_p);
            for (curr_p = own_l_p; curr_p; curr_p = curr_p->next) {
              if (omemo_devicelist_list_data(curr_p) != id) {
                temp_msg_2 = g_strdup_printf("%i\n", omemo_devicelist_list_data(curr_p));
                temp_msg_3 = g_strconcat(temp_msg_1, temp_msg_2, NULL);
                g_free(temp_msg_1);
                temp_msg_1 = temp_msg_3;
                g_free(temp_msg_2);
                temp_msg_2 = (void *) 0;
                temp_msg_3 = (void *) 0;
              }
            }

            msg = g_strdup(temp_msg_1);
          } else {
            msg = g_strdup("Valid arguments for 'lurch show id' are 'own' to display this device's ID "
                           "and 'list' to display this user's device list.");
          }

        } else if (!g_strcmp0(args[1], "fp")) {
          if (!g_strcmp0(args[2], "own")) {
            ret_val = axc_key_load_public_own(axc_ctx_p, &key_buf_p);
            if (ret_val) {
              err_msg = g_strdup_printf("Failed to access axc db %s.", axc_context_get_db_fn(axc_ctx_p));
              goto cleanup;
            }

            fp_printable = lurch_fp_printable_x(axc_buf_get_data(key_buf_p), axc_buf_get_len(key_buf_p));
            msg = g_strdup_printf("This device's fingerprint is:\n%s\n"
                                  "You should make sure that your conversation partner gets displayed the same for this device.", fp_printable);
          } else if (!g_strcmp0(args[2], "conv")) {

            ret_val = axc_key_load_public_own(axc_ctx_p, &key_buf_p);
            if (ret_val) {
              err_msg = g_strdup_printf("Failed to access axc db %s.", axc_context_get_db_fn(axc_ctx_p));
              goto cleanup;
            }

            fp_printable = lurch_fp_printable_x(axc_buf_get_data(key_buf_p), axc_buf_get_len(key_buf_p));

            temp_msg_1 = g_strdup_printf("The devices participating in this conversation and their fingerprints are as follows:\n"
                                         "This device's (%s:%i) fingerprint:\n%s\n", uname, id, fp_printable);

            ret_val = omemo_storage_user_devicelist_retrieve(uname, db_fn_omemo, &own_dl_p);
            if (ret_val) {
              err_msg = g_strdup_printf("Failed to access omemo db %s.", db_fn_omemo);
              goto cleanup;
            }

            own_l_p = omemo_devicelist_get_id_list(own_dl_p);
            for (curr_p = own_l_p; curr_p; curr_p = curr_p->next) {
              if (omemo_devicelist_list_data(curr_p) != id) {
                ret_val = axc_key_load_public_addr(uname, omemo_devicelist_list_data(curr_p), axc_ctx_p, &key_buf_p);
                if (ret_val < 0) {
                  err_msg = g_strdup_printf("Failed to access axc db %s.", axc_context_get_db_fn(axc_ctx_p));
                  goto cleanup;
                } else if (ret_val == 0) {
                  continue;
                }

                g_free(fp);
                fp_printable = lurch_fp_printable_x(axc_buf_get_data(key_buf_p), axc_buf_get_len(key_buf_p));
                axc_buf_free(key_buf_p);
                key_buf_p = (void *) 0;

                temp_msg_2 = g_strdup_printf("%s:%i's fingerprint:\n%s\n", uname, omemo_devicelist_list_data(curr_p), fp_printable);
                temp_msg_3 = g_strconcat(temp_msg_1, temp_msg_2, NULL);
                g_free(temp_msg_1);
                temp_msg_1 = temp_msg_3;
                temp_msg_3 = (void *) 0;
                g_free(temp_msg_2);
                temp_msg_2 = (void *) 0;
              }
            }

	    conversation_jid = lurch_irssi_conversation_get_name(item);
            bare_jid = lurch_get_bare_jid(conversation_jid);

            ret_val = omemo_storage_user_devicelist_retrieve(bare_jid, db_fn_omemo, &other_dl_p);
            if (ret_val) {
              err_msg = g_strdup_printf("Failed to access omemo db %s.", db_fn_omemo);
              goto cleanup;
            }

            other_l_p = omemo_devicelist_get_id_list(other_dl_p);
            for (curr_p = other_l_p; curr_p; curr_p = curr_p->next) {
              ret_val = axc_key_load_public_addr(bare_jid, omemo_devicelist_list_data(curr_p), axc_ctx_p, &key_buf_p);
              if (ret_val < 0) {
                err_msg = g_strdup_printf("Failed to access axc db %s.", axc_context_get_db_fn(axc_ctx_p));
                goto cleanup;
              } else if (ret_val == 0) {
                continue;
              }

              g_free(fp);
              fp_printable = lurch_fp_printable_x(axc_buf_get_data(key_buf_p), axc_buf_get_len(key_buf_p));
              axc_buf_free(key_buf_p);
              key_buf_p = (void *) 0;

              temp_msg_2 = g_strdup_printf("%s:%i's fingerprint:\n%s\n", bare_jid, omemo_devicelist_list_data(curr_p), fp_printable);
              temp_msg_3 = g_strconcat(temp_msg_1, temp_msg_2, NULL);
              g_free(temp_msg_1);
              temp_msg_1 = temp_msg_3;
              temp_msg_3 = (void *) 0;
              g_free(temp_msg_2);
              temp_msg_2 = (void *) 0;
            }

            msg = g_strdup(temp_msg_1);

          } else {
            msg = g_strdup("Valid arguments for 'lurch show fp' are 'own' for displaying this device's fingerprint, "
                           "and 'conv' for displaying all devices participating in this conversation and their fingerprints.");
          }
        } else {
          msg = g_strdup("Valid arguments for 'lurch show' are 'id' and 'fp'.");
        }
      } else if (!g_strcmp0(args[0], "remove")) {
        if (!g_strcmp0(args[1], "id")) {
          if (!args[2]) {
            msg = g_strdup("The command 'lurch remove id' must be followed by a device ID.");
          } else {
            ret_val = omemo_storage_user_devicelist_retrieve(uname, db_fn_omemo, &own_dl_p);
            if (ret_val) {
              err_msg = g_strdup_printf("Failed to access omemo db %s.", db_fn_omemo);
              goto cleanup;
            }

            remove_id = strtol(args[2], (void *) 0, 10);

            if (!omemo_devicelist_contains_id(own_dl_p, remove_id)) {
              msg = g_strdup_printf("Your devicelist does not contain the ID %s.", args[2]);
            } else {
              ret_val = omemo_devicelist_remove(own_dl_p, remove_id);
              if (ret_val) {
                err_msg = g_strdup_printf("Failed to remove %i from the list.", remove_id);
                goto cleanup;
              }

              ret_val = omemo_devicelist_export(own_dl_p, &temp_msg_1);
              if (ret_val) {
                err_msg = g_strdup("Failed to export new devicelist to xml string.");
                goto cleanup;
              }

	      signal_emit("lurch peppublish devicelist", 3, server, uname, temp_msg_1);
              //dl_node_p = xmlnode_from_str(temp_msg_1, -1);
              //jabber_pep_publish(purple_connection_get_protocol_data(purple_conversation_get_gc(conv_p)), dl_node_p);

              msg = g_strdup_printf("Removed %i from devicelist and republished it.", remove_id);
            }
          }
        } else {
          msg = g_strdup("Valid argument for 'lurch remove' is 'id'.");
        }

      } else {
        msg = g_strdup("Valid arguments for 'lurch' in IMs are 'show', 'remove', 'blacklist', 'uninstall', and 'help'.");
      }
    } else if (IS_CHANNEL(item)) {
      if (!g_strcmp0(args[0], "enable")) {
	conversation_jid = lurch_irssi_conversation_get_name(item);
        ret_val = omemo_storage_chatlist_save(conversation_jid, db_fn_omemo);
        if (ret_val) {
          err_msg = g_strdup_printf("Failed to look up %s in DB %s.", conversation_jid, db_fn_omemo);
          goto cleanup;
        }

	signal_emit("lurch encryption changed", 2, item, GINT_TO_POINTER(1));

        msg = g_strdup_printf("Activated OMEMO for this chat. This is a client-side setting, so every participant needs to activate it to work.");
      } else if (!g_strcmp0(args[0], "disable")) {
	conversation_jid = lurch_irssi_conversation_get_name(item);
        ret_val = omemo_storage_chatlist_delete(conversation_jid, db_fn_omemo);
        if (ret_val) {
          err_msg = g_strdup_printf("Failed to delete %s in DB %s.\n", conversation_jid, db_fn_omemo);
          goto cleanup;
        }

        msg = g_strdup_printf("Deactivated OMEMO for this chat. "
                              "This is a client-side setting and if other users still have it activated, you will not be able to read their messages.");

	signal_emit("lurch encryption changed", 2, item, GINT_TO_POINTER(0));
      } else {
        msg = g_strdup("Valid arguments for 'lurch' in groupchats are 'enable', 'disable', 'uninstall', and 'help'.");
      }
    }
  }

  if (msg) {
    printtext(server, item ? item->name : NULL, MSGLEVEL_CLIENTNOTICE | MSGLEVEL_NEVER, "[lurch] %s", msg);
  }

cleanup:
  g_free (uname);
  g_free(db_fn_omemo);
  axc_context_destroy_all(axc_ctx_p);
  g_free(msg);
  axc_buf_free(key_buf_p);
  g_free(fp);
  g_free(fp_printable);
  omemo_devicelist_destroy(own_dl_p);
  omemo_devicelist_destroy(other_dl_p);
  g_list_free_full(own_l_p, free);
  g_list_free_full(other_l_p, free);
  g_free(temp_msg_1);
  g_free(temp_msg_2);
  g_free(temp_msg_3);
  g_free(conversation_jid);
  g_free(bare_jid);
  g_strfreev(args);


  if (ret_val < 0) {
    //*error = err_msg;
    printtext(server, NULL, MSGLEVEL_CLIENTERROR, "[lurch] %s", err_msg);
    return; /* PURPLE_CMD_RET_FAILED */
  } else {
    return; /* PURPLE_CMD_RET_OK */
  }
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

  g_warning("sending xml: ##%s##", xml);
  //signal_emit("xmpp send others", server, /*LmMessage */ message);

  mxmlRelease(xml_p);
}

static void irssi_lurch_peprequest(SERVER_REC * server, const char * to, const char * node, void * callback_fn)
{
  LmMessage * jiq_p = lm_message_new_with_sub_type(to, LM_MESSAGE_TYPE_IQ, LM_MESSAGE_SUB_TYPE_GET);
  LmMessageNode * pubsub_node_p = lm_message_node_add_child(jiq_p->node, "pubsub", NULL);
  lm_message_node_set_attribute(pubsub_node_p, "xmlns", "http://jabber.org/protocol/pubsub");

  char * req_id;
  while (1) {
    char * rand_str = g_strdup_printf("%i", g_random_int());
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

  lurch_bundle_request_ht = g_hash_table_new(g_str_hash, g_str_equal);
  lurch_peprequest_response_ht = g_hash_table_new(g_str_hash, g_str_equal);

  omemo_default_crypto_init();

  ret_val = omemo_devicelist_get_pep_node_name(&dl_ns);
  if (ret_val) {
    err_msg_dbg = "failed to get devicelist pep node name";
    goto cleanup;
  }

  settings_add_bool("misc", LURCH_PREF_AXC_LOGGING, TRUE);
  settings_add_choice("misc", LURCH_PREF_AXC_LOGGING_LEVEL, 4, "error;warning;notice;info;debug");

  command_bind("lurch", NULL, (SIGNAL_FUNC) lurch_cmd_func);
  signal_add("xmpp recv message", (SIGNAL_FUNC) lurch_xml_received_cb);
  signal_add("xmpp send message", (SIGNAL_FUNC) lurch_xml_sent_cb);

  signal_add("xmpp recv iq", (SIGNAL_FUNC) irssi_lurch_bundle_request_cb);
  signal_add("xmpp recv iq", (SIGNAL_FUNC) irssi_lurch_peprequest_cb);
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
  signal_add("query created", (SIGNAL_FUNC) lurch_conv_created_cb);
  signal_add("channel created", (SIGNAL_FUNC) lurch_conv_created_cb);
  // (void) purple_signal_connect(purple_conversations_get_handle(), "conversation-updated", plugin_p, PURPLE_CALLBACK(lurch_conv_updated_cb), NULL);

  expando_create("encryption_omemo", (EXPANDO_FUNC) lurch_expando_encryption_omemo,
		 "window changed", EXPANDO_ARG_NONE,
		 "window item changed", EXPANDO_ARG_WINDOW,
		 "lurch encryption changed", EXPANDO_ARG_WINDOW_ITEM,
		 NULL);

  signal_add("lurch peprequest bundle", (SIGNAL_FUNC) irssi_lurch_peprequest);
  signal_add("lurch peprequest own_devicelist", (SIGNAL_FUNC) irssi_lurch_peprequest);

  signal_add("lurch peppublish bundle", (SIGNAL_FUNC) irssi_lurch_peppublish);
  signal_add("lurch send message", (SIGNAL_FUNC) irssi_lurch_send);
  signal_add("lurch send keytransport", (SIGNAL_FUNC) irssi_lurch_send);
  signal_add("lurch peppublish devicelist", (SIGNAL_FUNC) irssi_lurch_peppublish);

cleanup:
  free(dl_ns);
  g_list_free(accs_l_p);
  if (ret_val) {
    g_warning("[lurch]" "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
  }

  module_register("lurch", "core");
}

void lurch_core_deinit(void)
{
  signal_remove("server connected", (SIGNAL_FUNC) lurch_account_connect_cb);
  signal_remove("query created", (SIGNAL_FUNC) lurch_conv_created_cb);
  signal_remove("channel created", (SIGNAL_FUNC) lurch_conv_created_cb);

  signal_remove("xmpp recv iq", (SIGNAL_FUNC) irssi_lurch_bundle_request_cb);
  signal_remove("xmpp recv iq", (SIGNAL_FUNC) irssi_lurch_peprequest_cb);
  signal_remove("xmpp recv iq", (SIGNAL_FUNC) irssi_lurch_iq_cb);

  omemo_default_crypto_teardown();

  expando_destroy("encryption_omemo", (EXPANDO_FUNC) lurch_expando_encryption_omemo);

  signal_remove("lurch peprequest bundle", (SIGNAL_FUNC) irssi_lurch_peprequest);
  signal_remove("lurch peprequest own_devicelist", (SIGNAL_FUNC) irssi_lurch_peprequest);

  g_hash_table_unref(lurch_bundle_request_ht);
  g_hash_table_unref(lurch_peprequest_response_ht);
  g_free(g_dl_ns);
}

#if 0
void prefs(void)
{
  ppref_p = purple_plugin_pref_new_with_label("Extended logging");
  purple_plugin_pref_frame_add(frame_p, ppref_p);

  ppref_p = purple_plugin_pref_new_with_name_and_label(
                  LURCH_PREF_AXC_LOGGING,
                  "Show log output from underlying libraries");
  purple_plugin_pref_frame_add(frame_p, ppref_p);

}
#endif

#if 0
x = {
     "core-riba-lurch",
     "lurch",
     LURCH_VERSION,

     "Implements OMEMO for libpurple.",
     "End-to-end encryption using the Signal protocol, adapted for XMPP.",
     LURCH_AUTHOR,
     "https://github.com/gkdr/lurch",
};
#endif


#ifdef IRSSI_ABI_VERSION
void
lurch_core_abicheck(int * version)
{
        *version = IRSSI_ABI_VERSION;
}
#endif
