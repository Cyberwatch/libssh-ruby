#include "libssh_ruby.h"
#include <ruby/thread.h>
#include <stdatomic.h>

VALUE rb_cLibSSHSession;
VALUE rb_eLibSSHError;

static ID id_none, id_warn, id_info, id_debug, id_trace;
static ID id_password, id_key;

static void session_mark(void *);
static void session_free(void *);
static size_t session_memsize(const void *);

const rb_data_type_t session_type = {
    "ssh_session",
    {session_mark, session_free, session_memsize,},
    NULL,
    NULL,
    RUBY_TYPED_WB_PROTECTED | RUBY_TYPED_FREE_IMMEDIATELY,
};

static struct libssh_ruby_session* unwrap_session(VALUE session) {
  struct libssh_ruby_session *holder;
  TypedData_Get_Struct(session, struct libssh_ruby_session, &session_type, holder);
  return holder;
}

ssh_session libssh_ruby_get_session(VALUE session) {
  return unwrap_session(session)->session;
}

static VALUE session_alloc(VALUE klass) {
  struct libssh_ruby_session *holder;
  VALUE object = TypedData_Make_Struct(klass, struct libssh_ruby_session, &session_type, holder);
  holder->session = ssh_new();
  return object;
}

static void session_mark(RB_UNUSED_VAR(void *arg)) {}

static void session_free(void *arg) {
  struct libssh_ruby_session *holder = arg;
  ssh_free(holder->session);
  libssh_ruby_free_options(holder->options);
  ruby_xfree(holder->proxy_jumps);
  ruby_xfree(holder->proxy_jump_uris);
  ruby_xfree(holder);
}

static size_t session_memsize(RB_UNUSED_VAR(const void *arg)) {
  return sizeof(struct libssh_ruby_session);
}

/*
 * @overload log_verbosity=(verbosity)
 *  Set the session logging verbosity.
 *  @param [Symbol] verbosity +:none+, +:warn+, +:info+, +:debug+, or +:trace+.
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html
 *    ssh_options_set(SSH_OPTIONS_LOG_VERBOSITY)
 */
static VALUE m_set_log_verbosity(VALUE self, VALUE verbosity) {
  ID id_verbosity;
  int c_verbosity;

  Check_Type(verbosity, T_SYMBOL);
  id_verbosity = SYM2ID(verbosity);

  if (id_verbosity == id_none) {
    c_verbosity = SSH_LOG_NONE;
  } else if (id_verbosity == id_warn) {
    c_verbosity = SSH_LOG_WARN;
  } else if (id_verbosity == id_info) {
    c_verbosity = SSH_LOG_INFO;
  } else if (id_verbosity == id_debug) {
    c_verbosity = SSH_LOG_DEBUG;
  } else if (id_verbosity == id_trace) {
    c_verbosity = SSH_LOG_TRACE;
  } else {
    rb_raise(rb_eArgError, "invalid verbosity: %" PRIsVALUE, verbosity);
  }

  ssh_session session = libssh_ruby_get_session(self);
  if (ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &c_verbosity) == SSH_ERROR)
    libssh_ruby_raise(self);

  return Qnil;
}

static int authenticate(ssh_session session, struct libssh_ruby_options *options, libssh_ruby_error *error) {
  if (options->key) {
    if (ssh_userauth_publickey(session, NULL, options->key) == SSH_AUTH_SUCCESS) {
      return SSH_OK;
    } else {
      libssh_ruby_set_error(error, options, "Authentication by key failed.");
      return SSH_ERROR;
    }
  } else if (options->password) {
    if (ssh_userauth_none(session, NULL) == SSH_AUTH_ERROR)
      return SSH_ERROR;
    int auth_methods = ssh_userauth_list(session, NULL);
    if (auth_methods & SSH_AUTH_METHOD_INTERACTIVE) {
      for (;;) {
        int rc = ssh_userauth_kbdint(session, NULL, NULL);
        if (rc == SSH_AUTH_SUCCESS) {
          return SSH_OK;
        } else if (rc == SSH_AUTH_INFO) {
          int nprompts = ssh_userauth_kbdint_getnprompts(session);
          if (nprompts == 0) {
            continue;
          } else if (nprompts == 1) {
            if (ssh_userauth_kbdint_setanswer(session, 0, options->password) == 0) {
              continue;
            } else {
              libssh_ruby_set_error(error, options, "Could not reply to keyboard-interactive prompt.");
              return SSH_ERROR;
            }
          } else {
            libssh_ruby_set_error(error, options, "Keyboard-interactive authentication requires too many prompts.");
            return SSH_ERROR;
          }
        } else {
          libssh_ruby_set_error(error, options, "Keyboard-interactive authentication with password failed.");
          return SSH_ERROR;
        }
      }
    } else if (auth_methods & SSH_AUTH_METHOD_PASSWORD) {
      if (ssh_userauth_password(session, NULL, options->password) == SSH_AUTH_SUCCESS) {
        return SSH_OK;
      } else {
        libssh_ruby_set_error(error, options, "Plain authentication with password failed.");
        return SSH_ERROR;
      }
    } else {
      libssh_ruby_set_error(error, options, "Host rejects authentication by password.");
      return SSH_ERROR;
    }
  } else {
    if (ssh_userauth_publickey_auto(session, NULL, NULL) == SSH_AUTH_SUCCESS) {
      return SSH_OK;
    } else {
      libssh_ruby_set_error(error, options, "Automatic authentication failed.");
      return SSH_ERROR;
    }
  }
}

static int check_host(ssh_session session, struct libssh_ruby_options *options, libssh_ruby_error *error) {
  enum ssh_known_hosts_e state = ssh_session_is_known_server(session);
  switch (state) {
    case SSH_KNOWN_HOSTS_OK:        return SSH_OK;
    case SSH_KNOWN_HOSTS_CHANGED:   libssh_ruby_set_error(error, options, "Server key differs from known hosts."); break;
    case SSH_KNOWN_HOSTS_OTHER:     libssh_ruby_set_error(error, options, "Server key type differs from known hosts."); break;
    case SSH_KNOWN_HOSTS_UNKNOWN:   libssh_ruby_set_error(error, options, "Server missing from known hosts."); break;
    case SSH_KNOWN_HOSTS_NOT_FOUND: libssh_ruby_set_error(error, options, "Missing known hosts file."); break;
    default:
    case SSH_KNOWN_HOSTS_ERROR:     libssh_ruby_set_error(error, options, "Error checking known hosts.");
  }
  return SSH_ERROR;
}

static void *nogvl_connect(void *ptr) {
  struct libssh_ruby_session *holder = ptr;
  if (ssh_connect(holder->session) != SSH_OK)
    return (void*) -1;
  if (check_host(holder->session, holder->options, &holder->error) != SSH_OK)
    return (void*) -1;
  if (authenticate(holder->session, holder->options, &holder->error) != SSH_OK)
    return (void*) -1;
  return (void*) 0;
}

/*
 * @overload connect
 *  Connect to the SSH server.
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_connect
 */
static VALUE m_connect(VALUE self) {
  if (rb_thread_call_without_gvl(nogvl_connect, unwrap_session(self), RUBY_UBF_IO, NULL) != 0)
    libssh_ruby_raise(self);
  return Qnil;
}

static void* nogvl_disconnect(void *ptr) {
  struct libssh_ruby_session *holder = ptr;
  ssh_disconnect(holder->session);
  return NULL;
}

/*
 * @overload disconnect
 *  Disconnect from a session.
 *  @return [nil]
 *  @since 0.3.0
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_disconnect
 */
static VALUE m_disconnect(VALUE self) {
  rb_thread_call_without_gvl(nogvl_disconnect, unwrap_session(self), RUBY_UBF_IO, NULL);
  return Qnil;
}

static int proxy_jump_before_connection(ssh_session session, void *userdata) {
  struct libssh_ruby_proxy_jump *jump = userdata;
  return libssh_ruby_apply_options(jump->options, session, jump->error);
}

static int proxy_jump_verify_knownhost(ssh_session session, void *userdata) {
  struct libssh_ruby_proxy_jump *jump = userdata;
  return check_host(session, jump->options, jump->error);
}

static int proxy_jump_authenticate(ssh_session session, void *userdata) {
  struct libssh_ruby_proxy_jump *jump = userdata;
  return authenticate(session, jump->options, jump->error);
}

static void configure_proxy_jumps(VALUE session) {
  struct libssh_ruby_session *holder = unwrap_session(session);
  struct libssh_ruby_options *options = holder->options;

  size_t jump_count = 0;
  for (struct libssh_ruby_options *jump = options->proxy_jump; jump != NULL; jump = jump->proxy_jump)
    ++jump_count;

  if (jump_count == 0)
    return;

  // libssh requires a list of hostnames even though we set them in the before_connection callback.
  // The URIs we supply are placeholders for libssh to know how many callbacks to expect.
  holder->proxy_jump_uris = RB_ALLOC_N(char, jump_count * 2);
  char *cursor = holder->proxy_jump_uris;
  for (size_t i = 0; i < jump_count; ++i) {
    *(cursor++) = '0';
    *(cursor++) = (i == jump_count - 1) ? '\0' : ',';
  }

  int rc = ssh_options_set(holder->session, SSH_OPTIONS_PROXYJUMP, holder->proxy_jump_uris);
  if (rc != 0)
    libssh_ruby_raise(session);

  holder->proxy_jumps = RB_ZALLOC_N(struct libssh_ruby_proxy_jump, jump_count);
  struct libssh_ruby_options *jump_options = options->proxy_jump;
  struct libssh_ruby_proxy_jump *jump_struct = &holder->proxy_jumps[jump_count - 1];
  while (jump_options != NULL) {
    jump_struct->callbacks.userdata = jump_struct;
    jump_struct->callbacks.before_connection = proxy_jump_before_connection;
    jump_struct->callbacks.verify_knownhost = proxy_jump_verify_knownhost;
    jump_struct->callbacks.authenticate = proxy_jump_authenticate;
    jump_struct->options = jump_options;
    jump_struct->error = &holder->error;

    jump_options = jump_options->proxy_jump;
    --jump_struct; // The innermost jump must appear first.
  }

  for (size_t i = 0; i < jump_count; ++i) {
    rc = ssh_options_set(holder->session,
                         SSH_OPTIONS_PROXYJUMP_CB_LIST_APPEND,
                         &holder->proxy_jumps[i].callbacks);
    if (rc != 0)
      libssh_ruby_raise(session);
  }
}

// LibSSH::Session#set_options(LibSSH::Options)
static VALUE m_set_options(VALUE self, VALUE value) {
  struct libssh_ruby_session *session = unwrap_session(self);
  struct libssh_ruby_options **options = &session->options;
  if (*options) rb_raise(rb_eArgError, "Cannot set options twice.");
  *options = libssh_ruby_clone_options(value);

  if (libssh_ruby_apply_options(*options, libssh_ruby_get_session(self), &session->error) < 0)
    libssh_ruby_raise(self);

  configure_proxy_jumps(self);

  return Qnil;
}

static VALUE m_get_server_publickey(VALUE self) {
  ssh_session session = libssh_ruby_get_session(self);
  ssh_key key;
  if (ssh_get_server_publickey(session, &key) < 0)
    libssh_ruby_raise(self);
  return libssh_ruby_wrap_key(key);
}

void libssh_ruby_set_error(libssh_ruby_error *error, struct libssh_ruby_options *context, const char* message) {
  *error = (struct libssh_ruby_error) { .host = context->host, .message = message };
}

[[noreturn]] static void raise_libssh_error(VALUE session) {
  const char* message = ssh_get_error(libssh_ruby_get_session(session));

  /* Empty messages are converted to nil so that #to_s defaults to the error type. */
  if (message && message[0] == '\0')
    message = NULL;

  VALUE argv[1] = { message ? rb_str_new_cstr(message) : Qnil };
  VALUE exception = rb_class_new_instance(1, argv, rb_eLibSSHError);
  rb_exc_raise(exception);
}

void libssh_ruby_raise(VALUE session) {
  struct libssh_ruby_session *holder = unwrap_session(session);
  struct libssh_ruby_error error = atomic_exchange(&holder->error, (struct libssh_ruby_error) {});

  if (error.message)
    rb_raise(rb_eLibSSHError, "%s (Host: %s)", error.message, error.host);
  else
    raise_libssh_error(session);
}

/*
 * Document-class: LibSSH::Session
 * Wrapper for ssh_session struct in libssh.
 *
 * @since 0.1.0
 * @see http://api.libssh.org/stable/group__libssh__session.html
 */

void Init_libssh_session(void) {
  rb_cLibSSHSession = rb_define_class_under(rb_mLibSSH, "Session", rb_cObject);
  rb_define_alloc_func(rb_cLibSSHSession, session_alloc);

  id_none     = rb_intern("none");
  id_warn     = rb_intern("warn");
  id_info     = rb_intern("info");
  id_debug    = rb_intern("debug");
  id_trace    = rb_intern("trace");
  id_password = rb_intern("password");
  id_key      = rb_intern("key");

  rb_define_method(rb_cLibSSHSession, "log_verbosity=", m_set_log_verbosity, 1);

  rb_define_method(rb_cLibSSHSession, "connect",              m_connect,               0);
  rb_define_method(rb_cLibSSHSession, "disconnect",           m_disconnect,            0);
  rb_define_method(rb_cLibSSHSession, "get_server_publickey", m_get_server_publickey, 0);

  rb_define_private_method(rb_cLibSSHSession, "set_options", m_set_options, 1);

  rb_eLibSSHError = rb_define_class_under(rb_mLibSSH, "Error", rb_eStandardError);
}
