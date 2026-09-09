#include "libssh_ruby.h"
#include <ruby/thread.h>

VALUE rb_cLibSSHSession;

static ID id_none, id_warn, id_info, id_debug, id_trace;
static ID id_password, id_publickey, id_hostbased, id_interactive,
    id_gssapi_mic;

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
  if (holder->session != NULL) {
    ssh_free(holder->session);
    holder->session = NULL;
  }
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
    libssh_ruby_raise(session);

  return Qnil;
}

static VALUE set_string_option(VALUE self, enum ssh_options_e type, const char* name, VALUE str) {
  const void* value = NIL_P(str) ? NULL : StringValueCStr(str);
  if (ssh_options_set(libssh_ruby_get_session(self), type, value) < 0)
    rb_raise(rb_eArgError, "Invalid %s: %+" PRIsVALUE, name, str);
  return Qnil;
}

/*
 * @overload host=(host)
 *  Set the hostname or IP address to connect to.
 *  @param [String] host
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_HOST)
 */
static VALUE m_set_host(VALUE self, VALUE host) {
  return set_string_option(self, SSH_OPTIONS_HOST, "host", host);
}

/*
 * @overload user=(user)
 *  Set the username for authentication.
 *  @since 0.2.0
 *  @param [String] user
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_USER)
 */
static VALUE m_set_user(VALUE self, VALUE user) {
  return set_string_option(self, SSH_OPTIONS_USER, "user", user);
}

static VALUE set_int_option(VALUE self, enum ssh_options_e type, VALUE i) {
  Check_Type(i, T_FIXNUM);
  int j = FIX2INT(i);

  ssh_session session = libssh_ruby_get_session(self);
  if (ssh_options_set(session, type, &j) == SSH_ERROR)
    libssh_ruby_raise(session);

  return Qnil;
}

/*
 * @overload port=(port)
 *  Set the port to connect to.
 *  @since 0.2.0
 *  @param [Fixnum] port
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_PORT)
 */
static VALUE m_set_port(VALUE self, VALUE port) {
  return set_int_option(self, SSH_OPTIONS_PORT, port);
}

static VALUE set_long_option(VALUE self, enum ssh_options_e type, VALUE i) {
  Check_Type(i, T_FIXNUM);
  long j = FIX2LONG(i);

  ssh_session session = libssh_ruby_get_session(self);
  if (ssh_options_set(session, type, &j) == SSH_ERROR)
    libssh_ruby_raise(session);

  return Qnil;
}

/*
 * @overload timeout=(sec)
 *  Set a timeout for the connection in seconds
 *  @since 0.2.0
 *  @param [Fixnum] sec
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_TIMEOUT)
 */
static VALUE m_set_timeout(VALUE self, VALUE sec) {
  return set_long_option(self, SSH_OPTIONS_TIMEOUT, sec);
}

static VALUE set_comma_separated_option(VALUE self, enum ssh_options_e type,
                                        const char* name, VALUE ary) {
  VALUE str;

  Check_Type(ary, T_ARRAY);
  str = rb_ary_join(ary, rb_str_new_cstr(","));

  return set_string_option(self, type, name, str);
}

/*
 * @overload key_exchange=(methods)
 *  Set the key exchange method to be used
 *  @since 0.2.0
 *  @param [Array<String>] methods
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_KEY_EXCHANGE)
 */
static VALUE m_set_key_exchange(VALUE self, VALUE kex) {
  return set_comma_separated_option(self, SSH_OPTIONS_KEY_EXCHANGE, "key exchange methods", kex);
}

/*
 * @overload hmac_c_s=(methods)
 *  Set the allowed HMAC algorithms from the client to the server.
 *  @param [Array<String>] methods
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_HMAC_C_S)
 */
static VALUE m_set_hmac_c_s(VALUE self, VALUE algos) {
  return set_comma_separated_option(self, SSH_OPTIONS_HMAC_C_S, "client-to-server HMAC algorithms", algos);
}

/*
 * @overload hmac_s_c=(methods)
 *  Set the allowed HMAC algorithms from the server to the client.
 *  @param [Array<String>] methods
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_HMAC_S_C)
 */
static VALUE m_set_hmac_s_c(VALUE self, VALUE algos) {
  return set_comma_separated_option(self, SSH_OPTIONS_HMAC_S_C, "server-to-client HMAC algorithms", algos);
}

/*
 * @overload hostkeys=(key_types)
 *  Set the preferred server host key types
 *  @since 0.2.0
 *  @param [Array<String>] key_types
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_HOSTKEYS)
 */
static VALUE m_set_hostkeys(VALUE self, VALUE hostkeys) {
  return set_comma_separated_option(self, SSH_OPTIONS_HOSTKEYS, "host key types", hostkeys);
}

/*
 * @overload publickey_accepted_types=(publickey_types)
 *  Set the preferred public key algorithms to be used for authentication.
 *  @param [Array<String>] publickey_types
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES)
 */
static VALUE m_set_publickey_accepted_types(VALUE self, VALUE publickey_types) {
  return set_comma_separated_option(self,
                                    SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES,
                                    "public key types",
                                    publickey_types);
}

/*
 * @overload stricthostkeycheck=(enable)
 *  Set the parameter StrictHostKeyChecking to avoid asking about a fingerprint
 *  @since 0.2.0
 *  @param [TrueClass, FalseClass] enable
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_STRICTHOSTKEYCHECK)
 */
static VALUE m_set_stricthostkeycheck(VALUE self, VALUE enable) {
  return set_int_option(self, SSH_OPTIONS_STRICTHOSTKEYCHECK,
                        INT2FIX(RTEST(enable) ? 1 : 0));
}

struct nogvl_session_args {
  ssh_session session;
  int rc;
};

static void *nogvl_connect(void *ptr) {
  struct nogvl_session_args *args = ptr;
  args->rc = ssh_connect(args->session);
  return NULL;
}

/*
 * @overload connect
 *  Connect to the SSH server.
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_connect
 */
static VALUE m_connect(VALUE self) {
  struct nogvl_session_args args;

  args.session = libssh_ruby_get_session(self);
  rb_thread_call_without_gvl(nogvl_connect, &args, RUBY_UBF_IO, NULL);
  if (args.rc == SSH_ERROR) libssh_ruby_raise(args.session);

  return Qnil;
}

static void *nogvl_disconnect(void *ptr) {
  struct nogvl_session_args *args = ptr;
  ssh_disconnect(args->session);
  args->rc = 0;
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
  struct nogvl_session_args args;

  args.session = libssh_ruby_get_session(self);
  rb_thread_call_without_gvl(nogvl_disconnect, &args, RUBY_UBF_IO, NULL);

  return Qnil;
}

/*
 * @overload userauth_none
 *  Try to authenticate through then "none" method.
 *  @return [Fixnum]
 *  @see http://api.libssh.org/stable/group__libssh__auth.html ssh_userauth_none
 */
static VALUE m_userauth_none(VALUE self) {
  ssh_session session = libssh_ruby_get_session(self);
  int rc = ssh_userauth_none(session, NULL);
  if (rc == SSH_ERROR) libssh_ruby_raise(session);
  return INT2FIX(rc);
}

/*
 * @overload userauth_password
 *  Try to authenticate through the "password" method.
 *  @param [String] password
 *  @return [Fixnum]
 *  @see http://api.libssh.org/stable/group__libssh__auth.html ssh_userauth_password
 */
static VALUE m_userauth_password(VALUE self, VALUE password) {
  ssh_session session = libssh_ruby_get_session(self);
  int rc = ssh_userauth_password(session, NULL, StringValueCStr(password));
  if (rc == SSH_ERROR) libssh_ruby_raise(session);
  return INT2FIX(rc);
}

/*
 * @overload userauth_list
 *  Get available authentication methods from the server.
 *  @return [Array<Symbol>]
 *  @see http://api.libssh.org/stable/group__libssh__auth.html ssh_userauth_list
 */
static VALUE m_userauth_list(VALUE self) {
  ssh_session session = libssh_ruby_get_session(self);
  int list = ssh_userauth_list(session, NULL);
  if (list == SSH_ERROR) libssh_ruby_raise(session);

  VALUE ary = rb_ary_new();
  if (list & SSH_AUTH_METHOD_NONE) {
    rb_ary_push(ary, ID2SYM(id_none));
  }
  if (list & SSH_AUTH_METHOD_PASSWORD) {
    rb_ary_push(ary, ID2SYM(id_password));
  }
  if (list & SSH_AUTH_METHOD_PUBLICKEY) {
    rb_ary_push(ary, ID2SYM(id_publickey));
  }
  if (list & SSH_AUTH_METHOD_HOSTBASED) {
    rb_ary_push(ary, ID2SYM(id_hostbased));
  }
  if (list & SSH_AUTH_METHOD_INTERACTIVE) {
    rb_ary_push(ary, ID2SYM(id_interactive));
  }
  if (list & SSH_AUTH_METHOD_GSSAPI_MIC) {
    rb_ary_push(ary, ID2SYM(id_gssapi_mic));
  }
  return ary;
}

struct nogvl_userauth_publickey_args {
  ssh_session session;
  ssh_key privkey;
  int rc;
};

static void *nogvl_userauth_publickey(void *ptr) {
  struct nogvl_userauth_publickey_args *args = ptr;
  args->rc = ssh_userauth_publickey(args->session, NULL, args->privkey);
  return NULL;
}

/*
 * @overload userauth_publickey(private_key)
 *  Authenticate with a private key.
 *  @param [LibSSH::Key] private_key
 *  @return [Fixnum]
 *  @see http://api.libssh.org/stable/group__libssh__auth.html ssh_userauth_publickey
 */
static VALUE m_userauth_publickey(VALUE self, VALUE private_key) {
  KeyHolder *key_holder = libssh_ruby_key_holder(private_key);

  struct nogvl_userauth_publickey_args args;
  args.session = libssh_ruby_get_session(self);
  args.privkey = key_holder->key;

  rb_thread_call_without_gvl(nogvl_userauth_publickey, &args, RUBY_UBF_IO, NULL);
  if (args.rc == SSH_ERROR) libssh_ruby_raise(args.session);

  return INT2FIX(args.rc);
}

static void *nogvl_userauth_publickey_auto(void *ptr) {
  struct nogvl_session_args *args = ptr;
  args->rc = ssh_userauth_publickey_auto(args->session, NULL, NULL);
  return NULL;
}

/*
 * @overload userauth_publickey_auto
 *  Try to automatically authenticate with public key and "none".
 *  @return [Fixnum]
 *  @see http://api.libssh.org/stable/group__libssh__auth.html ssh_userauth_publickey_auto
 */
static VALUE m_userauth_publickey_auto(VALUE self) {
  struct nogvl_session_args args;
  args.session = libssh_ruby_get_session(self);

  rb_thread_call_without_gvl(nogvl_userauth_publickey_auto, &args, RUBY_UBF_IO, NULL);
  if (args.rc == SSH_ERROR) libssh_ruby_raise(args.session);

  return INT2FIX(args.rc);
}

/*
 * @overload userauth_kbdint
 *  Try to authenticate through the "keyboard-interactive" method.
 *  @return [Fixnum]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_userauth_kbdint
 */
static VALUE m_userauth_kbdint(VALUE self) {
  ssh_session session = libssh_ruby_get_session(self);
  int rc = ssh_userauth_kbdint(session, NULL, NULL);
  if (rc == SSH_ERROR) libssh_ruby_raise(session);
  return INT2FIX(rc);
}

/*
 * @overload userauth_kbdint_getnprompts
 *  Get the number of prompts (questions) the server has given.
 *  @return [Fixnum]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_userauth_kbdint_getnprompts
 */
static VALUE m_userauth_kbdint_getnpromts(VALUE self) {
  int n = ssh_userauth_kbdint_getnprompts(libssh_ruby_get_session(self));
  return INT2FIX(n);
}

/*
 * @overload userauth_kbdint_setanswer(i, answer)
 *  Set the answer to a prompt.
 *  @param [Fixnum] i Index of the prompt to answer.
 *  @param [String] answer
 *  @return [Fixnum]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_userauth_kbdint_setanswer
 */
static VALUE m_userauth_kbdint_setanswer(VALUE self, VALUE i, VALUE answer) {
  ssh_session session = libssh_ruby_get_session(self);
  int rc = ssh_userauth_kbdint_setanswer(libssh_ruby_get_session(self), FIX2INT(i), StringValueCStr(answer));
  if (rc == SSH_ERROR) libssh_ruby_raise(session);
  return Qnil;
}

/*
 * Document-class: LibSSH::Session
 * Wrapper for ssh_session struct in libssh.
 *
 * @since 0.1.0
 * @see http://api.libssh.org/stable/group__libssh__session.html
 */

void Init_libssh_session() {
  rb_cLibSSHSession = rb_define_class_under(rb_mLibSSH, "Session", rb_cObject);
  rb_define_alloc_func(rb_cLibSSHSession, session_alloc);

#define I(name) id_##name = rb_intern(#name)
  I(none);
  I(warn);
  I(info);
  I(debug);
  I(trace);
  I(password);
  I(publickey);
  I(hostbased);
  I(interactive);
  I(gssapi_mic);
#undef I

  rb_define_method(rb_cLibSSHSession, "log_verbosity=",               m_set_log_verbosity,               1);
  rb_define_method(rb_cLibSSHSession, "host=",                        m_set_host,                        1);
  rb_define_method(rb_cLibSSHSession, "user=",                        m_set_user,                        1);
  rb_define_method(rb_cLibSSHSession, "port=",                        m_set_port,                        1);
  rb_define_method(rb_cLibSSHSession, "timeout=",                     m_set_timeout,                     1);
  rb_define_method(rb_cLibSSHSession, "key_exchange=",                m_set_key_exchange,                1);
  rb_define_method(rb_cLibSSHSession, "hmac_c_s=",                    m_set_hmac_c_s,                    1);
  rb_define_method(rb_cLibSSHSession, "hmac_s_c=",                    m_set_hmac_s_c,                    1);
  rb_define_method(rb_cLibSSHSession, "hostkeys=",                    m_set_hostkeys,                    1);
  rb_define_method(rb_cLibSSHSession, "publickey_accepted_types=",    m_set_publickey_accepted_types,    1);
  rb_define_method(rb_cLibSSHSession, "stricthostkeycheck=",          m_set_stricthostkeycheck,          1);

  rb_define_method(rb_cLibSSHSession, "connect",      m_connect,       0);
  rb_define_method(rb_cLibSSHSession, "disconnect",   m_disconnect,    0);

  rb_define_method(rb_cLibSSHSession, "userauth_none",               m_userauth_none,              0);
  rb_define_method(rb_cLibSSHSession, "userauth_password",           m_userauth_password,          1);
  rb_define_method(rb_cLibSSHSession, "userauth_list",               m_userauth_list,              0);
  rb_define_method(rb_cLibSSHSession, "userauth_publickey",          m_userauth_publickey,         1);
  rb_define_method(rb_cLibSSHSession, "userauth_publickey_auto",     m_userauth_publickey_auto,    0);
  rb_define_method(rb_cLibSSHSession, "userauth_kbdint",             m_userauth_kbdint,            0);
  rb_define_method(rb_cLibSSHSession, "userauth_kbdint_getnprompts", m_userauth_kbdint_getnpromts, 0);
  rb_define_method(rb_cLibSSHSession, "userauth_kbdint_setanswer",   m_userauth_kbdint_setanswer,  2);
}
