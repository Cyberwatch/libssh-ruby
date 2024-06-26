#include "libssh_ruby.h"
#include <ruby/thread.h>

#define RAISE_IF_ERROR(rc) \
  if ((rc) == SSH_ERROR) libssh_ruby_raise(holder->session)

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

SessionHolder *libssh_ruby_session_holder(VALUE session) {
  SessionHolder *holder;
  TypedData_Get_Struct(session, SessionHolder, &session_type, holder);
  return holder;
}

static VALUE session_alloc(VALUE klass) {
  SessionHolder *holder = ALLOC(SessionHolder);
  holder->session = NULL;
  return TypedData_Wrap_Struct(klass, &session_type, holder);
}

static void session_mark(RB_UNUSED_VAR(void *arg)) {}

static void session_free(void *arg) {
  SessionHolder *holder = arg;
  if (holder->session != NULL) {
    ssh_free(holder->session);
    holder->session = NULL;
  }
  ruby_xfree(holder);
}

static size_t session_memsize(RB_UNUSED_VAR(const void *arg)) {
  return sizeof(SessionHolder);
}

/*
 * @overload initialize
 * Create a new SSH session.
 * @see http://api.libssh.org/stable/group__libssh__session.html ssh_new
 */
static VALUE m_initialize(VALUE self) {
  SessionHolder *holder;

  TypedData_Get_Struct(self, SessionHolder, &session_type, holder);
  holder->session = ssh_new();
  return self;
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
  SessionHolder *holder;

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

  TypedData_Get_Struct(self, SessionHolder, &session_type, holder);
  RAISE_IF_ERROR(ssh_options_set(holder->session, SSH_OPTIONS_LOG_VERBOSITY,
                                 &c_verbosity));

  return Qnil;
}

static VALUE set_string_option(VALUE self, enum ssh_options_e type, const char* name, VALUE str) {
  SessionHolder *holder;
  TypedData_Get_Struct(self, SessionHolder, &session_type, holder);
  const void* value = NIL_P(str) ? NULL : StringValueCStr(str);
  if (ssh_options_set(holder->session, type, value) < 0)
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
  SessionHolder *holder;
  int j;

  Check_Type(i, T_FIXNUM);
  j = FIX2INT(i);
  TypedData_Get_Struct(self, SessionHolder, &session_type, holder);
  RAISE_IF_ERROR(ssh_options_set(holder->session, type, &j));
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

/*
 * @overload bindaddr=(addr)
 *  Set the address to bind the client to.
 *  @since 0.2.0
 *  @param [String] addr
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_BINDADDR)
 */
static VALUE m_set_bindaddr(VALUE self, VALUE addr) {
  return set_string_option(self, SSH_OPTIONS_BINDADDR, "bind address", addr);
}

/*
 * @overload knownhosts=(path)
 *  Set the known hosts file name
 *  @since 0.2.0
 *  @param [String] path
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_KNOWNHOSTS)
 */
static VALUE m_set_knownhosts(VALUE self, VALUE path) {
  return set_string_option(self, SSH_OPTIONS_KNOWNHOSTS, "known_hosts file path", path);
}

static VALUE set_long_option(VALUE self, enum ssh_options_e type, VALUE i) {
  SessionHolder *holder;
  long j;

  Check_Type(i, T_FIXNUM);
  j = FIX2LONG(i);
  TypedData_Get_Struct(self, SessionHolder, &session_type, holder);
  RAISE_IF_ERROR(ssh_options_set(holder->session, type, &j));
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

/*
 * @overload timeout_usec=(usec)
 *  Set a timeout for the connection in micro seconds
 *  @since 0.2.0
 *  @param [Fixnum] usec
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_TIMEOUT_USEC)
 */
static VALUE m_set_timeout_usec(VALUE self, VALUE usec) {
  return set_long_option(self, SSH_OPTIONS_TIMEOUT_USEC, usec);
}

/*
 * @overload protocol=(protocol)
 *  Set allowed SSH protocols
 *  @since 0.2.0
 *  @param [Array<Integer>] protocol
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_SSH1)
 */
static VALUE m_set_protocol(VALUE self, VALUE protocols) {
  SessionHolder *holder;
  VALUE protocol;
  int i, ssh1 = 0, ssh2 = 0;

  Check_Type(protocols, T_ARRAY);

  for (i = 0; i < RARRAY_LEN(protocols); i++) {
    protocol = rb_ary_entry(protocols, i);
    Check_Type(protocol, T_FIXNUM);
    switch (FIX2INT(protocol)) {
      case 1:
        ssh1 = 1;
        break;
      case 2:
        ssh2 = 1;
        break;
      default:
        rb_raise(rb_eArgError, "protocol should be 1 or 2");
    }
  }

  TypedData_Get_Struct(self, SessionHolder, &session_type, holder);
  RAISE_IF_ERROR(ssh_options_set(holder->session, SSH_OPTIONS_SSH1, &ssh1));
  RAISE_IF_ERROR(ssh_options_set(holder->session, SSH_OPTIONS_SSH2, &ssh2));

  return Qnil;
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
 * @overload compression=(algorithm)
 *  Set the compression to use for both directions communication
 *  @since 0.2.0
 *  @param [TrueClass, FalseClass] algorithm
 *  @param [String] algorithm e.g. "yes", "no", "zlib", "zlib@openssh.com", "none"
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_COMPRESSION)
 */
static VALUE m_set_compression(VALUE self, VALUE compression) {
  SessionHolder *holder;
  if (compression == Qtrue || compression == Qfalse) {
    const char *val;
    if (compression == Qtrue) {
      val = "yes";
    } else {
      val = "no";
    }

    TypedData_Get_Struct(self, SessionHolder, &session_type, holder);
    RAISE_IF_ERROR(
        ssh_options_set(holder->session, SSH_OPTIONS_COMPRESSION, val));

    return Qnil;
  } else {
    return set_string_option(self, SSH_OPTIONS_COMPRESSION, "compression mode", compression);
  }
}

/*
 * @overload compression_level=(level)
 *  Set the compression level to use for zlib functions
 *  @since 0.2.0
 *  @param [Fixnum] level
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_COMPRESSION_LEVEL)
 */
static VALUE m_set_compression_level(VALUE self, VALUE level) {
  return set_int_option(self, SSH_OPTIONS_COMPRESSION_LEVEL, level);
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

/*
 * @overload proxycommand=(command)
 *  Set the command to be executed in order to connect to server
 *  @since 0.2.0
 *  @param [String] command
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_PROXYCOMMAND)
 */
static VALUE m_set_proxycommand(VALUE self, VALUE proxycommand) {
  return set_string_option(self, SSH_OPTIONS_PROXYCOMMAND, "proxy command", proxycommand);
}

/*
 * @overload gssapi_client_identity=(identity)
 *  Set the GSSAPI client identity that libssh should expect when connecting to the server
 *  @since 0.2.0
 *  @param [String] identity
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY)
 */
static VALUE m_set_gssapi_client_identity(VALUE self, VALUE identity) {
  return set_string_option(self, SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY, "GSS-API client identity", identity);
}

/*
 * @overload gssapi_server_identity=(identity)
 *  Set the GSSAPI server identity that libssh should expect when connecting to the server
 *  @since 0.2.0
 *  @param [String] identity
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_GSSAPI_SERVER_IDENTITY)
 */
static VALUE m_set_gssapi_server_identity(VALUE self, VALUE identity) {
  return set_string_option(self, SSH_OPTIONS_GSSAPI_SERVER_IDENTITY, "GSS-API server identity", identity);
}

/*
 * @overload gssapi_delegate_credentials=(enable)
 *  Set whether GSSAPI should delegate credentials to the server
 *  @since 0.2.0
 *  @param [FalseClass, TrueClass] enable
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS)
 */
static VALUE m_set_gssapi_delegate_credentials(VALUE self, VALUE enable) {
  return set_int_option(self, SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS,
                        INT2FIX(RTEST(enable) ? 1 : 0));
}

/*
 * @overload parse_config(path = nil)
 *  Parse the ssh_config file.
 *  @param [String, nil] Path to ssh_config. If +nil+, the default ~/.ssh/config will be used.
 *  @return [Boolean] Parsing the ssh_config was successful or not.
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_parse_config
 */
static VALUE m_parse_config(int argc, VALUE *argv, VALUE self) {
  SessionHolder *holder;
  VALUE path;
  char *c_path;

  rb_scan_args(argc, argv, "01", &path);

  if (NIL_P(path)) {
    c_path = NULL;
  } else {
    c_path = StringValueCStr(path);
  }

  TypedData_Get_Struct(self, SessionHolder, &session_type, holder);
  if (ssh_options_parse_config(holder->session, c_path) == 0) {
    return Qtrue;
  } else {
    return Qfalse;
  }
}

/*
 * @overload add_identity(path_format)
 *  Add the identity file name format.
 *  @param [String] path_format Format string for identity file.
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_options_set(SSH_OPTIONS_ADD_IDENTITY)
 */
static VALUE m_add_identity(VALUE self, VALUE path) {
  SessionHolder *holder;

  TypedData_Get_Struct(self, SessionHolder, &session_type, holder);
  RAISE_IF_ERROR(ssh_options_set(holder->session, SSH_OPTIONS_ADD_IDENTITY,
                                 StringValueCStr(path)));

  return Qnil;
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
  SessionHolder *holder;
  struct nogvl_session_args args;

  TypedData_Get_Struct(self, SessionHolder, &session_type, holder);
  args.session = holder->session;
  rb_thread_call_without_gvl(nogvl_connect, &args, RUBY_UBF_IO, NULL);
  RAISE_IF_ERROR(args.rc);

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
  SessionHolder *holder;
  struct nogvl_session_args args;

  TypedData_Get_Struct(self, SessionHolder, &session_type, holder);
  args.session = holder->session;
  rb_thread_call_without_gvl(nogvl_disconnect, &args, RUBY_UBF_IO, NULL);

  return Qnil;
}

/*
 * @overload server_known
 *  Check if the server is knonw.
 *  @return [Fixnum]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_is_server_known
 */
static VALUE m_server_known(VALUE self) {
  SessionHolder *holder;
  int rc;

  TypedData_Get_Struct(self, SessionHolder, &session_type, holder);
  rc = ssh_is_server_known(holder->session);
  RAISE_IF_ERROR(rc);
  return INT2FIX(rc);
}

/*
 * @overload fd
 * Get the fd of a connection
 * @return [Fixnum]
 * @since 0.3.0
 * @see http://api.libssh.org/stable/group__libssh__session.html ssh_get_fd
 */
static VALUE m_fd(VALUE self) {
  SessionHolder *holder;
  TypedData_Get_Struct(self, SessionHolder, &session_type, holder);
  return INT2FIX(ssh_get_fd(holder->session));
}

/*
 * @overload userauth_none
 *  Try to authenticate through then "none" method.
 *  @return [Fixnum]
 *  @see http://api.libssh.org/stable/group__libssh__auth.html ssh_userauth_none
 */
static VALUE m_userauth_none(VALUE self) {
  SessionHolder *holder;
  int rc;

  TypedData_Get_Struct(self, SessionHolder, &session_type, holder);
  rc = ssh_userauth_none(holder->session, NULL);
  RAISE_IF_ERROR(rc);
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
  SessionHolder *holder;
  int rc;

  TypedData_Get_Struct(self, SessionHolder, &session_type, holder);
  rc = ssh_userauth_password(holder->session, NULL, StringValueCStr(password));
  RAISE_IF_ERROR(rc);
  return INT2FIX(rc);
}

/*
 * @overload userauth_list
 *  Get available authentication methods from the server.
 *  @return [Array<Symbol>]
 *  @see http://api.libssh.org/stable/group__libssh__auth.html ssh_userauth_list
 */
static VALUE m_userauth_list(VALUE self) {
  SessionHolder *holder;
  int list;
  VALUE ary;

  TypedData_Get_Struct(self, SessionHolder, &session_type, holder);
  list = ssh_userauth_list(holder->session, NULL);
  RAISE_IF_ERROR(list);

  ary = rb_ary_new();
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
  SessionHolder *holder = libssh_ruby_session_holder(self);
  KeyHolder *key_holder = libssh_ruby_key_holder(private_key);

  struct nogvl_userauth_publickey_args args;
  args.session = holder->session;
  args.privkey = key_holder->key;
  rb_thread_call_without_gvl(nogvl_userauth_publickey, &args, RUBY_UBF_IO, NULL);
  RAISE_IF_ERROR(args.rc);
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
  SessionHolder *holder;
  struct nogvl_session_args args;

  TypedData_Get_Struct(self, SessionHolder, &session_type, holder);
  args.session = holder->session;
  rb_thread_call_without_gvl(nogvl_userauth_publickey_auto, &args, RUBY_UBF_IO,
                             NULL);
  RAISE_IF_ERROR(args.rc);
  return INT2FIX(args.rc);
}

/*
 * @overload userauth_kbdint
 *  Try to authenticate through the "keyboard-interactive" method.
 *  @return [Fixnum]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_userauth_kbdint
 */
static VALUE m_userauth_kbdint(VALUE self) {
  SessionHolder *holder = libssh_ruby_session_holder(self);
  int rc = ssh_userauth_kbdint(holder->session, NULL, NULL);
  RAISE_IF_ERROR(rc);
  return INT2FIX(rc);
}

/*
 * @overload userauth_kbdint_getnprompts
 *  Get the number of prompts (questions) the server has given.
 *  @return [Fixnum]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_userauth_kbdint_getnprompts
 */
static VALUE m_userauth_kbdint_getnpromts(VALUE self) {
  SessionHolder *holder = libssh_ruby_session_holder(self);
  int n = ssh_userauth_kbdint_getnprompts(holder->session);
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
  SessionHolder *holder = libssh_ruby_session_holder(self);
  int rc = ssh_userauth_kbdint_setanswer(holder->session, FIX2INT(i), StringValueCStr(answer));
  RAISE_IF_ERROR(rc);
  return Qnil;
}

/*
 * @overload get_publickey
 *  Get the server public key from a session.
 *  @return [Key]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_get_publickey
 */
static VALUE m_get_publickey(VALUE self) {
  SessionHolder *holder;
  KeyHolder *key_holder;
  VALUE key;

  TypedData_Get_Struct(self, SessionHolder, &session_type, holder);
  key = rb_obj_alloc(rb_cLibSSHKey);
  key_holder = libssh_ruby_key_holder(key);
  RAISE_IF_ERROR(ssh_get_publickey(holder->session, &key_holder->key));
  return key;
}

/*
 * @overload write_knownhost
 *  Write the current server as known in the known_hosts file.
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_write_knownhost
 */
static VALUE m_write_knownhost(VALUE self) {
  SessionHolder *holder;

  holder = libssh_ruby_session_holder(self);
  RAISE_IF_ERROR(ssh_write_knownhost(holder->session));
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

  rb_define_method(rb_cLibSSHSession, "initialize",
                   RUBY_METHOD_FUNC(m_initialize), 0);

  rb_define_method(rb_cLibSSHSession, "log_verbosity=",
                   RUBY_METHOD_FUNC(m_set_log_verbosity), 1);
  rb_define_method(rb_cLibSSHSession, "host=", RUBY_METHOD_FUNC(m_set_host), 1);
  rb_define_method(rb_cLibSSHSession, "user=", RUBY_METHOD_FUNC(m_set_user), 1);
  rb_define_method(rb_cLibSSHSession, "port=", RUBY_METHOD_FUNC(m_set_port), 1);
  rb_define_method(rb_cLibSSHSession, "bindaddr=",
                   RUBY_METHOD_FUNC(m_set_bindaddr), 1);
  rb_define_method(rb_cLibSSHSession, "knownhosts=",
                   RUBY_METHOD_FUNC(m_set_knownhosts), 1);
  rb_define_method(rb_cLibSSHSession, "timeout=",
                   RUBY_METHOD_FUNC(m_set_timeout), 1);
  rb_define_method(rb_cLibSSHSession, "timeout_usec=",
                   RUBY_METHOD_FUNC(m_set_timeout_usec), 1);
  rb_define_method(rb_cLibSSHSession, "protocol=",
                   RUBY_METHOD_FUNC(m_set_protocol), 1);
  rb_define_method(rb_cLibSSHSession, "key_exchange=",
                   RUBY_METHOD_FUNC(m_set_key_exchange), 1);
  rb_define_method(rb_cLibSSHSession, "hmac_c_s=",
                   RUBY_METHOD_FUNC(m_set_hmac_c_s), 1);
  rb_define_method(rb_cLibSSHSession, "hmac_s_c=",
                   RUBY_METHOD_FUNC(m_set_hmac_s_c), 1);
  rb_define_method(rb_cLibSSHSession, "hostkeys=",
                   RUBY_METHOD_FUNC(m_set_hostkeys), 1);
  rb_define_method(rb_cLibSSHSession, "publickey_accepted_types=",
                   RUBY_METHOD_FUNC(m_set_publickey_accepted_types), 1);
  rb_define_method(rb_cLibSSHSession, "compression=",
                   RUBY_METHOD_FUNC(m_set_compression), 1);
  rb_define_method(rb_cLibSSHSession, "compression_level=",
                   RUBY_METHOD_FUNC(m_set_compression_level), 1);
  rb_define_method(rb_cLibSSHSession, "compression_level=",
                   RUBY_METHOD_FUNC(m_set_compression_level), 1);
  rb_define_method(rb_cLibSSHSession, "stricthostkeycheck=",
                   RUBY_METHOD_FUNC(m_set_stricthostkeycheck), 1);
  rb_define_method(rb_cLibSSHSession, "proxycommand=",
                   RUBY_METHOD_FUNC(m_set_proxycommand), 1);
  rb_define_method(rb_cLibSSHSession, "gssapi_client_identity=",
                   RUBY_METHOD_FUNC(m_set_gssapi_client_identity), 1);
  rb_define_method(rb_cLibSSHSession, "gssapi_server_identity=",
                   RUBY_METHOD_FUNC(m_set_gssapi_server_identity), 1);
  rb_define_method(rb_cLibSSHSession, "gssapi_delegate_credentials=",
                   RUBY_METHOD_FUNC(m_set_gssapi_delegate_credentials), 1);

  rb_define_method(rb_cLibSSHSession, "parse_config",
                   RUBY_METHOD_FUNC(m_parse_config), -1);
  rb_define_method(rb_cLibSSHSession, "add_identity",
                   RUBY_METHOD_FUNC(m_add_identity), 1);
  rb_define_method(rb_cLibSSHSession, "connect", RUBY_METHOD_FUNC(m_connect),
                   0);
  rb_define_method(rb_cLibSSHSession, "disconnect",
                   RUBY_METHOD_FUNC(m_disconnect), 0);
  rb_define_method(rb_cLibSSHSession, "server_known",
                   RUBY_METHOD_FUNC(m_server_known), 0);
  rb_define_method(rb_cLibSSHSession, "fd", RUBY_METHOD_FUNC(m_fd), 0);

  rb_define_method(rb_cLibSSHSession, "userauth_none",
                   RUBY_METHOD_FUNC(m_userauth_none), 0);
  rb_define_method(rb_cLibSSHSession, "userauth_password",
                   RUBY_METHOD_FUNC(m_userauth_password), 1);
  rb_define_method(rb_cLibSSHSession, "userauth_list",
                   RUBY_METHOD_FUNC(m_userauth_list), 0);
  rb_define_method(rb_cLibSSHSession, "userauth_publickey",
                   RUBY_METHOD_FUNC(m_userauth_publickey), 1);
  rb_define_method(rb_cLibSSHSession, "userauth_publickey_auto",
                   RUBY_METHOD_FUNC(m_userauth_publickey_auto), 0);
  rb_define_method(rb_cLibSSHSession, "userauth_kbdint",
                   RUBY_METHOD_FUNC(m_userauth_kbdint), 0);
  rb_define_method(rb_cLibSSHSession, "userauth_kbdint_getnprompts",
                   RUBY_METHOD_FUNC(m_userauth_kbdint_getnpromts), 0);
  rb_define_method(rb_cLibSSHSession, "userauth_kbdint_setanswer",
                   RUBY_METHOD_FUNC(m_userauth_kbdint_setanswer), 2);
  rb_define_method(rb_cLibSSHSession, "get_publickey",
                   RUBY_METHOD_FUNC(m_get_publickey), 0);
  rb_define_method(rb_cLibSSHSession, "write_knownhost",
                   RUBY_METHOD_FUNC(m_write_knownhost), 0);
}
