#include "libssh_ruby.h"
#include <ruby/thread.h>

VALUE rb_cLibSSHSession;

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

// LibSSH::Session#set_options(LibSSH::Options)
static VALUE m_set_options(VALUE self, VALUE value) {
  struct libssh_ruby_options **options = &unwrap_session(self)->options;
  if (*options) rb_raise(rb_eArgError, "Cannot set options twice.");
  *options = libssh_ruby_clone_options(value);

  ssh_session session = libssh_ruby_get_session(self);
  char *error;
  int rc = libssh_ruby_apply_options(*options, session, &error);
  if (error) {
    VALUE exception_argv[1] = { rb_str_new_cstr(error) };
    free(error);
    rb_exc_raise(rb_class_new_instance(1, exception_argv, rb_eArgError));
  } else if (rc < 0) {
    libssh_ruby_raise(session);
  }

  return Qnil;
}

struct nogvl_session_args {
  ssh_session session;
  struct libssh_ruby_options *options;
  const char* error; // Literal only.
  int rc;
};

static int authenticate(ssh_session session, struct libssh_ruby_options *options, const char* *error) {
  if (options->key) {
    if (ssh_userauth_publickey(session, NULL, options->key) == SSH_AUTH_SUCCESS) {
      return SSH_OK;
    } else {
      *error = "Authentication by key failed.";
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
              *error = "Could not reply to keyboard-interactive prompt.";
              return SSH_ERROR;
            }
          } else {
            *error = "Keyboard-interactive authentication requires too many prompts.";
            return SSH_ERROR;
          }
        } else {
          *error = "Keyboard-interactive authentication with password failed.";
          return SSH_ERROR;
        }
      }
    } else if (auth_methods & SSH_AUTH_METHOD_PASSWORD) {
      if (ssh_userauth_password(session, NULL, options->password) == SSH_AUTH_SUCCESS) {
        return SSH_OK;
      } else {
        *error = "Plain authentication with password failed.";
        return SSH_ERROR;
      }
    } else {
      *error = "Host rejects authentication by password.";
      return SSH_ERROR;
    }
  } else {
    if (ssh_userauth_publickey_auto(session, NULL, NULL) == SSH_AUTH_SUCCESS) {
      return SSH_OK;
    } else {
      *error = "Automatic authentication failed.";
      return SSH_ERROR;
    }
  }
}

static void *nogvl_connect(void *ptr) {
  struct nogvl_session_args *args = ptr;
  args->rc = ssh_connect(args->session);
  if (args->rc == SSH_OK)
    args->rc = authenticate(args->session, args->options, &args->error);
  return NULL;
}

/*
 * @overload connect
 *  Connect to the SSH server.
 *  @return [nil]
 *  @see http://api.libssh.org/stable/group__libssh__session.html ssh_connect
 */
static VALUE m_connect(VALUE self) {
  struct nogvl_session_args args = {
    .session = libssh_ruby_get_session(self),
    .options = unwrap_session(self)->options,
  };
  rb_thread_call_without_gvl(nogvl_connect, &args, RUBY_UBF_IO, NULL);
  if (args.rc == SSH_ERROR) libssh_ruby_raise_message(args.session, args.error);
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

  rb_define_method(rb_cLibSSHSession, "connect",      m_connect,       0);
  rb_define_method(rb_cLibSSHSession, "disconnect",   m_disconnect,    0);

  rb_define_private_method(rb_cLibSSHSession, "set_options", m_set_options, 1);
}
