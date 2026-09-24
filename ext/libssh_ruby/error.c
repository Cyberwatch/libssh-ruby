#include "libssh_ruby.h"

VALUE rb_eLibSSHError;
ID id_code;

/*
 * Document-class: LibSSH::Error
 * Error returned from libssh.
 *
 * @since 0.1.0
 * @see http://api.libssh.org/stable/group__libssh__error.html
 *
 * @!attribute [r] code
 *  Error code returned from libssh.
 *  @return [Fixnum]
 */

void Init_libssh_error(void) {
  rb_eLibSSHError =
      rb_define_class_under(rb_mLibSSH, "Error", rb_eStandardError);
  id_code = rb_intern("@code");

  rb_define_attr(rb_eLibSSHError, "code", 1, 0);
}

void libssh_ruby_raise(ssh_session session) {
  libssh_ruby_raise_message(session, NULL);
}

void libssh_ruby_raise_message(ssh_session session, const char* message) {
  const char* libssh_error = ssh_get_error(session);

  /* Empty messages are converted to nil so that #to_s defaults to the error type. */
  if (libssh_error && libssh_error[0] == '\0')
    libssh_error = NULL;

  VALUE full_message = Qnil;
  if (message) {
    full_message = rb_str_new_cstr(message);
    if (libssh_error) {
      rb_str_cat_cstr(full_message, " ");
      rb_str_cat_cstr(full_message, libssh_error);
    }
  } else if (libssh_error) {
    full_message = rb_str_new_cstr(libssh_error);
  }

  VALUE argv[1] = { full_message };
  VALUE exception = rb_class_new_instance(1, argv, rb_eLibSSHError);
  rb_ivar_set(exception, id_code, INT2FIX(ssh_get_error_code(session)));
  rb_exc_raise(exception);
}
