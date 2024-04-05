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
  VALUE exc, code;
  VALUE argv[1];

  /* Empty messages are converted to nil so that #to_s defaults to the error type. */
  const char* message = ssh_get_error(session);
  argv[0] = (message != NULL && message[0] != '\0') ? rb_str_new_cstr(message) : Qnil;

  exc = rb_class_new_instance(1, argv, rb_eLibSSHError);
  code = INT2FIX(ssh_get_error_code(session));
  rb_ivar_set(exc, id_code, code);

  rb_exc_raise(exc);
}
