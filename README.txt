cl-scrypt is a project to implement the scrypt utility in common lisp.

The file format is the same as the original scrypt utility.
http://www.tarsnap.com/scrypt.html

Usage:
(with-open-file (out "/path/to/file.plain" :direction :output)
  (cl-scrypt:decrypt-file "/path/to/file.enc" "my-passphrase" out))

(with-open-file (out "/path/to/file.enc" :direction :output)
  (cl-scrypt:encrypt-file "/path/to/file.plain" "my-passphrase" out))
