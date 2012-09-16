cl-scrypt is a project to implement the scrypt utility in common lisp.

http://www.tarsnap.com/scrypt.html

The scrypt key derivation function is part of ironclad.

This is still in early stages.

Usage:
(cl-scrypt:decrypt-file "/path/to/file" "my-passphrase" *standard-ouput*) => T
