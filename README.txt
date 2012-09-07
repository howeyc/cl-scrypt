cl-scrypt is a project to implement the scrypt key derivation function
in common lisp.

This is based on two previous works:
C++ Implementation (http://www.tarsnap.com/scrypt.html)
Go Implementation (https://github.com/dchest/scrypt)

TODO:
Look at the magic of Ironclad to see how I can make it faster.

Usage:
(cl-scrypt:make-kdf &key N r p) => kdf
(cl-scrypt:derive-key kdf passphrase salt key-length) => digest

Example:
(cl-scrypt:derive-key (cl-scrypt:make-kdf :N 16384 :r 8 :p 1)
                      (ironclad:ascii-string-to-byte-array "password")
                      (ironclad:ascii-string-to-byte-array "salt")
                      32)
    =>
#(116 87 49 175 68 132 243 35 150 137 105 237 162 137 174 238 0 91 89
  3 172 86 30 100 165 172 161 33 121 123 247 115)
