;;;; package.lisp

(defpackage #:cl-scrypt
  (:use #:cl)
  (:export
    #:derive-key
    #:make-scrypt-kdf))
