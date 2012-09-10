;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
(ql:quickload :cl-scrypt)

;;; Test vectors based on calling crypto_scrypt library function in
;;; the original scrypt utility.

(defvar *scrypt1-password*
  (coerce #(112 97 115 115 119 111 114 100)
          '(vector (unsigned-byte 8))))
(defvar *scrypt1-salt*
  (coerce #(115 97 108 116)
          '(vector (unsigned-byte 8))))

(defvar *scrypt1-key*
  (coerce #(116 87 49 175 68 132 243 35 150 137 105 237 162 137 174 238 0 91 89
            3 172 86 30 100 165 172 161 33 121 123 247 115)
          '(vector (unsigned-byte 8))))

(defvar *scrypt2-password*
  (coerce #(112 97 115 115 119 111 114 100)
          '(vector (unsigned-byte 8))))
(defvar *scrypt2-salt*
  (coerce #(115 97 108 116)
          '(vector (unsigned-byte 8))))

(defvar *scrypt2-key*
  (coerce #(243 198 84 124 73 207 248 197 175 189 52 186 30 224 136 138 229 99
            59 58 111 136 95 54 139 227 241 159 14 126 231 215)
          '(vector (unsigned-byte 8))))

(defvar *scrypt3-password*
  (coerce #(112 97 115 115 119 111 114 100)
          '(vector (unsigned-byte 8))))
(defvar *scrypt3-salt*
  (coerce #(115 97 108 116)
          '(vector (unsigned-byte 8))))

(defvar *scrypt3-key*
  (coerce #(136 189 94 219 82 209 221 0 24 135 114 173 54 23 18 144 34 78 116
            130 149 37 177 141 115 35 165 127 145 150 60 55) 
          '(vector (unsigned-byte 8))))

(defun run-tests ()
 (values *scrypt1-key* (cl-scrypt:derive-key (cl-scrypt:make-scrypt-kdf) *scrypt1-password* *scrypt1-salt* (length *scrypt1-key*))
 *scrypt2-key* (cl-scrypt:derive-key (cl-scrypt:make-scrypt-kdf 16384 8 2) *scrypt2-password* *scrypt2-salt* (length *scrypt2-key*))
 *scrypt3-key* (cl-scrypt:derive-key (cl-scrypt:make-scrypt-kdf 16 100 100) *scrypt3-password* *scrypt3-salt* (length *scrypt3-key*))))
