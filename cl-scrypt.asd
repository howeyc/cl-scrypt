;;;; cl-scrypt.asd

(asdf:defsystem #:cl-scrypt
  :name "scrypt"
  :version "0.1.0"
  :description "Scrypt key derivation function"
  :author "Chris Howey <chris@howey.me>"
  :license "BSD License"
  :serial t
  :depends-on (#:ironclad)
  :components ((:file "package")
               (:file "ironclad-common")
               (:file "cl-scrypt")))

