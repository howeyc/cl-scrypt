;;;; cl-scrypt.asd

(asdf:defsystem #:cl-scrypt
  :name "scrypt"
  :version "0.2.0"
  :description "Scrypt utility"
  :author "Chris Howey <chris@howey.me>"
  :license "BSD License"
  :serial t
  :depends-on (#:ironclad)
  :components ((:file "package")
               (:file "cl-scrypt")))

