;;;; smbpasswd.asd

(asdf:defsystem #:smbpasswd
  :serial t
  :description "Describe smbpasswd here"
  :author "Your Name <your.name@example.com>"
  :license "Specify license here"
  :depends-on (#:ironclad #:babel)
  :components ((:file "package")
               (:file "smbpasswd")))

