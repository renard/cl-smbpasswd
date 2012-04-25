;;;; package.lisp

(defpackage #:smbpasswd
  (:use #:cl)
  (:export nt lm
	   %lm-string-to-byte-array %lm-integer-to-bit-vector
	   ))

