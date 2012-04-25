;;;; smbpasswd.lisp

(in-package #:smbpasswd)

(defconstant +smb-lmhash-magic+
  (ironclad:ascii-string-to-byte-array "KGS!@#$%")
  "Byte array containing the message to be encrypted with DES keys.")

(defconstant +smb-lm-passwd-max-length+ 14
  "Maximum length for LM password.")

(defun nt (string)
  "Hash STRING using NT-LANMANv1 algorithm."
  ;; - convert string to UTF-16LE byte array
  ;; - compute MD4 hash
  ;; - return the uppercase hex string of the digest.
  (string-upcase
   (ironclad:byte-array-to-hex-string
    (ironclad:digest-sequence
     :md4
     (babel:string-to-octets string :encoding :UTF-16LE)))))

(defun %lm-string-to-byte-array (string)
  "Convert STRING to 14-byte array. Characters after 14 are cut off. If
STRING is smaller than 14 it would be 0x00 padded."
  (let ((str-len (length string)))
    (ironclad:ascii-string-to-byte-array
     (string-upcase
      (if (>= str-len +smb-lm-passwd-max-length+)
	  (subseq string 0 +smb-lm-passwd-max-length+)
	  (concatenate
	   'string string
	   (make-sequence 'string (- +smb-lm-passwd-max-length+ str-len))))))))


(defun %lm-encrypt-magic-with-key (key)
  "Encrypt +smb-lmhash-magic+ with DES cipher and ECB mode
using KEY."
  (let ((ret (make-array '(8) :element-type '(unsigned-byte 8))))
    (ironclad:encrypt
     (ironclad:make-cipher :des :mode :ecb :key key)
     +smb-lmhash-magic+
     ret)
    ret))


(defun %lm-convert-byte-array-to-128bit (byte-array)
  ""
  (make-array 8 :element-type '(unsigned-byte 8)
	      :initial-contents
	      (loop for i below 8
		 if (= 0 i)
		 collect (logand (aref byte-array 0) #xFE)
		 else if (= 7 i)
		 collect (ash (logand #x7F (aref byte-array 6)) 1)
		 else
		 collect (ash
			  (logior (ash (logand
					(- (ash 1 i) 1)
					(aref byte-array (- i 1)))
				       (- 7 i))
				  (ash (aref byte-array i) (- (- 1) i)))
			  1))))

(defun lm (string)
  "Hash STRING using deprecated Windows LM-hash."
  (let ((bya (%lm-string-to-byte-array string)))
    (string-upcase
     (ironclad:byte-array-to-hex-string
      (concatenate 'vector
		   (%lm-encrypt-magic-with-key
		    (%lm-convert-byte-array-to-8bit (subseq bya 0 7)))
		   (%lm-encrypt-magic-with-key
		    (%lm-convert-byte-array-to-8bit (subseq bya 7 14))))))))

;;; "smbpasswd" goes here. Hacks and glory await!

