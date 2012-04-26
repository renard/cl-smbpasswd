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



(defun %lm-convert-byte-array-to-64bit (byte-array)
  "Extend 56-bit byte array BYTE-ARRAY to a 64-bit byte array.

This is done by adding a null padding bit each 7 bits.

Example: convert a bit-array from:
 #*10110010110110001100110100011010110101111011001101101110
to (. stands for 0)
 #*1011001.0110110.0011001.1010001.1010110.1011110.1100110.1101110.
"
  (check-type byte-array (array * (7)))
  (let* ((array-length (length byte-array))
	 ;; Fist convert the byte array to its numerical representation in
	 ;; order to get a 56-bit array.  For every element of byte-array
	 ;; shift left 8 *(length - position)
	 ;; => (* 256^((length - position)))
	 ;; and sum up the result
	 (sum (loop for i below array-length
		 summing (ash (elt byte-array i)
			      (* 8 (- array-length i 1)))))
	 (mask (byte 7 0)))

    ;; Extract every blocks of 7-bit from `sum' and convert it to a 8-bit
    ;; integer (shift left 1 bit == * 2).
    ;; Block extraction is done by moving a 7-bit mask from left to right.
    ;; return the result to its byte-array representation.
    (make-array (1+ array-length) :element-type '(unsigned-byte 8)
		:initial-contents
		(loop for i from array-length downto 0
		   collect
		     (ash
		      (ldb
		       (ash mask (* 7 i)) ;; shift mask from left to right
		       sum) ;; extract a 7-bit block from sum
		      1)    ;; shift left the 7-bit block to create a 8-bit
		     ))))   ;; block and insert the padding bit.

(defun lm (string)
  "Hash STRING using deprecated Windows LM-hash."
  (let ((bya (%lm-string-to-byte-array string)))
    ;; Join both +smb-lmhash-magic+ encrypted message and return a
    ;; capitalized representation.
    (string-upcase
     (ironclad:byte-array-to-hex-string
      (concatenate 'vector
		   (%lm-encrypt-magic-with-key
		    (%lm-convert-byte-array-to-64bit
		     (subseq bya 0 (/ +smb-lm-passwd-max-length+ 2))))
		   (%lm-encrypt-magic-with-key
		    (%lm-convert-byte-array-to-128bit
		     (subseq bya  (/ +smb-lm-passwd-max-length+ 2)
			     +smb-lm-passwd-max-length+))))))))

;;; "smbpasswd" goes here. Hacks and glory await!

