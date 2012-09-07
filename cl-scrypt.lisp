;;;; cl-scrypt.lisp

(in-package #:cl-scrypt)


(defclass scrypt-kdf ()
 ((N :accessor scrypt-kdf-N
     :initarg :N
     :initform 16384)
  (r :accessor scrypt-kdf-r
     :initarg :r
     :initform 8)
  (p :accessor scrypt-kdf-p
     :initarg :p
     :initform 1)))

(defun make-kdf (&key (N 16384) (r 8) (p 1))
 (make-instance 'scrypt-kdf :N N :r r :p p))

(defmacro start-slice (array-name start-index-expr)
 (let ((start-index (gensym))
       (length-val (gensym)))
  `(let* ((,start-index ,start-index-expr)
          (,length-val (- (length ,array-name) ,start-index)))
    (make-array ,length-val
                :element-type '(unsigned-byte 8)
                :displaced-to ,array-name
                :displaced-index-offset ,start-index))))

(defun mod32+ (a b)
  (declare (type (unsigned-byte 32) a b))
  (ldb (byte 32 0) (+ a b)))

(defun rol32 (a s)
  (declare (type (unsigned-byte 32) a) (type (integer 0 32) s))
  #+sbcl
  (sb-rotate-byte:rotate-byte s (byte 32 0) a)
  #-(or sbcl cmu)
  (logior (ldb (byte 32 0) (ash a s)) (ash a (- s 32))))

(defmacro salsa-4mix (v4 v8 v12 v0)
  `(setf ,v4 (ldb (byte 32 0) (logxor ,v4 (rol32 (mod32+ ,v0 ,v12) 7)))
         ,v8 (ldb (byte 32 0) (logxor ,v8 (rol32 (mod32+ ,v4 ,v0) 9)))
         ,v12 (ldb (byte 32 0) (logxor ,v12 (rol32 (mod32+ ,v8 ,v4) 13)))
         ,v0 (ldb (byte 32 0) (logxor ,v0 (rol32 (mod32+ ,v12 ,v8) 18)))))

(defun block-copy (dst dst-start src src-start n)
 (dotimes (i n)
   (setf (aref dst (+ i dst-start)) (aref src (+ i src-start)))))

(defun block-xor (dst dst-start src src-start n)
 (dotimes (i n)
   (setf (aref dst (+ i dst-start)) (logxor (aref dst (+ i dst-start)) (aref src (+ i src-start))))))

(defun salsa (b)
 (let ((w0 (ironclad:ub32ref/le b 0))
       (w1 (ironclad:ub32ref/le b 4))
       (w2 (ironclad:ub32ref/le b 8))
       (w3 (ironclad:ub32ref/le b 12))
       (w4 (ironclad:ub32ref/le b 16))
       (w5 (ironclad:ub32ref/le b 20))
       (w6 (ironclad:ub32ref/le b 24))
       (w7 (ironclad:ub32ref/le b 28))
       (w8 (ironclad:ub32ref/le b 32))
       (w9 (ironclad:ub32ref/le b 36))
       (w10 (ironclad:ub32ref/le b 40))
       (w11 (ironclad:ub32ref/le b 44))
       (w12 (ironclad:ub32ref/le b 48))
       (w13 (ironclad:ub32ref/le b 52))
       (w14 (ironclad:ub32ref/le b 56))
       (w15 (ironclad:ub32ref/le b 60))
       (x0 (ironclad:ub32ref/le b 0))
       (x1 (ironclad:ub32ref/le b 4))
       (x2 (ironclad:ub32ref/le b 8))
       (x3 (ironclad:ub32ref/le b 12))
       (x4 (ironclad:ub32ref/le b 16))
       (x5 (ironclad:ub32ref/le b 20))
       (x6 (ironclad:ub32ref/le b 24))
       (x7 (ironclad:ub32ref/le b 28))
       (x8 (ironclad:ub32ref/le b 32))
       (x9 (ironclad:ub32ref/le b 36))
       (x10 (ironclad:ub32ref/le b 40))
       (x11 (ironclad:ub32ref/le b 44))
       (x12 (ironclad:ub32ref/le b 48))
       (x13 (ironclad:ub32ref/le b 52))
       (x14 (ironclad:ub32ref/le b 56))
       (x15 (ironclad:ub32ref/le b 60)))

  (declare (type (unsigned-byte 32)
            x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15
            w0 w1 w2 w3 w4 w5 w6 w7 w8 w9 w10 w11 w12 w13 w14 w15)
            (optimize (speed 3) (safety 0)))

  (loop for i from 0 below 8 by 2
        do 
        (salsa-4mix x4 x8 x12 x0)
        (salsa-4mix x9 x13 x1 x5)
        (salsa-4mix x14 x2 x6 x10)
        (salsa-4mix x3 x7 x11 x15)
        (salsa-4mix x1 x2 x3 x0)
        (salsa-4mix x6 x7 x4 x5)
        (salsa-4mix x11 x8 x9 x10)
        (salsa-4mix x12 x13 x14 x15))

  (setf (ironclad:ub32ref/le b 0) (ldb (byte 32 0) (+ x0 w0))
        (ironclad:ub32ref/le b 4) (ldb (byte 32 0) (+ x1 w1))
        (ironclad:ub32ref/le b 8) (ldb (byte 32 0) (+ x2 w2))
        (ironclad:ub32ref/le b 12) (ldb (byte 32 0) (+ x3 w3))
        (ironclad:ub32ref/le b 16) (ldb (byte 32 0) (+ x4 w4))
        (ironclad:ub32ref/le b 20) (ldb (byte 32 0) (+ x5 w5))
        (ironclad:ub32ref/le b 24) (ldb (byte 32 0) (+ x6 w6))
        (ironclad:ub32ref/le b 28) (ldb (byte 32 0) (+ x7 w7))
        (ironclad:ub32ref/le b 32) (ldb (byte 32 0) (+ x8 w8))
        (ironclad:ub32ref/le b 36) (ldb (byte 32 0) (+ x9 w9))
        (ironclad:ub32ref/le b 40) (ldb (byte 32 0) (+ x10 w10))
        (ironclad:ub32ref/le b 44) (ldb (byte 32 0) (+ x11 w11))
        (ironclad:ub32ref/le b 48) (ldb (byte 32 0) (+ x12 w12))
        (ironclad:ub32ref/le b 52) (ldb (byte 32 0) (+ x13 w13))
        (ironclad:ub32ref/le b 56) (ldb (byte 32 0) (+ x14 w14))
        (ironclad:ub32ref/le b 60) (ldb (byte 32 0) (+ x15 w15)))))

(defun block-mix (b y r)
 (let ((xs (make-array 64 :element-type '(unsigned-byte 8))))
  (block-copy xs
              0
              b
              (* 64 (1- (* 2 r)))
              64)
  (loop for i from 0 below (* 2 r)
        do (block-xor xs
                      0
                      b 
                      (* i 64)
                      64)
           (salsa xs)
           (block-copy y
                       (* i 64)
                       xs
                       0
                       64))
  (loop for i from 0 below r
        do (block-copy b
                       (* i 64)
                       y
                       (* 64 2 i)
                       64))
  (loop for i from 0 below r
        do (block-copy b
                       (* 64 (+ i r))
                       y
                       (* 64 (1+ (* i 2)))
                       64))))

(defun smix (b r N v xy)
 (let ((x xy)
       (y (start-slice xy (* 128 r))))
  (block-copy x 0 b 0 (* 128 r))
  (loop for i from 0 below N
        do (block-copy v
                       (* i 128 r)
                       x
                       0
                       (* 128 r))
           (block-mix x
                      y
                      r))
  (loop for i from 0 below N
        do (let ((j (ldb (byte 32 0) (logand (ironclad:ub64ref/le x (* (1- (* 2 r)) 64)) (1- N)))))
            (block-xor x
                       0
                       v
                       (* j 128 r)
                       (* 128 r))
            (block-mix x
                       y
                       r)))
  (block-copy b
              0
              x
              0
              (* 128 r))))

(defun derive-key (kdf passphrase salt key-length)
 (let ((xy (make-array (* 256 (scrypt-kdf-r kdf))
                       :element-type '(unsigned-byte 8)
                       :fill-pointer t))
       (v (make-array (* 128 (scrypt-kdf-r kdf) (scrypt-kdf-N kdf))
                      :element-type '(unsigned-byte 8)
                      :fill-pointer t))
       (b (ironclad:derive-key (ironclad:make-kdf 'ironclad:PBKDF2 :digest 'ironclad:sha256)
                               passphrase
                               salt
                               1
                               (* (scrypt-kdf-p kdf) 128 (scrypt-kdf-r kdf)))))
  (loop for i from 0 below (scrypt-kdf-p kdf)
        do (smix (start-slice b (* i 128 (scrypt-kdf-r kdf)))
                 (scrypt-kdf-r kdf)
                 (scrypt-kdf-N kdf)
                 v
                 xy))
  (ironclad:derive-key (ironclad:make-kdf 'ironclad:PBKDF2 :digest 'ironclad:SHA256)
                       passphrase
                       b
                       1
                       key-length)))
