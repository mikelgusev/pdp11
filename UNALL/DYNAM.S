dynamic:
dynam:

qL2:
;	$i=177770
;	$j=177766
;	$l=177764
;	$m=177762
;	$n=177760
;	$tl=177756
;	$td=177754
;	$bl=177752
;	$bd=177750
;	$nb=177746
;	$nl=177744
;	$nd=177742
;	$ll=176542

	mov	#d$dat,r5

	mov	#5,r1
	needbits

	mov	b,r0
	bic	#-40,r0
	add	#401,r0
	mov	r0,-34(r5)

	mov	#5,r1
	dumpbits

	mov	#5,r1
	needbits

	mov	b,r0
	bic	#-40,r0
	inc	r0
	mov	r0,-36(r5)

	mov	#5,r1
	dumpbits

	mov	#4,r1
	needbits

	mov	b,r0
	bic	#-20,r0
	add	#4,r0
	mov	r0,-32(r5)

	mov	#4,r1
	dumpbits

	cmp	#440,-34(r5)
	blo	qL10000

	cmp	#40,-36(r5)
	bhis	qL4
qL10000:	mov	#1,r0
	jmp	qL3
qL4:	clr	-12(r5)
qL5:	cmp	-32(r5),-12(r5)
	blos	qL6

	mov	#3,r1
	needbits

	mov	-12(r5),r0
	asl	r0
	mov	border(r0),r0
	asl	r0
	add	r5,r0
	mov	b,r1
	bic	#-10,r1
	mov	r1,-1236(r0)

	mov	#3,r1
	dumpbits

qL7:	inc	-12(r5)
	jmp	qL5
qL6:
qL8:	cmp	#23,-12(r5)
	blos	qL9
	mov	-12(r5),r0
	asl	r0
	mov	border(r0),r0
	asl	r0
	add	r5,r0
	clr	-1236(r0)
qL10:	inc	-12(r5)
	jmp	qL8
qL9:
	mov	#7,-26(r5)

	mov	#h$dat,r5

	mov	#d$dat,$m(r5)
	add	#-26,$m(r5)
	mov	#d$dat,$t(r5)
	add	#-22,$t(r5)
	clr	$e(r5)
	clr	$d(r5)
	mov	#23,$s(r5)
	mov	#23,$n(r5)
	mov	#d$dat,$b(r5)
	add	#-1236,$b(r5)
	call	build
	mov	#d$dat,r5

	mov	r0,-10(r5)
	beq	qL11
	jmp	qL3
qql14:	jmp	ql14
qL11:	mov	-34(r5),r0
	add	-36(r5),r0
	mov	r0,-20(r5)
	mov	-26(r5),r0
	asl	r0
	mov	maskbi(r0),-16(r5)
	clr	r0
	mov	r0,-14(r5)
	mov	r0,-10(r5)
qL13:	cmp	-20(r5),-10(r5)
	blos	qqL14

	mov	-26(r5),r1
	needbits

	mov	b,r0
	mov	-16(r5),r1
	com	r1
	bic	r1,r0
	ash	#2,r0
	add	-22(r5),r0
	mov	r0,-24(r5)
	movb	1(r0),r0
	bic	#^c377,r0
	mov	r0,-12(r5)

	mov	-12(r5),r1
	dumpbits

	mov	-24(r5),r0
	mov	2(r0),-12(r5)
	cmp	#20,-12(r5)
	blos	qL15
	mov	-10(r5),r0
	asl	r0
	inc	-10(r5)
	add	r5,r0
	mov	-12(r5),r1
	mov	r1,-14(r5)
	mov	r1,-1236(r0)
	jmp	qL16
qL15:	cmp	#20,-12(r5)
	bne	qL17

	mov	#2,r1
	needbits

	mov	b,r0
	bic	#-4,r0
	add	#3,r0
	mov	r0,-12(r5)

	mov	#2,r1
	dumpbits

	mov	-10(r5),r0
	add	-12(r5),r0
	cmp	-20(r5),r0
	bhis	qL18
	mov	#1,r0
	jmp	qL3
qL18:
qL19:	mov	-12(r5),r0
	dec	-12(r5)
	tst	r0
	beq	qL20
	mov	-10(r5),r0
	asl	r0
	inc	-10(r5)
	add	r5,r0
	mov	-14(r5),-1236(r0)
	jmp	qL19
qL20:	jmp	qL21
qL17:	cmp	#21,-12(r5)
	bne	qL22

	mov	#3,r1
	needbits

	mov	b,r0
	bic	#-10,r0
	add	#3,r0
	mov	r0,-12(r5)

	mov	#3,r1
	dumpbits

	mov	-10(r5),r0
	add	-12(r5),r0
	cmp	-20(r5),r0
	bhis	qL23
	mov	#1,r0
	jmp	qL3
qL23:
qL24:	mov	-12(r5),r0
	dec	-12(r5)
	tst	r0
	beq	qL25
	mov	-10(r5),r0
	asl	r0
	inc	-10(r5)
	add	r5,r0
	clr	-1236(r0)
	jmp	qL24
qL25:	clr	-14(r5)
	jmp	qL26
qL22:
	mov	#7,r1
	needbits

	mov	b,r0
	bic	#-200,r0
	add	#13,r0
	mov	r0,-12(r5)

	mov	#7,r1
	dumpbits

	mov	-10(r5),r0
	add	-12(r5),r0
	cmp	-20(r5),r0
	bhis	qL27
	mov	#1,r0
	jmp	qL3
qL27:
qL28:	mov	-12(r5),r0
	dec	-12(r5)
	tst	r0
	beq	qL29
	mov	-10(r5),r0
	asl	r0
	inc	-10(r5)
	add	r5,r0
	clr	-1236(r0)
	jmp	qL28
qL29:	clr	-14(r5)
qL26:
qL21:
qL16:	jmp	qL13
qL14:
	mov	#offset+2,nmem

	mov	lbits,-26(r5)
	mov	#h$dat,r5

	mov	#d$dat-26,$m(r5)
	mov	#d$dat-22,$t(r5)
	mov	#cplext,$e(r5)
	mov	#cplens,$d(r5)
	mov	#401,$s(r5)
	mov	-34+d$dat,$n(r5)
	mov	#d$dat-1236,$b(r5)
	call	build
	bcc	qL30

	jmp	qL3

qL30:	mov	dbits,-30+d$dat

	mov	#d$dat-30,$m(r5)
	mov	#d$dat-24,$t(r5)
	mov	#cpdext,$e(r5)
	mov	#cpdist,$d(r5)
	clr	$s(r5)
	mov	-36+d$dat,$n(r5)
	mov	-34+d$dat,r0
	asl	r0
	add	#d$dat-1236,r0
	mov	r0,$b(r5)

	call	build
	bcs	ql3

qL32:	mov	-30+d$dat,$$bd(r5)
	mov	-26+d$dat,$$bl(r5)
	mov	-24+d$dat,$$td(r5)
	mov	-22+d$dat,$$tl(r5)

	call	inflate
qL3:	mov	#h$dat,r5
	RETURN
;L1:sub	$1230,sp
;jbr	L2
                                                                                                                                                                                                                                                                                                                        