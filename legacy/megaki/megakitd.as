
bin/megakitd:     file format elf64-x86-64


Disassembly of section .init:

0000000000401798 <_init>:
  401798:	48 83 ec 08          	sub    $0x8,%rsp
  40179c:	48 8b 05 75 4a 20 00 	mov    0x204a75(%rip),%rax        # 606218 <_DYNAMIC+0x200>
  4017a3:	48 85 c0             	test   %rax,%rax
  4017a6:	74 05                	je     4017ad <_init+0x15>
  4017a8:	e8 93 00 00 00       	callq  401840 <__gmon_start__@plt>
  4017ad:	48 83 c4 08          	add    $0x8,%rsp
  4017b1:	c3                   	retq   

Disassembly of section .plt:

00000000004017c0 <pthread_cond_destroy@plt-0x10>:
  4017c0:	ff 35 6a 4a 20 00    	pushq  0x204a6a(%rip)        # 606230 <_GLOBAL_OFFSET_TABLE_+0x8>
  4017c6:	ff 25 6c 4a 20 00    	jmpq   *0x204a6c(%rip)        # 606238 <_GLOBAL_OFFSET_TABLE_+0x10>
  4017cc:	0f 1f 40 00          	nopl   0x0(%rax)

00000000004017d0 <pthread_cond_destroy@plt>:
  4017d0:	ff 25 6a 4a 20 00    	jmpq   *0x204a6a(%rip)        # 606240 <_GLOBAL_OFFSET_TABLE_+0x18>
  4017d6:	68 00 00 00 00       	pushq  $0x0
  4017db:	e9 e0 ff ff ff       	jmpq   4017c0 <_init+0x28>

00000000004017e0 <RAND_pseudo_bytes@plt>:
  4017e0:	ff 25 62 4a 20 00    	jmpq   *0x204a62(%rip)        # 606248 <_GLOBAL_OFFSET_TABLE_+0x20>
  4017e6:	68 01 00 00 00       	pushq  $0x1
  4017eb:	e9 d0 ff ff ff       	jmpq   4017c0 <_init+0x28>

00000000004017f0 <memset@plt>:
  4017f0:	ff 25 5a 4a 20 00    	jmpq   *0x204a5a(%rip)        # 606250 <_GLOBAL_OFFSET_TABLE_+0x28>
  4017f6:	68 02 00 00 00       	pushq  $0x2
  4017fb:	e9 c0 ff ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401800 <CRYPTO_cleanup_all_ex_data@plt>:
  401800:	ff 25 52 4a 20 00    	jmpq   *0x204a52(%rip)        # 606258 <_GLOBAL_OFFSET_TABLE_+0x30>
  401806:	68 03 00 00 00       	pushq  $0x3
  40180b:	e9 b0 ff ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401810 <uv_async_send@plt>:
  401810:	ff 25 4a 4a 20 00    	jmpq   *0x204a4a(%rip)        # 606260 <_GLOBAL_OFFSET_TABLE_+0x38>
  401816:	68 04 00 00 00       	pushq  $0x4
  40181b:	e9 a0 ff ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401820 <RSA_private_decrypt@plt>:
  401820:	ff 25 42 4a 20 00    	jmpq   *0x204a42(%rip)        # 606268 <_GLOBAL_OFFSET_TABLE_+0x40>
  401826:	68 05 00 00 00       	pushq  $0x5
  40182b:	e9 90 ff ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401830 <uv_ip4_addr@plt>:
  401830:	ff 25 3a 4a 20 00    	jmpq   *0x204a3a(%rip)        # 606270 <_GLOBAL_OFFSET_TABLE_+0x48>
  401836:	68 06 00 00 00       	pushq  $0x6
  40183b:	e9 80 ff ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401840 <__gmon_start__@plt>:
  401840:	ff 25 32 4a 20 00    	jmpq   *0x204a32(%rip)        # 606278 <_GLOBAL_OFFSET_TABLE_+0x50>
  401846:	68 07 00 00 00       	pushq  $0x7
  40184b:	e9 70 ff ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401850 <pthread_cond_signal@plt>:
  401850:	ff 25 2a 4a 20 00    	jmpq   *0x204a2a(%rip)        # 606280 <_GLOBAL_OFFSET_TABLE_+0x58>
  401856:	68 08 00 00 00       	pushq  $0x8
  40185b:	e9 60 ff ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401860 <exit@plt>:
  401860:	ff 25 22 4a 20 00    	jmpq   *0x204a22(%rip)        # 606288 <_GLOBAL_OFFSET_TABLE_+0x60>
  401866:	68 09 00 00 00       	pushq  $0x9
  40186b:	e9 50 ff ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401870 <putchar@plt>:
  401870:	ff 25 1a 4a 20 00    	jmpq   *0x204a1a(%rip)        # 606290 <_GLOBAL_OFFSET_TABLE_+0x68>
  401876:	68 0a 00 00 00       	pushq  $0xa
  40187b:	e9 40 ff ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401880 <malloc@plt>:
  401880:	ff 25 12 4a 20 00    	jmpq   *0x204a12(%rip)        # 606298 <_GLOBAL_OFFSET_TABLE_+0x70>
  401886:	68 0b 00 00 00       	pushq  $0xb
  40188b:	e9 30 ff ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401890 <fopen@plt>:
  401890:	ff 25 0a 4a 20 00    	jmpq   *0x204a0a(%rip)        # 6062a0 <_GLOBAL_OFFSET_TABLE_+0x78>
  401896:	68 0c 00 00 00       	pushq  $0xc
  40189b:	e9 20 ff ff ff       	jmpq   4017c0 <_init+0x28>

00000000004018a0 <__libc_start_main@plt>:
  4018a0:	ff 25 02 4a 20 00    	jmpq   *0x204a02(%rip)        # 6062a8 <_GLOBAL_OFFSET_TABLE_+0x80>
  4018a6:	68 0d 00 00 00       	pushq  $0xd
  4018ab:	e9 10 ff ff ff       	jmpq   4017c0 <_init+0x28>

00000000004018b0 <RSA_new@plt>:
  4018b0:	ff 25 fa 49 20 00    	jmpq   *0x2049fa(%rip)        # 6062b0 <_GLOBAL_OFFSET_TABLE_+0x88>
  4018b6:	68 0e 00 00 00       	pushq  $0xe
  4018bb:	e9 00 ff ff ff       	jmpq   4017c0 <_init+0x28>

00000000004018c0 <RSA_free@plt>:
  4018c0:	ff 25 f2 49 20 00    	jmpq   *0x2049f2(%rip)        # 6062b8 <_GLOBAL_OFFSET_TABLE_+0x90>
  4018c6:	68 0f 00 00 00       	pushq  $0xf
  4018cb:	e9 f0 fe ff ff       	jmpq   4017c0 <_init+0x28>

00000000004018d0 <uv_loop_delete@plt>:
  4018d0:	ff 25 ea 49 20 00    	jmpq   *0x2049ea(%rip)        # 6062c0 <_GLOBAL_OFFSET_TABLE_+0x98>
  4018d6:	68 10 00 00 00       	pushq  $0x10
  4018db:	e9 e0 fe ff ff       	jmpq   4017c0 <_init+0x28>

00000000004018e0 <setsockopt@plt>:
  4018e0:	ff 25 e2 49 20 00    	jmpq   *0x2049e2(%rip)        # 6062c8 <_GLOBAL_OFFSET_TABLE_+0xa0>
  4018e6:	68 11 00 00 00       	pushq  $0x11
  4018eb:	e9 d0 fe ff ff       	jmpq   4017c0 <_init+0x28>

00000000004018f0 <pthread_mutex_init@plt>:
  4018f0:	ff 25 da 49 20 00    	jmpq   *0x2049da(%rip)        # 6062d0 <_GLOBAL_OFFSET_TABLE_+0xa8>
  4018f6:	68 12 00 00 00       	pushq  $0x12
  4018fb:	e9 c0 fe ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401900 <fgets@plt>:
  401900:	ff 25 d2 49 20 00    	jmpq   *0x2049d2(%rip)        # 6062d8 <_GLOBAL_OFFSET_TABLE_+0xb0>
  401906:	68 13 00 00 00       	pushq  $0x13
  40190b:	e9 b0 fe ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401910 <uv_default_loop@plt>:
  401910:	ff 25 ca 49 20 00    	jmpq   *0x2049ca(%rip)        # 6062e0 <_GLOBAL_OFFSET_TABLE_+0xb8>
  401916:	68 14 00 00 00       	pushq  $0x14
  40191b:	e9 a0 fe ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401920 <ERR_load_crypto_strings@plt>:
  401920:	ff 25 c2 49 20 00    	jmpq   *0x2049c2(%rip)        # 6062e8 <_GLOBAL_OFFSET_TABLE_+0xc0>
  401926:	68 15 00 00 00       	pushq  $0x15
  40192b:	e9 90 fe ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401930 <fputc@plt>:
  401930:	ff 25 ba 49 20 00    	jmpq   *0x2049ba(%rip)        # 6062f0 <_GLOBAL_OFFSET_TABLE_+0xc8>
  401936:	68 16 00 00 00       	pushq  $0x16
  40193b:	e9 80 fe ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401940 <free@plt>:
  401940:	ff 25 b2 49 20 00    	jmpq   *0x2049b2(%rip)        # 6062f8 <_GLOBAL_OFFSET_TABLE_+0xd0>
  401946:	68 17 00 00 00       	pushq  $0x17
  40194b:	e9 70 fe ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401950 <uv_run@plt>:
  401950:	ff 25 aa 49 20 00    	jmpq   *0x2049aa(%rip)        # 606300 <_GLOBAL_OFFSET_TABLE_+0xd8>
  401956:	68 18 00 00 00       	pushq  $0x18
  40195b:	e9 60 fe ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401960 <strlen@plt>:
  401960:	ff 25 a2 49 20 00    	jmpq   *0x2049a2(%rip)        # 606308 <_GLOBAL_OFFSET_TABLE_+0xe0>
  401966:	68 19 00 00 00       	pushq  $0x19
  40196b:	e9 50 fe ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401970 <EVP_cleanup@plt>:
  401970:	ff 25 9a 49 20 00    	jmpq   *0x20499a(%rip)        # 606310 <_GLOBAL_OFFSET_TABLE_+0xe8>
  401976:	68 1a 00 00 00       	pushq  $0x1a
  40197b:	e9 40 fe ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401980 <pthread_create@plt>:
  401980:	ff 25 92 49 20 00    	jmpq   *0x204992(%rip)        # 606318 <_GLOBAL_OFFSET_TABLE_+0xf0>
  401986:	68 1b 00 00 00       	pushq  $0x1b
  40198b:	e9 30 fe ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401990 <pthread_cond_init@plt>:
  401990:	ff 25 8a 49 20 00    	jmpq   *0x20498a(%rip)        # 606320 <_GLOBAL_OFFSET_TABLE_+0xf8>
  401996:	68 1c 00 00 00       	pushq  $0x1c
  40199b:	e9 20 fe ff ff       	jmpq   4017c0 <_init+0x28>

00000000004019a0 <uv_tcp_init@plt>:
  4019a0:	ff 25 82 49 20 00    	jmpq   *0x204982(%rip)        # 606328 <_GLOBAL_OFFSET_TABLE_+0x100>
  4019a6:	68 1d 00 00 00       	pushq  $0x1d
  4019ab:	e9 10 fe ff ff       	jmpq   4017c0 <_init+0x28>

00000000004019b0 <uv_tcp_bind@plt>:
  4019b0:	ff 25 7a 49 20 00    	jmpq   *0x20497a(%rip)        # 606330 <_GLOBAL_OFFSET_TABLE_+0x108>
  4019b6:	68 1e 00 00 00       	pushq  $0x1e
  4019bb:	e9 00 fe ff ff       	jmpq   4017c0 <_init+0x28>

00000000004019c0 <ERR_free_strings@plt>:
  4019c0:	ff 25 72 49 20 00    	jmpq   *0x204972(%rip)        # 606338 <_GLOBAL_OFFSET_TABLE_+0x110>
  4019c6:	68 1f 00 00 00       	pushq  $0x1f
  4019cb:	e9 f0 fd ff ff       	jmpq   4017c0 <_init+0x28>

00000000004019d0 <BN_bn2bin@plt>:
  4019d0:	ff 25 6a 49 20 00    	jmpq   *0x20496a(%rip)        # 606340 <_GLOBAL_OFFSET_TABLE_+0x118>
  4019d6:	68 20 00 00 00       	pushq  $0x20
  4019db:	e9 e0 fd ff ff       	jmpq   4017c0 <_init+0x28>

00000000004019e0 <uv_write@plt>:
  4019e0:	ff 25 62 49 20 00    	jmpq   *0x204962(%rip)        # 606348 <_GLOBAL_OFFSET_TABLE_+0x120>
  4019e6:	68 21 00 00 00       	pushq  $0x21
  4019eb:	e9 d0 fd ff ff       	jmpq   4017c0 <_init+0x28>

00000000004019f0 <pthread_join@plt>:
  4019f0:	ff 25 5a 49 20 00    	jmpq   *0x20495a(%rip)        # 606350 <_GLOBAL_OFFSET_TABLE_+0x128>
  4019f6:	68 22 00 00 00       	pushq  $0x22
  4019fb:	e9 c0 fd ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401a00 <sigaction@plt>:
  401a00:	ff 25 52 49 20 00    	jmpq   *0x204952(%rip)        # 606358 <_GLOBAL_OFFSET_TABLE_+0x130>
  401a06:	68 23 00 00 00       	pushq  $0x23
  401a0b:	e9 b0 fd ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401a10 <PEM_read_RSAPrivateKey@plt>:
  401a10:	ff 25 4a 49 20 00    	jmpq   *0x20494a(%rip)        # 606360 <_GLOBAL_OFFSET_TABLE_+0x138>
  401a16:	68 24 00 00 00       	pushq  $0x24
  401a1b:	e9 a0 fd ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401a20 <pthread_exit@plt>:
  401a20:	ff 25 42 49 20 00    	jmpq   *0x204942(%rip)        # 606368 <_GLOBAL_OFFSET_TABLE_+0x140>
  401a26:	68 25 00 00 00       	pushq  $0x25
  401a2b:	e9 90 fd ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401a30 <uv_read_start@plt>:
  401a30:	ff 25 3a 49 20 00    	jmpq   *0x20493a(%rip)        # 606370 <_GLOBAL_OFFSET_TABLE_+0x148>
  401a36:	68 26 00 00 00       	pushq  $0x26
  401a3b:	e9 80 fd ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401a40 <SHA256@plt>:
  401a40:	ff 25 32 49 20 00    	jmpq   *0x204932(%rip)        # 606378 <_GLOBAL_OFFSET_TABLE_+0x150>
  401a46:	68 27 00 00 00       	pushq  $0x27
  401a4b:	e9 70 fd ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401a50 <atoi@plt>:
  401a50:	ff 25 2a 49 20 00    	jmpq   *0x20492a(%rip)        # 606380 <_GLOBAL_OFFSET_TABLE_+0x158>
  401a56:	68 28 00 00 00       	pushq  $0x28
  401a5b:	e9 60 fd ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401a60 <uv_async_init@plt>:
  401a60:	ff 25 22 49 20 00    	jmpq   *0x204922(%rip)        # 606388 <_GLOBAL_OFFSET_TABLE_+0x160>
  401a66:	68 29 00 00 00       	pushq  $0x29
  401a6b:	e9 50 fd ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401a70 <ERR_print_errors_fp@plt>:
  401a70:	ff 25 1a 49 20 00    	jmpq   *0x20491a(%rip)        # 606390 <_GLOBAL_OFFSET_TABLE_+0x168>
  401a76:	68 2a 00 00 00       	pushq  $0x2a
  401a7b:	e9 40 fd ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401a80 <ERR_get_error@plt>:
  401a80:	ff 25 12 49 20 00    	jmpq   *0x204912(%rip)        # 606398 <_GLOBAL_OFFSET_TABLE_+0x170>
  401a86:	68 2b 00 00 00       	pushq  $0x2b
  401a8b:	e9 30 fd ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401a90 <raise@plt>:
  401a90:	ff 25 0a 49 20 00    	jmpq   *0x20490a(%rip)        # 6063a0 <_GLOBAL_OFFSET_TABLE_+0x178>
  401a96:	68 2c 00 00 00       	pushq  $0x2c
  401a9b:	e9 20 fd ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401aa0 <uv_shutdown@plt>:
  401aa0:	ff 25 02 49 20 00    	jmpq   *0x204902(%rip)        # 6063a8 <_GLOBAL_OFFSET_TABLE_+0x180>
  401aa6:	68 2d 00 00 00       	pushq  $0x2d
  401aab:	e9 10 fd ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401ab0 <uv_accept@plt>:
  401ab0:	ff 25 fa 48 20 00    	jmpq   *0x2048fa(%rip)        # 6063b0 <_GLOBAL_OFFSET_TABLE_+0x188>
  401ab6:	68 2e 00 00 00       	pushq  $0x2e
  401abb:	e9 00 fd ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401ac0 <uv_listen@plt>:
  401ac0:	ff 25 f2 48 20 00    	jmpq   *0x2048f2(%rip)        # 6063b8 <_GLOBAL_OFFSET_TABLE_+0x190>
  401ac6:	68 2f 00 00 00       	pushq  $0x2f
  401acb:	e9 f0 fc ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401ad0 <RAND_bytes@plt>:
  401ad0:	ff 25 ea 48 20 00    	jmpq   *0x2048ea(%rip)        # 6063c0 <_GLOBAL_OFFSET_TABLE_+0x198>
  401ad6:	68 30 00 00 00       	pushq  $0x30
  401adb:	e9 e0 fc ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401ae0 <clock@plt>:
  401ae0:	ff 25 e2 48 20 00    	jmpq   *0x2048e2(%rip)        # 6063c8 <_GLOBAL_OFFSET_TABLE_+0x1a0>
  401ae6:	68 31 00 00 00       	pushq  $0x31
  401aeb:	e9 d0 fc ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401af0 <uv_stop@plt>:
  401af0:	ff 25 da 48 20 00    	jmpq   *0x2048da(%rip)        # 6063d0 <_GLOBAL_OFFSET_TABLE_+0x1a8>
  401af6:	68 32 00 00 00       	pushq  $0x32
  401afb:	e9 c0 fc ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401b00 <strcmp@plt>:
  401b00:	ff 25 d2 48 20 00    	jmpq   *0x2048d2(%rip)        # 6063d8 <_GLOBAL_OFFSET_TABLE_+0x1b0>
  401b06:	68 33 00 00 00       	pushq  $0x33
  401b0b:	e9 b0 fc ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401b10 <uv_close@plt>:
  401b10:	ff 25 ca 48 20 00    	jmpq   *0x2048ca(%rip)        # 6063e0 <_GLOBAL_OFFSET_TABLE_+0x1b8>
  401b16:	68 34 00 00 00       	pushq  $0x34
  401b1b:	e9 a0 fc ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401b20 <srand@plt>:
  401b20:	ff 25 c2 48 20 00    	jmpq   *0x2048c2(%rip)        # 6063e8 <_GLOBAL_OFFSET_TABLE_+0x1c0>
  401b26:	68 35 00 00 00       	pushq  $0x35
  401b2b:	e9 90 fc ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401b30 <pthread_cond_wait@plt>:
  401b30:	ff 25 ba 48 20 00    	jmpq   *0x2048ba(%rip)        # 6063f0 <_GLOBAL_OFFSET_TABLE_+0x1c8>
  401b36:	68 36 00 00 00       	pushq  $0x36
  401b3b:	e9 80 fc ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401b40 <memcmp@plt>:
  401b40:	ff 25 b2 48 20 00    	jmpq   *0x2048b2(%rip)        # 6063f8 <_GLOBAL_OFFSET_TABLE_+0x1d0>
  401b46:	68 37 00 00 00       	pushq  $0x37
  401b4b:	e9 70 fc ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401b50 <feof@plt>:
  401b50:	ff 25 aa 48 20 00    	jmpq   *0x2048aa(%rip)        # 606400 <_GLOBAL_OFFSET_TABLE_+0x1d8>
  401b56:	68 38 00 00 00       	pushq  $0x38
  401b5b:	e9 60 fc ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401b60 <fclose@plt>:
  401b60:	ff 25 a2 48 20 00    	jmpq   *0x2048a2(%rip)        # 606408 <_GLOBAL_OFFSET_TABLE_+0x1e0>
  401b66:	68 39 00 00 00       	pushq  $0x39
  401b6b:	e9 50 fc ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401b70 <BN_num_bits@plt>:
  401b70:	ff 25 9a 48 20 00    	jmpq   *0x20489a(%rip)        # 606410 <_GLOBAL_OFFSET_TABLE_+0x1e8>
  401b76:	68 3a 00 00 00       	pushq  $0x3a
  401b7b:	e9 40 fc ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401b80 <RSA_public_encrypt@plt>:
  401b80:	ff 25 92 48 20 00    	jmpq   *0x204892(%rip)        # 606418 <_GLOBAL_OFFSET_TABLE_+0x1f0>
  401b86:	68 3b 00 00 00       	pushq  $0x3b
  401b8b:	e9 30 fc ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401b90 <fork@plt>:
  401b90:	ff 25 8a 48 20 00    	jmpq   *0x20488a(%rip)        # 606420 <_GLOBAL_OFFSET_TABLE_+0x1f8>
  401b96:	68 3c 00 00 00       	pushq  $0x3c
  401b9b:	e9 20 fc ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401ba0 <sigemptyset@plt>:
  401ba0:	ff 25 82 48 20 00    	jmpq   *0x204882(%rip)        # 606428 <_GLOBAL_OFFSET_TABLE_+0x200>
  401ba6:	68 3d 00 00 00       	pushq  $0x3d
  401bab:	e9 10 fc ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401bb0 <fwrite@plt>:
  401bb0:	ff 25 7a 48 20 00    	jmpq   *0x20487a(%rip)        # 606430 <_GLOBAL_OFFSET_TABLE_+0x208>
  401bb6:	68 3e 00 00 00       	pushq  $0x3e
  401bbb:	e9 00 fc ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401bc0 <pthread_mutex_lock@plt>:
  401bc0:	ff 25 72 48 20 00    	jmpq   *0x204872(%rip)        # 606438 <_GLOBAL_OFFSET_TABLE_+0x210>
  401bc6:	68 3f 00 00 00       	pushq  $0x3f
  401bcb:	e9 f0 fb ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401bd0 <OpenSSL_add_all_ciphers@plt>:
  401bd0:	ff 25 6a 48 20 00    	jmpq   *0x20486a(%rip)        # 606440 <_GLOBAL_OFFSET_TABLE_+0x218>
  401bd6:	68 40 00 00 00       	pushq  $0x40
  401bdb:	e9 e0 fb ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401be0 <perror@plt>:
  401be0:	ff 25 62 48 20 00    	jmpq   *0x204862(%rip)        # 606448 <_GLOBAL_OFFSET_TABLE_+0x220>
  401be6:	68 41 00 00 00       	pushq  $0x41
  401beb:	e9 d0 fb ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401bf0 <rand@plt>:
  401bf0:	ff 25 5a 48 20 00    	jmpq   *0x20485a(%rip)        # 606450 <_GLOBAL_OFFSET_TABLE_+0x228>
  401bf6:	68 42 00 00 00       	pushq  $0x42
  401bfb:	e9 c0 fb ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401c00 <fprintf@plt>:
  401c00:	ff 25 52 48 20 00    	jmpq   *0x204852(%rip)        # 606458 <_GLOBAL_OFFSET_TABLE_+0x230>
  401c06:	68 43 00 00 00       	pushq  $0x43
  401c0b:	e9 b0 fb ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401c10 <uv_buf_init@plt>:
  401c10:	ff 25 4a 48 20 00    	jmpq   *0x20484a(%rip)        # 606460 <_GLOBAL_OFFSET_TABLE_+0x238>
  401c16:	68 44 00 00 00       	pushq  $0x44
  401c1b:	e9 a0 fb ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401c20 <pthread_mutex_destroy@plt>:
  401c20:	ff 25 42 48 20 00    	jmpq   *0x204842(%rip)        # 606468 <_GLOBAL_OFFSET_TABLE_+0x240>
  401c26:	68 45 00 00 00       	pushq  $0x45
  401c2b:	e9 90 fb ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401c30 <pthread_cond_broadcast@plt>:
  401c30:	ff 25 3a 48 20 00    	jmpq   *0x20483a(%rip)        # 606470 <_GLOBAL_OFFSET_TABLE_+0x248>
  401c36:	68 46 00 00 00       	pushq  $0x46
  401c3b:	e9 80 fb ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401c40 <ERR_reason_error_string@plt>:
  401c40:	ff 25 32 48 20 00    	jmpq   *0x204832(%rip)        # 606478 <_GLOBAL_OFFSET_TABLE_+0x250>
  401c46:	68 47 00 00 00       	pushq  $0x47
  401c4b:	e9 70 fb ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401c50 <BN_bin2bn@plt>:
  401c50:	ff 25 2a 48 20 00    	jmpq   *0x20482a(%rip)        # 606480 <_GLOBAL_OFFSET_TABLE_+0x258>
  401c56:	68 48 00 00 00       	pushq  $0x48
  401c5b:	e9 60 fb ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401c60 <pthread_mutex_unlock@plt>:
  401c60:	ff 25 22 48 20 00    	jmpq   *0x204822(%rip)        # 606488 <_GLOBAL_OFFSET_TABLE_+0x260>
  401c66:	68 49 00 00 00       	pushq  $0x49
  401c6b:	e9 50 fb ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401c70 <memcpy@plt>:
  401c70:	ff 25 1a 48 20 00    	jmpq   *0x20481a(%rip)        # 606490 <_GLOBAL_OFFSET_TABLE_+0x268>
  401c76:	68 4a 00 00 00       	pushq  $0x4a
  401c7b:	e9 40 fb ff ff       	jmpq   4017c0 <_init+0x28>

0000000000401c80 <time@plt>:
  401c80:	ff 25 12 48 20 00    	jmpq   *0x204812(%rip)        # 606498 <_GLOBAL_OFFSET_TABLE_+0x270>
  401c86:	68 4b 00 00 00       	pushq  $0x4b
  401c8b:	e9 30 fb ff ff       	jmpq   4017c0 <_init+0x28>

Disassembly of section .text:

0000000000401c90 <_start>:
  401c90:	31 ed                	xor    %ebp,%ebp
  401c92:	49 89 d1             	mov    %rdx,%r9
  401c95:	5e                   	pop    %rsi
  401c96:	48 89 e2             	mov    %rsp,%rdx
  401c99:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  401c9d:	50                   	push   %rax
  401c9e:	54                   	push   %rsp
  401c9f:	49 c7 c0 b0 4e 40 00 	mov    $0x404eb0,%r8
  401ca6:	48 c7 c1 40 4e 40 00 	mov    $0x404e40,%rcx
  401cad:	48 c7 c7 a9 37 40 00 	mov    $0x4037a9,%rdi
  401cb4:	e8 e7 fb ff ff       	callq  4018a0 <__libc_start_main@plt>
  401cb9:	f4                   	hlt    
  401cba:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000401cc0 <deregister_tm_clones>:
  401cc0:	b8 b7 64 60 00       	mov    $0x6064b7,%eax
  401cc5:	55                   	push   %rbp
  401cc6:	48 2d b0 64 60 00    	sub    $0x6064b0,%rax
  401ccc:	48 83 f8 0e          	cmp    $0xe,%rax
  401cd0:	48 89 e5             	mov    %rsp,%rbp
  401cd3:	77 02                	ja     401cd7 <deregister_tm_clones+0x17>
  401cd5:	5d                   	pop    %rbp
  401cd6:	c3                   	retq   
  401cd7:	b8 00 00 00 00       	mov    $0x0,%eax
  401cdc:	48 85 c0             	test   %rax,%rax
  401cdf:	74 f4                	je     401cd5 <deregister_tm_clones+0x15>
  401ce1:	5d                   	pop    %rbp
  401ce2:	bf b0 64 60 00       	mov    $0x6064b0,%edi
  401ce7:	ff e0                	jmpq   *%rax
  401ce9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000401cf0 <register_tm_clones>:
  401cf0:	b8 b0 64 60 00       	mov    $0x6064b0,%eax
  401cf5:	55                   	push   %rbp
  401cf6:	48 2d b0 64 60 00    	sub    $0x6064b0,%rax
  401cfc:	48 c1 f8 03          	sar    $0x3,%rax
  401d00:	48 89 e5             	mov    %rsp,%rbp
  401d03:	48 89 c2             	mov    %rax,%rdx
  401d06:	48 c1 ea 3f          	shr    $0x3f,%rdx
  401d0a:	48 01 d0             	add    %rdx,%rax
  401d0d:	48 d1 f8             	sar    %rax
  401d10:	75 02                	jne    401d14 <register_tm_clones+0x24>
  401d12:	5d                   	pop    %rbp
  401d13:	c3                   	retq   
  401d14:	ba 00 00 00 00       	mov    $0x0,%edx
  401d19:	48 85 d2             	test   %rdx,%rdx
  401d1c:	74 f4                	je     401d12 <register_tm_clones+0x22>
  401d1e:	5d                   	pop    %rbp
  401d1f:	48 89 c6             	mov    %rax,%rsi
  401d22:	bf b0 64 60 00       	mov    $0x6064b0,%edi
  401d27:	ff e2                	jmpq   *%rdx
  401d29:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000401d30 <__do_global_dtors_aux>:
  401d30:	80 3d 89 47 20 00 00 	cmpb   $0x0,0x204789(%rip)        # 6064c0 <completed.6361>
  401d37:	75 11                	jne    401d4a <__do_global_dtors_aux+0x1a>
  401d39:	55                   	push   %rbp
  401d3a:	48 89 e5             	mov    %rsp,%rbp
  401d3d:	e8 7e ff ff ff       	callq  401cc0 <deregister_tm_clones>
  401d42:	5d                   	pop    %rbp
  401d43:	c6 05 76 47 20 00 01 	movb   $0x1,0x204776(%rip)        # 6064c0 <completed.6361>
  401d4a:	f3 c3                	repz retq 
  401d4c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000401d50 <frame_dummy>:
  401d50:	48 83 3d b8 42 20 00 	cmpq   $0x0,0x2042b8(%rip)        # 606010 <__JCR_END__>
  401d57:	00 
  401d58:	74 1e                	je     401d78 <frame_dummy+0x28>
  401d5a:	b8 00 00 00 00       	mov    $0x0,%eax
  401d5f:	48 85 c0             	test   %rax,%rax
  401d62:	74 14                	je     401d78 <frame_dummy+0x28>
  401d64:	55                   	push   %rbp
  401d65:	bf 10 60 60 00       	mov    $0x606010,%edi
  401d6a:	48 89 e5             	mov    %rsp,%rbp
  401d6d:	ff d0                	callq  *%rax
  401d6f:	5d                   	pop    %rbp
  401d70:	e9 7b ff ff ff       	jmpq   401cf0 <register_tm_clones>
  401d75:	0f 1f 00             	nopl   (%rax)
  401d78:	e9 73 ff ff ff       	jmpq   401cf0 <register_tm_clones>

0000000000401d7d <on_close>:
  uint32_t received_length;

} connection;

void on_close(uv_handle_t* h)
{
  401d7d:	55                   	push   %rbp
  401d7e:	48 89 e5             	mov    %rsp,%rbp
  401d81:	48 83 ec 10          	sub    $0x10,%rsp
  401d85:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  /*connection* c = (connection*)h->data;
  fprintf(stderr, "closing %s\n",c->conn_id);*/
  free(h);
  401d89:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401d8d:	48 89 c7             	mov    %rax,%rdi
  401d90:	e8 ab fb ff ff       	callq  401940 <free@plt>
}
  401d95:	c9                   	leaveq 
  401d96:	c3                   	retq   

0000000000401d97 <on_shutdown>:

void on_shutdown(uv_shutdown_t *sht, int status)
{
  401d97:	55                   	push   %rbp
  401d98:	48 89 e5             	mov    %rsp,%rbp
  401d9b:	48 83 ec 10          	sub    $0x10,%rsp
  401d9f:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  401da3:	89 75 f4             	mov    %esi,-0xc(%rbp)
  /*fprintf(stderr, "shutdown\n ");*/
  uv_close(sht->handle, on_close);
  401da6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401daa:	48 8b 40 20          	mov    0x20(%rax),%rax
  401dae:	48 8d 15 c8 ff ff ff 	lea    -0x38(%rip),%rdx        # 401d7d <on_close>
  401db5:	48 89 d6             	mov    %rdx,%rsi
  401db8:	48 89 c7             	mov    %rax,%rdi
  401dbb:	e8 50 fd ff ff       	callq  401b10 <uv_close@plt>
  free(sht);
  401dc0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401dc4:	48 89 c7             	mov    %rax,%rdi
  401dc7:	e8 74 fb ff ff       	callq  401940 <free@plt>
}
  401dcc:	c9                   	leaveq 
  401dcd:	c3                   	retq   

0000000000401dce <quit_connection>:

void quit_connection(connection* c, int ret)
{
  401dce:	55                   	push   %rbp
  401dcf:	48 89 e5             	mov    %rsp,%rbp
  401dd2:	48 83 ec 20          	sub    $0x20,%rsp
  401dd6:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  401dda:	89 75 e4             	mov    %esi,-0x1c(%rbp)
  uv_shutdown_t *sht = malloc(sizeof(uv_shutdown_t));
  401ddd:	bf 30 00 00 00       	mov    $0x30,%edi
  401de2:	e8 99 fa ff ff       	callq  401880 <malloc@plt>
  401de7:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  if (uv_shutdown(sht, c->stream, on_shutdown) == -1)
  401deb:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  401def:	48 8b 88 00 02 00 00 	mov    0x200(%rax),%rcx
  401df6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401dfa:	48 8d 15 96 ff ff ff 	lea    -0x6a(%rip),%rdx        # 401d97 <on_shutdown>
  401e01:	48 89 ce             	mov    %rcx,%rsi
  401e04:	48 89 c7             	mov    %rax,%rdi
  401e07:	e8 94 fc ff ff       	callq  401aa0 <uv_shutdown@plt>
  401e0c:	83 f8 ff             	cmp    $0xffffffff,%eax
  401e0f:	75 48                	jne    401e59 <quit_connection+0x8b>
  {
    #ifdef DOCUMENT_CONNECTIONS
    fprintf(stderr, "[%s] connection already closed by client\n", c->conn_id);
  401e11:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  401e15:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  401e1c:	48 8b 05 fd 43 20 00 	mov    0x2043fd(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  401e23:	48 8b 00             	mov    (%rax),%rax
  401e26:	48 8d 35 a3 30 00 00 	lea    0x30a3(%rip),%rsi        # 404ed0 <_IO_stdin_used+0x10>
  401e2d:	48 89 c7             	mov    %rax,%rdi
  401e30:	b8 00 00 00 00       	mov    $0x0,%eax
  401e35:	e8 c6 fd ff ff       	callq  401c00 <fprintf@plt>
    #endif
    free(sht);
  401e3a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401e3e:	48 89 c7             	mov    %rax,%rdi
  401e41:	e8 fa fa ff ff       	callq  401940 <free@plt>
    free(c->stream);
  401e46:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  401e4a:	48 8b 80 00 02 00 00 	mov    0x200(%rax),%rax
  401e51:	48 89 c7             	mov    %rax,%rdi
  401e54:	e8 e7 fa ff ff       	callq  401940 <free@plt>
  }
  if (c->client_public)
  401e59:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  401e5d:	48 8b 40 10          	mov    0x10(%rax),%rax
  401e61:	48 85 c0             	test   %rax,%rax
  401e64:	74 10                	je     401e76 <quit_connection+0xa8>
    RSA_free(c->client_public);
  401e66:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  401e6a:	48 8b 40 10          	mov    0x10(%rax),%rax
  401e6e:	48 89 c7             	mov    %rax,%rdi
  401e71:	e8 4a fa ff ff       	callq  4018c0 <RSA_free@plt>
  free(c);
  401e76:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  401e7a:	48 89 c7             	mov    %rax,%rdi
  401e7d:	e8 be fa ff ff       	callq  401940 <free@plt>
}
  401e82:	c9                   	leaveq 
  401e83:	c3                   	retq   

0000000000401e84 <on_close_async>:

void on_close_async(uv_handle_t* t)
{
  401e84:	55                   	push   %rbp
  401e85:	48 89 e5             	mov    %rsp,%rbp
  401e88:	48 83 ec 10          	sub    $0x10,%rsp
  401e8c:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  free(t);
  401e90:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401e94:	48 89 c7             	mov    %rax,%rdi
  401e97:	e8 a4 fa ff ff       	callq  401940 <free@plt>
}
  401e9c:	c9                   	leaveq 
  401e9d:	c3                   	retq   

0000000000401e9e <quit_connection_cb>:

void quit_connection_cb(uv_handle_t* h, int status)
{
  401e9e:	55                   	push   %rbp
  401e9f:	48 89 e5             	mov    %rsp,%rbp
  401ea2:	48 83 ec 10          	sub    $0x10,%rsp
  401ea6:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  401eaa:	89 75 f4             	mov    %esi,-0xc(%rbp)
  quit_connection((connection*)h->data, 0);
  401ead:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401eb1:	48 8b 40 08          	mov    0x8(%rax),%rax
  401eb5:	be 00 00 00 00       	mov    $0x0,%esi
  401eba:	48 89 c7             	mov    %rax,%rdi
  401ebd:	e8 0c ff ff ff       	callq  401dce <quit_connection>
  uv_close(h, on_close_async);
  401ec2:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401ec6:	48 8d 15 b7 ff ff ff 	lea    -0x49(%rip),%rdx        # 401e84 <on_close_async>
  401ecd:	48 89 d6             	mov    %rdx,%rsi
  401ed0:	48 89 c7             	mov    %rax,%rdi
  401ed3:	e8 38 fc ff ff       	callq  401b10 <uv_close@plt>
}
  401ed8:	c9                   	leaveq 
  401ed9:	c3                   	retq   

0000000000401eda <quit_connection_async>:

void quit_connection_async(connection* c)
{
  401eda:	55                   	push   %rbp
  401edb:	48 89 e5             	mov    %rsp,%rbp
  401ede:	48 83 ec 20          	sub    $0x20,%rsp
  401ee2:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  uv_async_t* async = (uv_async_t*)malloc(sizeof(uv_async_t));
  401ee6:	bf 60 00 00 00       	mov    $0x60,%edi
  401eeb:	e8 90 f9 ff ff       	callq  401880 <malloc@plt>
  401ef0:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  async->data = c;
  401ef4:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401ef8:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
  401efc:	48 89 50 08          	mov    %rdx,0x8(%rax)
  if (uv_async_init(loop, async, quit_connection_cb) != -1) {
  401f00:	48 8d 05 01 47 20 00 	lea    0x204701(%rip),%rax        # 606608 <loop>
  401f07:	48 8b 00             	mov    (%rax),%rax
  401f0a:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
  401f0e:	48 8d 15 89 ff ff ff 	lea    -0x77(%rip),%rdx        # 401e9e <quit_connection_cb>
  401f15:	48 89 ce             	mov    %rcx,%rsi
  401f18:	48 89 c7             	mov    %rax,%rdi
  401f1b:	e8 40 fb ff ff       	callq  401a60 <uv_async_init@plt>
  401f20:	83 f8 ff             	cmp    $0xffffffff,%eax
  401f23:	74 0c                	je     401f31 <quit_connection_async+0x57>
    uv_async_send(async);
  401f25:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401f29:	48 89 c7             	mov    %rax,%rdi
  401f2c:	e8 df f8 ff ff       	callq  401810 <uv_async_send@plt>
  }
}
  401f31:	c9                   	leaveq 
  401f32:	c3                   	retq   

0000000000401f33 <onexit>:

void onexit()
{
  401f33:	55                   	push   %rbp
  401f34:	48 89 e5             	mov    %rsp,%rbp
  threadpool_destroy(pool, 0);
  401f37:	48 8d 05 82 46 20 00 	lea    0x204682(%rip),%rax        # 6065c0 <pool>
  401f3e:	48 8b 00             	mov    (%rax),%rax
  401f41:	be 00 00 00 00       	mov    $0x0,%esi
  401f46:	48 89 c7             	mov    %rax,%rdi
  401f49:	e8 7d 2a 00 00       	callq  4049cb <threadpool_destroy>
  uv_stop(loop);
  401f4e:	48 8d 05 b3 46 20 00 	lea    0x2046b3(%rip),%rax        # 606608 <loop>
  401f55:	48 8b 00             	mov    (%rax),%rax
  401f58:	48 89 c7             	mov    %rax,%rdi
  401f5b:	e8 90 fb ff ff       	callq  401af0 <uv_stop@plt>
  uv_loop_delete(loop);
  401f60:	48 8d 05 a1 46 20 00 	lea    0x2046a1(%rip),%rax        # 606608 <loop>
  401f67:	48 8b 00             	mov    (%rax),%rax
  401f6a:	48 89 c7             	mov    %rax,%rdi
  401f6d:	e8 5e f9 ff ff       	callq  4018d0 <uv_loop_delete@plt>
  tokshutdown();
  401f72:	b8 00 00 00 00       	mov    $0x0,%eax
  401f77:	e8 bd 26 00 00       	callq  404639 <tokshutdown>
  if (opt_port)
  401f7c:	48 8d 05 8d 46 20 00 	lea    0x20468d(%rip),%rax        # 606610 <opt_port>
  401f83:	48 8b 00             	mov    (%rax),%rax
  401f86:	48 85 c0             	test   %rax,%rax
  401f89:	74 12                	je     401f9d <onexit+0x6a>
    free(opt_port);
  401f8b:	48 8d 05 7e 46 20 00 	lea    0x20467e(%rip),%rax        # 606610 <opt_port>
  401f92:	48 8b 00             	mov    (%rax),%rax
  401f95:	48 89 c7             	mov    %rax,%rdi
  401f98:	e8 a3 f9 ff ff       	callq  401940 <free@plt>
  if (opt_addr)
  401f9d:	48 8d 05 14 46 20 00 	lea    0x204614(%rip),%rax        # 6065b8 <opt_addr>
  401fa4:	48 8b 00             	mov    (%rax),%rax
  401fa7:	48 85 c0             	test   %rax,%rax
  401faa:	74 12                	je     401fbe <onexit+0x8b>
    free(opt_addr);
  401fac:	48 8d 05 05 46 20 00 	lea    0x204605(%rip),%rax        # 6065b8 <opt_addr>
  401fb3:	48 8b 00             	mov    (%rax),%rax
  401fb6:	48 89 c7             	mov    %rax,%rdi
  401fb9:	e8 82 f9 ff ff       	callq  401940 <free@plt>
  if (opt_cert)
  401fbe:	48 8d 05 0b 46 20 00 	lea    0x20460b(%rip),%rax        # 6065d0 <opt_cert>
  401fc5:	48 8b 00             	mov    (%rax),%rax
  401fc8:	48 85 c0             	test   %rax,%rax
  401fcb:	74 12                	je     401fdf <onexit+0xac>
    free(opt_cert);
  401fcd:	48 8d 05 fc 45 20 00 	lea    0x2045fc(%rip),%rax        # 6065d0 <opt_cert>
  401fd4:	48 8b 00             	mov    (%rax),%rax
  401fd7:	48 89 c7             	mov    %rax,%rdi
  401fda:	e8 61 f9 ff ff       	callq  401940 <free@plt>
  if (opt_cert_passphrase)
  401fdf:	48 8d 05 0a 46 20 00 	lea    0x20460a(%rip),%rax        # 6065f0 <opt_cert_passphrase>
  401fe6:	48 8b 00             	mov    (%rax),%rax
  401fe9:	48 85 c0             	test   %rax,%rax
  401fec:	74 12                	je     402000 <onexit+0xcd>
    free(opt_cert_passphrase);
  401fee:	48 8d 05 fb 45 20 00 	lea    0x2045fb(%rip),%rax        # 6065f0 <opt_cert_passphrase>
  401ff5:	48 8b 00             	mov    (%rax),%rax
  401ff8:	48 89 c7             	mov    %rax,%rdi
  401ffb:	e8 40 f9 ff ff       	callq  401940 <free@plt>
  RSA_free(server_private);
  402000:	48 8d 05 19 46 20 00 	lea    0x204619(%rip),%rax        # 606620 <server_private>
  402007:	48 8b 00             	mov    (%rax),%rax
  40200a:	48 89 c7             	mov    %rax,%rdi
  40200d:	e8 ae f8 ff ff       	callq  4018c0 <RSA_free@plt>
  EVP_cleanup();
  402012:	e8 59 f9 ff ff       	callq  401970 <EVP_cleanup@plt>
  ERR_free_strings();
  402017:	e8 a4 f9 ff ff       	callq  4019c0 <ERR_free_strings@plt>
  CRYPTO_cleanup_all_ex_data();
  40201c:	e8 df f7 ff ff       	callq  401800 <CRYPTO_cleanup_all_ex_data@plt>
}
  402021:	5d                   	pop    %rbp
  402022:	c3                   	retq   

0000000000402023 <on_write_syn>:

const char vowels[] = "AEIOU";
const char consonants[] = "BCDFGHJKLMNPQRSTVWXYZ";

void on_write_syn(uv_write_t* req, int status)
{
  402023:	55                   	push   %rbp
  402024:	48 89 e5             	mov    %rsp,%rbp
  402027:	48 83 ec 20          	sub    $0x20,%rsp
  40202b:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  40202f:	89 75 e4             	mov    %esi,-0x1c(%rbp)
  connection* c = (connection*)req->data;
  402032:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  402036:	48 8b 00             	mov    (%rax),%rax
  402039:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  if (status != 0) {
  40203d:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
  402041:	74 39                	je     40207c <on_write_syn+0x59>
    #ifdef DOCUMENT_CONNECTIONS
    fprintf(stderr, "[%s] unable to write to socket (in callback)\n", c->conn_id);
  402043:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402047:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  40204e:	48 8b 05 cb 41 20 00 	mov    0x2041cb(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402055:	48 8b 00             	mov    (%rax),%rax
  402058:	48 8d 35 b9 2e 00 00 	lea    0x2eb9(%rip),%rsi        # 404f18 <consonants+0x18>
  40205f:	48 89 c7             	mov    %rax,%rdi
  402062:	b8 00 00 00 00       	mov    $0x0,%eax
  402067:	e8 94 fb ff ff       	callq  401c00 <fprintf@plt>
    #endif
    c->conn_state = cs_error;
  40206c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402070:	c7 80 08 02 00 00 05 	movl   $0x5,0x208(%rax)
  402077:	00 00 00 
  40207a:	eb 0e                	jmp    40208a <on_write_syn+0x67>
  } else {
    c->conn_state = cs_wait_ack;
  40207c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402080:	c7 80 08 02 00 00 02 	movl   $0x2,0x208(%rax)
  402087:	00 00 00 
  }
  free(req);
  40208a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  40208e:	48 89 c7             	mov    %rax,%rdi
  402091:	e8 aa f8 ff ff       	callq  401940 <free@plt>
}
  402096:	c9                   	leaveq 
  402097:	c3                   	retq   

0000000000402098 <handle_syn>:

void handle_syn(connection* c)
{
  402098:	55                   	push   %rbp
  402099:	48 89 e5             	mov    %rsp,%rbp
  40209c:	53                   	push   %rbx
  40209d:	48 81 ec 88 07 00 00 	sub    $0x788,%rsp
  4020a4:	48 89 bd 78 f8 ff ff 	mov    %rdi,-0x788(%rbp)
  magic_type mgt;
  tokentry* token;
  byte buffer [MAX_MESSAGE_LENGTH], decbuffer [DECRYPTION_BUF_LENGTH], mac [MEGAKI_HASH_BYTES],
       tokstr [MEGAKI_TOKEN_BYTES];
  
  pthread_mutex_lock(&c->buffer_mutex);
  4020ab:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  4020b2:	48 05 18 02 00 00    	add    $0x218,%rax
  4020b8:	48 89 c7             	mov    %rax,%rdi
  4020bb:	e8 00 fb ff ff       	callq  401bc0 <pthread_mutex_lock@plt>
  memcpy(buffer, c->receive_buffer, MAGIC_BYTES);
  4020c0:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  4020c7:	48 8d 88 40 02 00 00 	lea    0x240(%rax),%rcx
  4020ce:	48 8d 85 c0 fb ff ff 	lea    -0x440(%rbp),%rax
  4020d5:	ba 06 00 00 00       	mov    $0x6,%edx
  4020da:	48 89 ce             	mov    %rcx,%rsi
  4020dd:	48 89 c7             	mov    %rax,%rdi
  4020e0:	e8 8b fb ff ff       	callq  401c70 <memcpy@plt>
  pthread_mutex_unlock(&c->buffer_mutex);
  4020e5:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  4020ec:	48 05 18 02 00 00    	add    $0x218,%rax
  4020f2:	48 89 c7             	mov    %rax,%rdi
  4020f5:	e8 66 fb ff ff       	callq  401c60 <pthread_mutex_unlock@plt>
  
  mgt = mgk_check_magic(buffer);
  4020fa:	48 8d 85 c0 fb ff ff 	lea    -0x440(%rbp),%rax
  402101:	48 89 c7             	mov    %rax,%rdi
  402104:	e8 21 1a 00 00       	callq  403b2a <mgk_check_magic>
  402109:	89 45 e4             	mov    %eax,-0x1c(%rbp)
  if (mgt == magic_syn) {
  40210c:	83 7d e4 00          	cmpl   $0x0,-0x1c(%rbp)
  402110:	0f 85 01 0a 00 00    	jne    402b17 <handle_syn+0xa7f>
    int recovered;
    pthread_mutex_lock(&c->buffer_mutex);
  402116:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  40211d:	48 05 18 02 00 00    	add    $0x218,%rax
  402123:	48 89 c7             	mov    %rax,%rdi
  402126:	e8 95 fa ff ff       	callq  401bc0 <pthread_mutex_lock@plt>
    memcpy(buffer, c->receive_buffer + MAGIC_BYTES, SYN_LENGTH - MAGIC_BYTES);
  40212b:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402132:	48 8d 88 46 02 00 00 	lea    0x246(%rax),%rcx
  402139:	48 8d 85 c0 fb ff ff 	lea    -0x440(%rbp),%rax
  402140:	ba 20 02 00 00       	mov    $0x220,%edx
  402145:	48 89 ce             	mov    %rcx,%rsi
  402148:	48 89 c7             	mov    %rax,%rdi
  40214b:	e8 20 fb ff ff       	callq  401c70 <memcpy@plt>
    pthread_mutex_unlock(&c->buffer_mutex);
  402150:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402157:	48 05 18 02 00 00    	add    $0x218,%rax
  40215d:	48 89 c7             	mov    %rax,%rdi
  402160:	e8 fb fa ff ff       	callq  401c60 <pthread_mutex_unlock@plt>
    
    /* decrypt block 1 */
    if ((recovered = RSA_private_decrypt(MEGAKI_RSA_KEYSIZE / 8, buffer + MEGAKI_HASH_BYTES, decbuffer,
  402165:	48 8d 05 b4 44 20 00 	lea    0x2044b4(%rip),%rax        # 606620 <server_private>
  40216c:	48 8b 10             	mov    (%rax),%rdx
  40216f:	48 8d 85 c0 f9 ff ff 	lea    -0x640(%rbp),%rax
  402176:	48 8d 8d c0 fb ff ff 	lea    -0x440(%rbp),%rcx
  40217d:	48 8d 71 20          	lea    0x20(%rcx),%rsi
  402181:	41 b8 04 00 00 00    	mov    $0x4,%r8d
  402187:	48 89 d1             	mov    %rdx,%rcx
  40218a:	48 89 c2             	mov    %rax,%rdx
  40218d:	bf 00 01 00 00       	mov    $0x100,%edi
  402192:	e8 89 f6 ff ff       	callq  401820 <RSA_private_decrypt@plt>
  402197:	89 45 e0             	mov    %eax,-0x20(%rbp)
  40219a:	83 7d e0 ff          	cmpl   $0xffffffff,-0x20(%rbp)
  40219e:	75 6b                	jne    40220b <handle_syn+0x173>
        server_private, RSA_PKCS1_OAEP_PADDING)) == -1) {
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] could not decrypt block 1 of syn ciphertext:\n", c->conn_id);
  4021a0:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  4021a7:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  4021ae:	48 8b 05 6b 40 20 00 	mov    0x20406b(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  4021b5:	48 8b 00             	mov    (%rax),%rax
  4021b8:	48 8d 35 89 2d 00 00 	lea    0x2d89(%rip),%rsi        # 404f48 <consonants+0x48>
  4021bf:	48 89 c7             	mov    %rax,%rdi
  4021c2:	b8 00 00 00 00       	mov    $0x0,%eax
  4021c7:	e8 34 fa ff ff       	callq  401c00 <fprintf@plt>
      ERR_print_errors_fp(stderr);
  4021cc:	48 8b 05 4d 40 20 00 	mov    0x20404d(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  4021d3:	48 8b 00             	mov    (%rax),%rax
  4021d6:	48 89 c7             	mov    %rax,%rdi
  4021d9:	e8 92 f8 ff ff       	callq  401a70 <ERR_print_errors_fp@plt>
      fprintf(stderr, "\n");
  4021de:	48 8b 05 3b 40 20 00 	mov    0x20403b(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  4021e5:	48 8b 00             	mov    (%rax),%rax
  4021e8:	48 89 c6             	mov    %rax,%rsi
  4021eb:	bf 0a 00 00 00       	mov    $0xa,%edi
  4021f0:	e8 3b f7 ff ff       	callq  401930 <fputc@plt>
      #endif

      c->conn_state = cs_error;
  4021f5:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  4021fc:	c7 80 08 02 00 00 05 	movl   $0x5,0x208(%rax)
  402203:	00 00 00 
      return;
  402206:	e9 49 09 00 00       	jmpq   402b54 <handle_syn+0xabc>
    }
    
    /* decrypt block 2 */
    if (RSA_private_decrypt(MEGAKI_RSA_KEYSIZE / 8, buffer + MEGAKI_HASH_BYTES + MEGAKI_RSA_KEYSIZE / 8,
  40220b:	48 8d 05 0e 44 20 00 	lea    0x20440e(%rip),%rax        # 606620 <server_private>
  402212:	48 8b 00             	mov    (%rax),%rax
  402215:	8b 55 e0             	mov    -0x20(%rbp),%edx
  402218:	48 63 d2             	movslq %edx,%rdx
  40221b:	48 8d 8d c0 f9 ff ff 	lea    -0x640(%rbp),%rcx
  402222:	48 01 ca             	add    %rcx,%rdx
  402225:	48 8d 8d c0 fb ff ff 	lea    -0x440(%rbp),%rcx
  40222c:	48 8d b1 20 01 00 00 	lea    0x120(%rcx),%rsi
  402233:	41 b8 04 00 00 00    	mov    $0x4,%r8d
  402239:	48 89 c1             	mov    %rax,%rcx
  40223c:	bf 00 01 00 00       	mov    $0x100,%edi
  402241:	e8 da f5 ff ff       	callq  401820 <RSA_private_decrypt@plt>
  402246:	83 f8 ff             	cmp    $0xffffffff,%eax
  402249:	75 6b                	jne    4022b6 <handle_syn+0x21e>
        decbuffer + recovered, server_private, RSA_PKCS1_OAEP_PADDING) == -1) {
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] could not decrypt block 2 of syn ciphertext:\n\t", c->conn_id);
  40224b:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402252:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  402259:	48 8b 05 c0 3f 20 00 	mov    0x203fc0(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402260:	48 8b 00             	mov    (%rax),%rax
  402263:	48 8d 35 16 2d 00 00 	lea    0x2d16(%rip),%rsi        # 404f80 <consonants+0x80>
  40226a:	48 89 c7             	mov    %rax,%rdi
  40226d:	b8 00 00 00 00       	mov    $0x0,%eax
  402272:	e8 89 f9 ff ff       	callq  401c00 <fprintf@plt>
      ERR_print_errors_fp(stderr);
  402277:	48 8b 05 a2 3f 20 00 	mov    0x203fa2(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  40227e:	48 8b 00             	mov    (%rax),%rax
  402281:	48 89 c7             	mov    %rax,%rdi
  402284:	e8 e7 f7 ff ff       	callq  401a70 <ERR_print_errors_fp@plt>
      fprintf(stderr, "\n");
  402289:	48 8b 05 90 3f 20 00 	mov    0x203f90(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402290:	48 8b 00             	mov    (%rax),%rax
  402293:	48 89 c6             	mov    %rax,%rsi
  402296:	bf 0a 00 00 00       	mov    $0xa,%edi
  40229b:	e8 90 f6 ff ff       	callq  401930 <fputc@plt>
      #endif
      c->conn_state = cs_error;
  4022a0:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  4022a7:	c7 80 08 02 00 00 05 	movl   $0x5,0x208(%rax)
  4022ae:	00 00 00 
      return;
  4022b1:	e9 9e 08 00 00       	jmpq   402b54 <handle_syn+0xabc>
    }
    
    /* decode block 2 */
    int i;
    for (i = 0; i < recovered; ++i)
  4022b6:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)
  4022bd:	eb 38                	jmp    4022f7 <handle_syn+0x25f>
      decbuffer[i + recovered] ^= decbuffer[i];
  4022bf:	8b 45 e0             	mov    -0x20(%rbp),%eax
  4022c2:	8b 55 ec             	mov    -0x14(%rbp),%edx
  4022c5:	8d 0c 02             	lea    (%rdx,%rax,1),%ecx
  4022c8:	8b 45 e0             	mov    -0x20(%rbp),%eax
  4022cb:	8b 55 ec             	mov    -0x14(%rbp),%edx
  4022ce:	01 d0                	add    %edx,%eax
  4022d0:	48 98                	cltq   
  4022d2:	0f b6 94 05 c0 f9 ff 	movzbl -0x640(%rbp,%rax,1),%edx
  4022d9:	ff 
  4022da:	8b 45 ec             	mov    -0x14(%rbp),%eax
  4022dd:	48 98                	cltq   
  4022df:	0f b6 84 05 c0 f9 ff 	movzbl -0x640(%rbp,%rax,1),%eax
  4022e6:	ff 
  4022e7:	31 c2                	xor    %eax,%edx
  4022e9:	48 63 c1             	movslq %ecx,%rax
  4022ec:	88 94 05 c0 f9 ff ff 	mov    %dl,-0x640(%rbp,%rax,1)
      return;
    }
    
    /* decode block 2 */
    int i;
    for (i = 0; i < recovered; ++i)
  4022f3:	83 45 ec 01          	addl   $0x1,-0x14(%rbp)
  4022f7:	8b 45 ec             	mov    -0x14(%rbp),%eax
  4022fa:	3b 45 e0             	cmp    -0x20(%rbp),%eax
  4022fd:	7c c0                	jl     4022bf <handle_syn+0x227>
      decbuffer[i + recovered] ^= decbuffer[i];
    
    #ifdef DOCUMENT_CONNECTIONS
    fprintf(stderr, "[%s] syn plaintext:\n", c->conn_id);
  4022ff:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402306:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  40230d:	48 8b 05 0c 3f 20 00 	mov    0x203f0c(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402314:	48 8b 00             	mov    (%rax),%rax
  402317:	48 8d 35 96 2c 00 00 	lea    0x2c96(%rip),%rsi        # 404fb4 <consonants+0xb4>
  40231e:	48 89 c7             	mov    %rax,%rdi
  402321:	b8 00 00 00 00       	mov    $0x0,%eax
  402326:	e8 d5 f8 ff ff       	callq  401c00 <fprintf@plt>
    hexdump(stderr, "SYNCLRT", decbuffer, MEGAKI_VERSION_BYTES + 4 + MEGAKI_RSA_KEYSIZE / 8);
  40232b:	48 8b 05 ee 3e 20 00 	mov    0x203eee(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402332:	48 8b 00             	mov    (%rax),%rax
  402335:	48 8d 95 c0 f9 ff ff 	lea    -0x640(%rbp),%rdx
  40233c:	b9 06 01 00 00       	mov    $0x106,%ecx
  402341:	48 8d 35 81 2c 00 00 	lea    0x2c81(%rip),%rsi        # 404fc9 <consonants+0xc9>
  402348:	48 89 c7             	mov    %rax,%rdi
  40234b:	e8 5a 29 00 00       	callq  404caa <hexdump>
    printf("\n");
  402350:	bf 0a 00 00 00       	mov    $0xa,%edi
  402355:	e8 16 f5 ff ff       	callq  401870 <putchar@plt>
    #endif
    
    /* compute MAC and check */
    SHA256(decbuffer, MEGAKI_RSA_KEYSIZE / 8 + 4 + MEGAKI_VERSION_BYTES, mac);
  40235a:	48 8d 95 a0 f9 ff ff 	lea    -0x660(%rbp),%rdx
  402361:	48 8d 85 c0 f9 ff ff 	lea    -0x640(%rbp),%rax
  402368:	be 06 01 00 00       	mov    $0x106,%esi
  40236d:	48 89 c7             	mov    %rax,%rdi
  402370:	e8 cb f6 ff ff       	callq  401a40 <SHA256@plt>
    if (!mgk_memeql(mac, buffer, MEGAKI_HASH_BYTES)) {
  402375:	48 8d 8d c0 fb ff ff 	lea    -0x440(%rbp),%rcx
  40237c:	48 8d 85 a0 f9 ff ff 	lea    -0x660(%rbp),%rax
  402383:	ba 20 00 00 00       	mov    $0x20,%edx
  402388:	48 89 ce             	mov    %rcx,%rsi
  40238b:	48 89 c7             	mov    %rax,%rdi
  40238e:	e8 8b 16 00 00       	callq  403a1e <mgk_memeql>
  402393:	85 c0                	test   %eax,%eax
  402395:	75 42                	jne    4023d9 <handle_syn+0x341>
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] hash mismatch in syn packet\n", c->conn_id);
  402397:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  40239e:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  4023a5:	48 8b 05 74 3e 20 00 	mov    0x203e74(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  4023ac:	48 8b 00             	mov    (%rax),%rax
  4023af:	48 8d 35 22 2c 00 00 	lea    0x2c22(%rip),%rsi        # 404fd8 <consonants+0xd8>
  4023b6:	48 89 c7             	mov    %rax,%rdi
  4023b9:	b8 00 00 00 00       	mov    $0x0,%eax
  4023be:	e8 3d f8 ff ff       	callq  401c00 <fprintf@plt>
      #endif
      c->conn_state = cs_error;
  4023c3:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  4023ca:	c7 80 08 02 00 00 05 	movl   $0x5,0x208(%rax)
  4023d1:	00 00 00 
      return;
  4023d4:	e9 7b 07 00 00       	jmpq   402b54 <handle_syn+0xabc>
    }
    
    /* fill client public key data */
    c->client_public = RSA_new();
  4023d9:	e8 d2 f4 ff ff       	callq  4018b0 <RSA_new@plt>
  4023de:	48 8b 95 78 f8 ff ff 	mov    -0x788(%rbp),%rdx
  4023e5:	48 89 42 10          	mov    %rax,0x10(%rdx)
    if (c->client_public == NULL) {
  4023e9:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  4023f0:	48 8b 40 10          	mov    0x10(%rax),%rax
  4023f4:	48 85 c0             	test   %rax,%rax
  4023f7:	75 42                	jne    40243b <handle_syn+0x3a3>
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] UNEXPECTED: RSA alloc fails\n", c->conn_id);
  4023f9:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402400:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  402407:	48 8b 05 12 3e 20 00 	mov    0x203e12(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  40240e:	48 8b 00             	mov    (%rax),%rax
  402411:	48 8d 35 e8 2b 00 00 	lea    0x2be8(%rip),%rsi        # 405000 <consonants+0x100>
  402418:	48 89 c7             	mov    %rax,%rdi
  40241b:	b8 00 00 00 00       	mov    $0x0,%eax
  402420:	e8 db f7 ff ff       	callq  401c00 <fprintf@plt>
      #endif
      c->conn_state = cs_error;
  402425:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  40242c:	c7 80 08 02 00 00 05 	movl   $0x5,0x208(%rax)
  402433:	00 00 00 
      return;
  402436:	e9 19 07 00 00       	jmpq   402b54 <handle_syn+0xabc>
    }
      
    if (!(c->client_public->n = BN_bin2bn(decbuffer, MEGAKI_RSA_KEYSIZE / 8, c->client_public->n))) {
  40243b:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402442:	48 8b 58 10          	mov    0x10(%rax),%rbx
  402446:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  40244d:	48 8b 40 10          	mov    0x10(%rax),%rax
  402451:	48 8b 50 20          	mov    0x20(%rax),%rdx
  402455:	48 8d 85 c0 f9 ff ff 	lea    -0x640(%rbp),%rax
  40245c:	be 00 01 00 00       	mov    $0x100,%esi
  402461:	48 89 c7             	mov    %rax,%rdi
  402464:	e8 e7 f7 ff ff       	callq  401c50 <BN_bin2bn@plt>
  402469:	48 89 43 20          	mov    %rax,0x20(%rbx)
  40246d:	48 8b 43 20          	mov    0x20(%rbx),%rax
  402471:	48 85 c0             	test   %rax,%rax
  402474:	75 42                	jne    4024b8 <handle_syn+0x420>
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] UNEXPECTED: BN_bin2bn fails on modulus\n", c->conn_id);
  402476:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  40247d:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  402484:	48 8b 05 95 3d 20 00 	mov    0x203d95(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  40248b:	48 8b 00             	mov    (%rax),%rax
  40248e:	48 8d 35 93 2b 00 00 	lea    0x2b93(%rip),%rsi        # 405028 <consonants+0x128>
  402495:	48 89 c7             	mov    %rax,%rdi
  402498:	b8 00 00 00 00       	mov    $0x0,%eax
  40249d:	e8 5e f7 ff ff       	callq  401c00 <fprintf@plt>
      #endif
      c->conn_state = cs_error;
  4024a2:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  4024a9:	c7 80 08 02 00 00 05 	movl   $0x5,0x208(%rax)
  4024b0:	00 00 00 
      return;
  4024b3:	e9 9c 06 00 00       	jmpq   402b54 <handle_syn+0xabc>
    }
      
    if (!(c->client_public->e = BN_bin2bn(decbuffer + MEGAKI_RSA_KEYSIZE / 8, 4, c->client_public->e))) {
  4024b8:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  4024bf:	48 8b 58 10          	mov    0x10(%rax),%rbx
  4024c3:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  4024ca:	48 8b 40 10          	mov    0x10(%rax),%rax
  4024ce:	48 8b 40 28          	mov    0x28(%rax),%rax
  4024d2:	48 8d 95 c0 f9 ff ff 	lea    -0x640(%rbp),%rdx
  4024d9:	48 8d 8a 00 01 00 00 	lea    0x100(%rdx),%rcx
  4024e0:	48 89 c2             	mov    %rax,%rdx
  4024e3:	be 04 00 00 00       	mov    $0x4,%esi
  4024e8:	48 89 cf             	mov    %rcx,%rdi
  4024eb:	e8 60 f7 ff ff       	callq  401c50 <BN_bin2bn@plt>
  4024f0:	48 89 43 28          	mov    %rax,0x28(%rbx)
  4024f4:	48 8b 43 28          	mov    0x28(%rbx),%rax
  4024f8:	48 85 c0             	test   %rax,%rax
  4024fb:	75 42                	jne    40253f <handle_syn+0x4a7>
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] UNEXPECTED: BN_bin2bn fails on exponent\n", c->conn_id);
  4024fd:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402504:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  40250b:	48 8b 05 0e 3d 20 00 	mov    0x203d0e(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402512:	48 8b 00             	mov    (%rax),%rax
  402515:	48 8d 35 3c 2b 00 00 	lea    0x2b3c(%rip),%rsi        # 405058 <consonants+0x158>
  40251c:	48 89 c7             	mov    %rax,%rdi
  40251f:	b8 00 00 00 00       	mov    $0x0,%eax
  402524:	e8 d7 f6 ff ff       	callq  401c00 <fprintf@plt>
      #endif
      c->conn_state = cs_error;
  402529:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402530:	c7 80 08 02 00 00 05 	movl   $0x5,0x208(%rax)
  402537:	00 00 00 
      return;
  40253a:	e9 15 06 00 00       	jmpq   402b54 <handle_syn+0xabc>
    }
    
    #ifdef DOCUMENT_CONNECTIONS
    byte debugbuf[MEGAKI_RSA_KEYSIZE / 8];
    BN_bn2bin(c->client_public->n, debugbuf);
  40253f:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402546:	48 8b 40 10          	mov    0x10(%rax),%rax
  40254a:	48 8b 40 20          	mov    0x20(%rax),%rax
  40254e:	48 8d 95 80 f8 ff ff 	lea    -0x780(%rbp),%rdx
  402555:	48 89 d6             	mov    %rdx,%rsi
  402558:	48 89 c7             	mov    %rax,%rdi
  40255b:	e8 70 f4 ff ff       	callq  4019d0 <BN_bn2bin@plt>
    fprintf(stderr, "[%s] retrieved client modulus/exponent:\n", c->conn_id);
  402560:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402567:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  40256e:	48 8b 05 ab 3c 20 00 	mov    0x203cab(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402575:	48 8b 00             	mov    (%rax),%rax
  402578:	48 8d 35 09 2b 00 00 	lea    0x2b09(%rip),%rsi        # 405088 <consonants+0x188>
  40257f:	48 89 c7             	mov    %rax,%rdi
  402582:	b8 00 00 00 00       	mov    $0x0,%eax
  402587:	e8 74 f6 ff ff       	callq  401c00 <fprintf@plt>
    hexdump(stderr, "CLNTMOD", debugbuf, BN_num_bytes(c->client_public->n));
  40258c:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402593:	48 8b 40 10          	mov    0x10(%rax),%rax
  402597:	48 8b 40 20          	mov    0x20(%rax),%rax
  40259b:	48 89 c7             	mov    %rax,%rdi
  40259e:	e8 cd f5 ff ff       	callq  401b70 <BN_num_bits@plt>
  4025a3:	83 c0 07             	add    $0x7,%eax
  4025a6:	8d 50 07             	lea    0x7(%rax),%edx
  4025a9:	85 c0                	test   %eax,%eax
  4025ab:	0f 48 c2             	cmovs  %edx,%eax
  4025ae:	c1 f8 03             	sar    $0x3,%eax
  4025b1:	89 c1                	mov    %eax,%ecx
  4025b3:	48 8b 05 66 3c 20 00 	mov    0x203c66(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  4025ba:	48 8b 00             	mov    (%rax),%rax
  4025bd:	48 8d 95 80 f8 ff ff 	lea    -0x780(%rbp),%rdx
  4025c4:	48 8d 35 e6 2a 00 00 	lea    0x2ae6(%rip),%rsi        # 4050b1 <consonants+0x1b1>
  4025cb:	48 89 c7             	mov    %rax,%rdi
  4025ce:	e8 d7 26 00 00       	callq  404caa <hexdump>
    BN_bn2bin(c->client_public->e, debugbuf);
  4025d3:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  4025da:	48 8b 40 10          	mov    0x10(%rax),%rax
  4025de:	48 8b 40 28          	mov    0x28(%rax),%rax
  4025e2:	48 8d 95 80 f8 ff ff 	lea    -0x780(%rbp),%rdx
  4025e9:	48 89 d6             	mov    %rdx,%rsi
  4025ec:	48 89 c7             	mov    %rax,%rdi
  4025ef:	e8 dc f3 ff ff       	callq  4019d0 <BN_bn2bin@plt>
    hexdump(stderr, "CLNTEXP", debugbuf, BN_num_bytes(c->client_public->e));
  4025f4:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  4025fb:	48 8b 40 10          	mov    0x10(%rax),%rax
  4025ff:	48 8b 40 28          	mov    0x28(%rax),%rax
  402603:	48 89 c7             	mov    %rax,%rdi
  402606:	e8 65 f5 ff ff       	callq  401b70 <BN_num_bits@plt>
  40260b:	83 c0 07             	add    $0x7,%eax
  40260e:	8d 50 07             	lea    0x7(%rax),%edx
  402611:	85 c0                	test   %eax,%eax
  402613:	0f 48 c2             	cmovs  %edx,%eax
  402616:	c1 f8 03             	sar    $0x3,%eax
  402619:	89 c1                	mov    %eax,%ecx
  40261b:	48 8b 05 fe 3b 20 00 	mov    0x203bfe(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402622:	48 8b 00             	mov    (%rax),%rax
  402625:	48 8d 95 80 f8 ff ff 	lea    -0x780(%rbp),%rdx
  40262c:	48 8d 35 86 2a 00 00 	lea    0x2a86(%rip),%rsi        # 4050b9 <consonants+0x1b9>
  402633:	48 89 c7             	mov    %rax,%rdi
  402636:	e8 6f 26 00 00       	callq  404caa <hexdump>
    fprintf(stderr, "\n");
  40263b:	48 8b 05 de 3b 20 00 	mov    0x203bde(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402642:	48 8b 00             	mov    (%rax),%rax
  402645:	48 89 c6             	mov    %rax,%rsi
  402648:	bf 0a 00 00 00       	mov    $0xa,%edi
  40264d:	e8 de f2 ff ff       	callq  401930 <fputc@plt>
    #endif
    
    int badproto = 0, internalerror = 0;
  402652:	c7 45 e8 00 00 00 00 	movl   $0x0,-0x18(%rbp)
  402659:	c7 45 dc 00 00 00 00 	movl   $0x0,-0x24(%rbp)
    const int off = MEGAKI_RSA_KEYSIZE / 8 + 4;
  402660:	c7 45 d8 04 01 00 00 	movl   $0x104,-0x28(%rbp)
    /* check the version first */
    if (memcmp(MEGAKI_VERSION, decbuffer + off, MEGAKI_VERSION_BYTES) != 0) {
  402667:	8b 45 d8             	mov    -0x28(%rbp),%eax
  40266a:	48 98                	cltq   
  40266c:	48 8d 95 c0 f9 ff ff 	lea    -0x640(%rbp),%rdx
  402673:	48 01 d0             	add    %rdx,%rax
  402676:	ba 02 00 00 00       	mov    $0x2,%edx
  40267b:	48 89 c6             	mov    %rax,%rsi
  40267e:	48 8d 05 fb 2e 00 00 	lea    0x2efb(%rip),%rax        # 405580 <MEGAKI_VERSION>
  402685:	48 89 c7             	mov    %rax,%rdi
  402688:	e8 b3 f4 ff ff       	callq  401b40 <memcmp@plt>
  40268d:	85 c0                	test   %eax,%eax
  40268f:	0f 84 80 00 00 00    	je     402715 <handle_syn+0x67d>
      /* we're not running the same version of the protocol---sorry pal */
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] version mismatch, client uses %02X%02X and we're on %02X%02X\n", c->conn_id,
        decbuffer[off], decbuffer[off + 1],
        MEGAKI_VERSION[0], MEGAKI_VERSION[1]);
  402695:	48 8d 05 e4 2e 00 00 	lea    0x2ee4(%rip),%rax        # 405580 <MEGAKI_VERSION>
  40269c:	0f b6 40 01          	movzbl 0x1(%rax),%eax
    const int off = MEGAKI_RSA_KEYSIZE / 8 + 4;
    /* check the version first */
    if (memcmp(MEGAKI_VERSION, decbuffer + off, MEGAKI_VERSION_BYTES) != 0) {
      /* we're not running the same version of the protocol---sorry pal */
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] version mismatch, client uses %02X%02X and we're on %02X%02X\n", c->conn_id,
  4026a0:	0f b6 c8             	movzbl %al,%ecx
        decbuffer[off], decbuffer[off + 1],
        MEGAKI_VERSION[0], MEGAKI_VERSION[1]);
  4026a3:	48 8d 05 d6 2e 00 00 	lea    0x2ed6(%rip),%rax        # 405580 <MEGAKI_VERSION>
  4026aa:	0f b6 00             	movzbl (%rax),%eax
    const int off = MEGAKI_RSA_KEYSIZE / 8 + 4;
    /* check the version first */
    if (memcmp(MEGAKI_VERSION, decbuffer + off, MEGAKI_VERSION_BYTES) != 0) {
      /* we're not running the same version of the protocol---sorry pal */
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] version mismatch, client uses %02X%02X and we're on %02X%02X\n", c->conn_id,
  4026ad:	44 0f b6 c0          	movzbl %al,%r8d
        decbuffer[off], decbuffer[off + 1],
  4026b1:	8b 45 d8             	mov    -0x28(%rbp),%eax
  4026b4:	83 c0 01             	add    $0x1,%eax
  4026b7:	48 98                	cltq   
  4026b9:	0f b6 84 05 c0 f9 ff 	movzbl -0x640(%rbp,%rax,1),%eax
  4026c0:	ff 
    const int off = MEGAKI_RSA_KEYSIZE / 8 + 4;
    /* check the version first */
    if (memcmp(MEGAKI_VERSION, decbuffer + off, MEGAKI_VERSION_BYTES) != 0) {
      /* we're not running the same version of the protocol---sorry pal */
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] version mismatch, client uses %02X%02X and we're on %02X%02X\n", c->conn_id,
  4026c1:	0f b6 f8             	movzbl %al,%edi
        decbuffer[off], decbuffer[off + 1],
  4026c4:	8b 45 d8             	mov    -0x28(%rbp),%eax
  4026c7:	48 98                	cltq   
  4026c9:	0f b6 84 05 c0 f9 ff 	movzbl -0x640(%rbp,%rax,1),%eax
  4026d0:	ff 
    const int off = MEGAKI_RSA_KEYSIZE / 8 + 4;
    /* check the version first */
    if (memcmp(MEGAKI_VERSION, decbuffer + off, MEGAKI_VERSION_BYTES) != 0) {
      /* we're not running the same version of the protocol---sorry pal */
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] version mismatch, client uses %02X%02X and we're on %02X%02X\n", c->conn_id,
  4026d1:	0f b6 d0             	movzbl %al,%edx
  4026d4:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  4026db:	48 8d b0 0c 02 00 00 	lea    0x20c(%rax),%rsi
  4026e2:	48 8b 05 37 3b 20 00 	mov    0x203b37(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  4026e9:	48 8b 00             	mov    (%rax),%rax
  4026ec:	89 0c 24             	mov    %ecx,(%rsp)
  4026ef:	45 89 c1             	mov    %r8d,%r9d
  4026f2:	41 89 f8             	mov    %edi,%r8d
  4026f5:	89 d1                	mov    %edx,%ecx
  4026f7:	48 89 f2             	mov    %rsi,%rdx
  4026fa:	48 8d 35 c7 29 00 00 	lea    0x29c7(%rip),%rsi        # 4050c8 <consonants+0x1c8>
  402701:	48 89 c7             	mov    %rax,%rdi
  402704:	b8 00 00 00 00       	mov    $0x0,%eax
  402709:	e8 f2 f4 ff ff       	callq  401c00 <fprintf@plt>
        decbuffer[off], decbuffer[off + 1],
        MEGAKI_VERSION[0], MEGAKI_VERSION[1]);
      #endif
      badproto = 1;
  40270e:	c7 45 e8 01 00 00 00 	movl   $0x1,-0x18(%rbp)
    }
    
    /* so, the client has taken care to do an RSA pad-encrypt operation
     * and to compute an SHA-256 hash. maybe she is worth our time...? */
    mgk_fill_magic(buffer, magic_synack);
  402715:	48 8d 85 c0 fb ff ff 	lea    -0x440(%rbp),%rax
  40271c:	be 01 00 00 00       	mov    $0x1,%esi
  402721:	48 89 c7             	mov    %rax,%rdi
  402724:	e8 4a 13 00 00       	callq  403a73 <mgk_fill_magic>
    if (badproto) {
  402729:	83 7d e8 00          	cmpl   $0x0,-0x18(%rbp)
  40272d:	74 51                	je     402780 <handle_syn+0x6e8>
      memcpy(decbuffer, MEGAKI_ERROR_TOKEN, MEGAKI_TOKEN_BYTES);
  40272f:	48 8d 05 5a 2e 00 00 	lea    0x2e5a(%rip),%rax        # 405590 <MEGAKI_ERROR_TOKEN>
  402736:	48 8b 50 08          	mov    0x8(%rax),%rdx
  40273a:	48 8b 00             	mov    (%rax),%rax
  40273d:	48 89 85 c0 f9 ff ff 	mov    %rax,-0x640(%rbp)
  402744:	48 89 95 c8 f9 ff ff 	mov    %rdx,-0x638(%rbp)
      memcpy(decbuffer + MEGAKI_TOKEN_BYTES, MEGAKI_INCOMPATIBLE_VERSIONS_ERROR, MEGAKI_ERROR_CODE_BYTES);
  40274b:	48 8d 85 c0 f9 ff ff 	lea    -0x640(%rbp),%rax
  402752:	48 83 c0 10          	add    $0x10,%rax
  402756:	48 8d 15 43 2e 00 00 	lea    0x2e43(%rip),%rdx        # 4055a0 <MEGAKI_INCOMPATIBLE_VERSIONS_ERROR>
  40275d:	48 8b 0a             	mov    (%rdx),%rcx
  402760:	48 89 08             	mov    %rcx,(%rax)
  402763:	48 8b 4a 08          	mov    0x8(%rdx),%rcx
  402767:	48 89 48 08          	mov    %rcx,0x8(%rax)
  40276b:	48 8b 4a 10          	mov    0x10(%rdx),%rcx
  40276f:	48 89 48 10          	mov    %rcx,0x10(%rax)
  402773:	48 8b 52 18          	mov    0x18(%rdx),%rdx
  402777:	48 89 50 18          	mov    %rdx,0x18(%rax)
  40277b:	e9 f2 02 00 00       	jmpq   402a72 <handle_syn+0x9da>
    } else {
      if (!RAND_pseudo_bytes(tokstr, MEGAKI_TOKEN_BYTES)) {
  402780:	48 8d 85 90 f9 ff ff 	lea    -0x670(%rbp),%rax
  402787:	be 10 00 00 00       	mov    $0x10,%esi
  40278c:	48 89 c7             	mov    %rax,%rdi
  40278f:	e8 4c f0 ff ff       	callq  4017e0 <RAND_pseudo_bytes@plt>
  402794:	85 c0                	test   %eax,%eax
  402796:	75 42                	jne    4027da <handle_syn+0x742>
        #ifdef DOCUMENT_CONNECTIONS
        fprintf(stderr, "[%s] UNEXPECTED: could not generate bytes for token\n", c->conn_id);
  402798:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  40279f:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  4027a6:	48 8b 05 73 3a 20 00 	mov    0x203a73(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  4027ad:	48 8b 00             	mov    (%rax),%rax
  4027b0:	48 8d 35 59 29 00 00 	lea    0x2959(%rip),%rsi        # 405110 <consonants+0x210>
  4027b7:	48 89 c7             	mov    %rax,%rdi
  4027ba:	b8 00 00 00 00       	mov    $0x0,%eax
  4027bf:	e8 3c f4 ff ff       	callq  401c00 <fprintf@plt>
        #endif
        c->conn_state = cs_error;
  4027c4:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  4027cb:	c7 80 08 02 00 00 05 	movl   $0x5,0x208(%rax)
  4027d2:	00 00 00 
        return;
  4027d5:	e9 7a 03 00 00       	jmpq   402b54 <handle_syn+0xabc>
      }
      
      token = tok_create(tokstr);
  4027da:	48 8d 85 90 f9 ff ff 	lea    -0x670(%rbp),%rax
  4027e1:	48 89 c7             	mov    %rax,%rdi
  4027e4:	e8 a3 1b 00 00       	callq  40438c <tok_create>
  4027e9:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
      if (!token) {
  4027ed:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
  4027f2:	0f 85 84 00 00 00    	jne    40287c <handle_syn+0x7e4>
        memcpy(decbuffer, MEGAKI_ERROR_TOKEN, MEGAKI_TOKEN_BYTES);    
  4027f8:	48 8d 05 91 2d 00 00 	lea    0x2d91(%rip),%rax        # 405590 <MEGAKI_ERROR_TOKEN>
  4027ff:	48 8b 50 08          	mov    0x8(%rax),%rdx
  402803:	48 8b 00             	mov    (%rax),%rax
  402806:	48 89 85 c0 f9 ff ff 	mov    %rax,-0x640(%rbp)
  40280d:	48 89 95 c8 f9 ff ff 	mov    %rdx,-0x638(%rbp)
        memcpy(decbuffer + MEGAKI_TOKEN_BYTES, MEGAKI_SERVICE_UNAVAILABLE_ERROR, MEGAKI_ERROR_CODE_BYTES);    
  402814:	48 8d 85 c0 f9 ff ff 	lea    -0x640(%rbp),%rax
  40281b:	48 83 c0 10          	add    $0x10,%rax
  40281f:	48 8d 15 9a 2d 00 00 	lea    0x2d9a(%rip),%rdx        # 4055c0 <MEGAKI_SERVICE_UNAVAILABLE_ERROR>
  402826:	48 8b 0a             	mov    (%rdx),%rcx
  402829:	48 89 08             	mov    %rcx,(%rax)
  40282c:	48 8b 4a 08          	mov    0x8(%rdx),%rcx
  402830:	48 89 48 08          	mov    %rcx,0x8(%rax)
  402834:	48 8b 4a 10          	mov    0x10(%rdx),%rcx
  402838:	48 89 48 10          	mov    %rcx,0x10(%rax)
  40283c:	48 8b 52 18          	mov    0x18(%rdx),%rdx
  402840:	48 89 50 18          	mov    %rdx,0x18(%rax)
        
        #ifdef DOCUMENT_CONNECTIONS
        fprintf(stderr, "[%s] UNEXPECTED: tok_create fails\n", c->conn_id);
  402844:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  40284b:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  402852:	48 8b 05 c7 39 20 00 	mov    0x2039c7(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402859:	48 8b 00             	mov    (%rax),%rax
  40285c:	48 8d 35 e5 28 00 00 	lea    0x28e5(%rip),%rsi        # 405148 <consonants+0x248>
  402863:	48 89 c7             	mov    %rax,%rdi
  402866:	b8 00 00 00 00       	mov    $0x0,%eax
  40286b:	e8 90 f3 ff ff       	callq  401c00 <fprintf@plt>
        #endif
        internalerror = 1;
  402870:	c7 45 dc 01 00 00 00 	movl   $0x1,-0x24(%rbp)
  402877:	e9 f6 01 00 00       	jmpq   402a72 <handle_syn+0x9da>
      } else {
        #ifdef DOCUMENT_CONNECTIONS
        fprintf(stderr, "[%s] generated token:\n", c->conn_id);
  40287c:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402883:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  40288a:	48 8b 05 8f 39 20 00 	mov    0x20398f(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402891:	48 8b 00             	mov    (%rax),%rax
  402894:	48 8d 35 d0 28 00 00 	lea    0x28d0(%rip),%rsi        # 40516b <consonants+0x26b>
  40289b:	48 89 c7             	mov    %rax,%rdi
  40289e:	b8 00 00 00 00       	mov    $0x0,%eax
  4028a3:	e8 58 f3 ff ff       	callq  401c00 <fprintf@plt>
        hexdump(stderr, "SSTOKEN", tokstr, MEGAKI_TOKEN_BYTES);
  4028a8:	48 8b 05 71 39 20 00 	mov    0x203971(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  4028af:	48 8b 00             	mov    (%rax),%rax
  4028b2:	48 8d 95 90 f9 ff ff 	lea    -0x670(%rbp),%rdx
  4028b9:	b9 10 00 00 00       	mov    $0x10,%ecx
  4028be:	48 8d 35 bd 28 00 00 	lea    0x28bd(%rip),%rsi        # 405182 <consonants+0x282>
  4028c5:	48 89 c7             	mov    %rax,%rdi
  4028c8:	e8 dd 23 00 00       	callq  404caa <hexdump>
        #endif
        memcpy(decbuffer, token->token, MEGAKI_TOKEN_BYTES);
  4028cd:	48 8b 4d d0          	mov    -0x30(%rbp),%rcx
  4028d1:	48 8d 85 c0 f9 ff ff 	lea    -0x640(%rbp),%rax
  4028d8:	ba 10 00 00 00       	mov    $0x10,%edx
  4028dd:	48 89 ce             	mov    %rcx,%rsi
  4028e0:	48 89 c7             	mov    %rax,%rdi
  4028e3:	e8 88 f3 ff ff       	callq  401c70 <memcpy@plt>
        memcpy(buffer + MAGIC_BYTES + MEGAKI_HASH_BYTES, token->token, MEGAKI_TOKEN_BYTES);
  4028e8:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  4028ec:	48 8d 95 c0 fb ff ff 	lea    -0x440(%rbp),%rdx
  4028f3:	48 8d 4a 26          	lea    0x26(%rdx),%rcx
  4028f7:	ba 10 00 00 00       	mov    $0x10,%edx
  4028fc:	48 89 c6             	mov    %rax,%rsi
  4028ff:	48 89 cf             	mov    %rcx,%rdi
  402902:	e8 69 f3 ff ff       	callq  401c70 <memcpy@plt>
        
        memcpy(c->token, tokstr, MEGAKI_TOKEN_BYTES);
  402907:	48 8b 8d 78 f8 ff ff 	mov    -0x788(%rbp),%rcx
  40290e:	48 8b 85 90 f9 ff ff 	mov    -0x670(%rbp),%rax
  402915:	48 8b 95 98 f9 ff ff 	mov    -0x668(%rbp),%rdx
  40291c:	48 89 01             	mov    %rax,(%rcx)
  40291f:	48 89 51 08          	mov    %rdx,0x8(%rcx)
        if (!RAND_bytes(decbuffer + MEGAKI_TOKEN_BYTES, MEGAKI_RSA_KEYSIZE / 8)) {
  402923:	48 8d 85 c0 f9 ff ff 	lea    -0x640(%rbp),%rax
  40292a:	48 83 c0 10          	add    $0x10,%rax
  40292e:	be 00 01 00 00       	mov    $0x100,%esi
  402933:	48 89 c7             	mov    %rax,%rdi
  402936:	e8 95 f1 ff ff       	callq  401ad0 <RAND_bytes@plt>
  40293b:	85 c0                	test   %eax,%eax
  40293d:	75 42                	jne    402981 <handle_syn+0x8e9>
          #ifdef DOCUMENT_CONNECTIONS
          fprintf(stderr, "[%s] UNEXPECTED: could not generate bytes for srvsymm\n", c->conn_id);
  40293f:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402946:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  40294d:	48 8b 05 cc 38 20 00 	mov    0x2038cc(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402954:	48 8b 00             	mov    (%rax),%rax
  402957:	48 8d 35 32 28 00 00 	lea    0x2832(%rip),%rsi        # 405190 <consonants+0x290>
  40295e:	48 89 c7             	mov    %rax,%rdi
  402961:	b8 00 00 00 00       	mov    $0x0,%eax
  402966:	e8 95 f2 ff ff       	callq  401c00 <fprintf@plt>
          #endif
          c->conn_state = cs_error;
  40296b:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402972:	c7 80 08 02 00 00 05 	movl   $0x5,0x208(%rax)
  402979:	00 00 00 
          return;
  40297c:	e9 d3 01 00 00       	jmpq   402b54 <handle_syn+0xabc>
        }
        #ifdef DOCUMENT_CONNECTIONS
        fprintf(stderr, "[%s] generated srvsymm:\n", c->conn_id);
  402981:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402988:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  40298f:	48 8b 05 8a 38 20 00 	mov    0x20388a(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402996:	48 8b 00             	mov    (%rax),%rax
  402999:	48 8d 35 27 28 00 00 	lea    0x2827(%rip),%rsi        # 4051c7 <consonants+0x2c7>
  4029a0:	48 89 c7             	mov    %rax,%rdi
  4029a3:	b8 00 00 00 00       	mov    $0x0,%eax
  4029a8:	e8 53 f2 ff ff       	callq  401c00 <fprintf@plt>
        hexdump(stderr, "SRVSYMM", decbuffer + MEGAKI_TOKEN_BYTES, MEGAKI_AES_CBC_KEYSIZE / 8);
  4029ad:	48 8b 05 6c 38 20 00 	mov    0x20386c(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  4029b4:	48 8b 00             	mov    (%rax),%rax
  4029b7:	48 8d 95 c0 f9 ff ff 	lea    -0x640(%rbp),%rdx
  4029be:	48 83 c2 10          	add    $0x10,%rdx
  4029c2:	b9 20 00 00 00       	mov    $0x20,%ecx
  4029c7:	48 8d 35 12 28 00 00 	lea    0x2812(%rip),%rsi        # 4051e0 <consonants+0x2e0>
  4029ce:	48 89 c7             	mov    %rax,%rdi
  4029d1:	e8 d4 22 00 00       	callq  404caa <hexdump>
        #endif
        
        SHA256(decbuffer, MEGAKI_TOKEN_BYTES + MEGAKI_AES_CBC_KEYSIZE / 8, buffer + MAGIC_BYTES);
  4029d6:	48 8d 85 c0 fb ff ff 	lea    -0x440(%rbp),%rax
  4029dd:	48 8d 50 06          	lea    0x6(%rax),%rdx
  4029e1:	48 8d 85 c0 f9 ff ff 	lea    -0x640(%rbp),%rax
  4029e8:	be 30 00 00 00       	mov    $0x30,%esi
  4029ed:	48 89 c7             	mov    %rax,%rdi
  4029f0:	e8 4b f0 ff ff       	callq  401a40 <SHA256@plt>
        
        if ((RSA_public_encrypt(MEGAKI_TOKEN_BYTES + MEGAKI_AES_CBC_KEYSIZE / 8, decbuffer,
  4029f5:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  4029fc:	48 8b 50 10          	mov    0x10(%rax),%rdx
  402a00:	48 8d 85 c0 fb ff ff 	lea    -0x440(%rbp),%rax
  402a07:	48 8d 70 36          	lea    0x36(%rax),%rsi
  402a0b:	48 8d 85 c0 f9 ff ff 	lea    -0x640(%rbp),%rax
  402a12:	41 b8 04 00 00 00    	mov    $0x4,%r8d
  402a18:	48 89 d1             	mov    %rdx,%rcx
  402a1b:	48 89 f2             	mov    %rsi,%rdx
  402a1e:	48 89 c6             	mov    %rax,%rsi
  402a21:	bf 30 00 00 00       	mov    $0x30,%edi
  402a26:	e8 55 f1 ff ff       	callq  401b80 <RSA_public_encrypt@plt>
  402a2b:	83 f8 ff             	cmp    $0xffffffff,%eax
  402a2e:	75 42                	jne    402a72 <handle_syn+0x9da>
          buffer + MAGIC_BYTES + MEGAKI_TOKEN_BYTES + MEGAKI_HASH_BYTES, c->client_public, RSA_PKCS1_OAEP_PADDING)) == -1) {
          #ifdef DOCUMENT_CONNECTIONS
          fprintf(stderr, "[%s] UNEXPECTED: could not encrypt syn-ack plaintext\n", c->conn_id);
  402a30:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402a37:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  402a3e:	48 8b 05 db 37 20 00 	mov    0x2037db(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402a45:	48 8b 00             	mov    (%rax),%rax
  402a48:	48 8d 35 99 27 00 00 	lea    0x2799(%rip),%rsi        # 4051e8 <consonants+0x2e8>
  402a4f:	48 89 c7             	mov    %rax,%rdi
  402a52:	b8 00 00 00 00       	mov    $0x0,%eax
  402a57:	e8 a4 f1 ff ff       	callq  401c00 <fprintf@plt>
          #endif
          c->conn_state = cs_error;
  402a5c:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402a63:	c7 80 08 02 00 00 05 	movl   $0x5,0x208(%rax)
  402a6a:	00 00 00 
          return;
  402a6d:	e9 e2 00 00 00       	jmpq   402b54 <handle_syn+0xabc>
        }
      } 
    }
    const int len = MAGIC_BYTES + MEGAKI_HASH_BYTES + MEGAKI_TOKEN_BYTES +
  402a72:	c7 45 cc 36 01 00 00 	movl   $0x136,-0x34(%rbp)
    MEGAKI_RSA_KEYSIZE / 8;
    uv_buf_t a = { .base = buffer, .len = len };
  402a79:	48 8d 85 c0 fb ff ff 	lea    -0x440(%rbp),%rax
  402a80:	48 89 85 80 f9 ff ff 	mov    %rax,-0x680(%rbp)
  402a87:	8b 45 cc             	mov    -0x34(%rbp),%eax
  402a8a:	48 98                	cltq   
  402a8c:	48 89 85 88 f9 ff ff 	mov    %rax,-0x678(%rbp)
    uv_write_t* wreq = (uv_write_t*)malloc(sizeof(uv_write_t));
  402a93:	bf a0 00 00 00       	mov    $0xa0,%edi
  402a98:	e8 e3 ed ff ff       	callq  401880 <malloc@plt>
  402a9d:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
    if (uv_write(wreq, c->stream, &a, 1, on_write_syn)) {
  402aa1:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402aa8:	48 8b b0 00 02 00 00 	mov    0x200(%rax),%rsi
  402aaf:	48 8d 95 80 f9 ff ff 	lea    -0x680(%rbp),%rdx
  402ab6:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
  402aba:	48 8d 0d 62 f5 ff ff 	lea    -0xa9e(%rip),%rcx        # 402023 <on_write_syn>
  402ac1:	49 89 c8             	mov    %rcx,%r8
  402ac4:	b9 01 00 00 00       	mov    $0x1,%ecx
  402ac9:	48 89 c7             	mov    %rax,%rdi
  402acc:	e8 0f ef ff ff       	callq  4019e0 <uv_write@plt>
  402ad1:	85 c0                	test   %eax,%eax
  402ad3:	74 40                	je     402b15 <handle_syn+0xa7d>
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] unable to write to socket\n", c->conn_id);
  402ad5:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402adc:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  402ae3:	48 8b 05 36 37 20 00 	mov    0x203736(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402aea:	48 8b 00             	mov    (%rax),%rax
  402aed:	48 8d 35 2c 27 00 00 	lea    0x272c(%rip),%rsi        # 405220 <consonants+0x320>
  402af4:	48 89 c7             	mov    %rax,%rdi
  402af7:	b8 00 00 00 00       	mov    $0x0,%eax
  402afc:	e8 ff f0 ff ff       	callq  401c00 <fprintf@plt>
      #endif
      c->conn_state = cs_error;
  402b01:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402b08:	c7 80 08 02 00 00 05 	movl   $0x5,0x208(%rax)
  402b0f:	00 00 00 
      return;
  402b12:	90                   	nop
  402b13:	eb 3f                	jmp    402b54 <handle_syn+0xabc>
  402b15:	eb 3d                	jmp    402b54 <handle_syn+0xabc>
    }
  } else {
    #ifdef DOCUMENT_CONNECTIONS
    fprintf(stderr, "[%s] invalid magic\n", c->conn_id);
  402b17:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402b1e:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  402b25:	48 8b 05 f4 36 20 00 	mov    0x2036f4(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402b2c:	48 8b 00             	mov    (%rax),%rax
  402b2f:	48 8d 35 0a 27 00 00 	lea    0x270a(%rip),%rsi        # 405240 <consonants+0x340>
  402b36:	48 89 c7             	mov    %rax,%rdi
  402b39:	b8 00 00 00 00       	mov    $0x0,%eax
  402b3e:	e8 bd f0 ff ff       	callq  401c00 <fprintf@plt>
    #endif
    c->conn_state = cs_error;
  402b43:	48 8b 85 78 f8 ff ff 	mov    -0x788(%rbp),%rax
  402b4a:	c7 80 08 02 00 00 05 	movl   $0x5,0x208(%rax)
  402b51:	00 00 00 
  }
}
  402b54:	48 81 c4 88 07 00 00 	add    $0x788,%rsp
  402b5b:	5b                   	pop    %rbx
  402b5c:	5d                   	pop    %rbp
  402b5d:	c3                   	retq   

0000000000402b5e <handle_syn_wrapper>:

void handle_syn_wrapper(void* param)
{
  402b5e:	55                   	push   %rbp
  402b5f:	48 89 e5             	mov    %rsp,%rbp
  402b62:	48 83 ec 20          	sub    $0x20,%rsp
  402b66:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  connection* c = (connection*)param;
  402b6a:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  402b6e:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  handle_syn(c);
  402b72:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402b76:	48 89 c7             	mov    %rax,%rdi
  402b79:	e8 1a f5 ff ff       	callq  402098 <handle_syn>
  
  if (c->conn_state == cs_error) {
  402b7e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402b82:	8b 80 08 02 00 00    	mov    0x208(%rax),%eax
  402b88:	83 f8 05             	cmp    $0x5,%eax
  402b8b:	75 35                	jne    402bc2 <handle_syn_wrapper+0x64>
    #ifdef DOCUMENT_CONNECTIONS
    fprintf(stderr, "[%s] error state: closing connection\n", c->conn_id);
  402b8d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402b91:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  402b98:	48 8b 05 81 36 20 00 	mov    0x203681(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402b9f:	48 8b 00             	mov    (%rax),%rax
  402ba2:	48 8d 35 af 26 00 00 	lea    0x26af(%rip),%rsi        # 405258 <consonants+0x358>
  402ba9:	48 89 c7             	mov    %rax,%rdi
  402bac:	b8 00 00 00 00       	mov    $0x0,%eax
  402bb1:	e8 4a f0 ff ff       	callq  401c00 <fprintf@plt>
    #endif
    quit_connection_async(c);
  402bb6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402bba:	48 89 c7             	mov    %rax,%rdi
  402bbd:	e8 18 f3 ff ff       	callq  401eda <quit_connection_async>
  }
}
  402bc2:	c9                   	leaveq 
  402bc3:	c3                   	retq   

0000000000402bc4 <handle_ack>:

void handle_ack(connection* c)
{
  402bc4:	55                   	push   %rbp
  402bc5:	48 89 e5             	mov    %rsp,%rbp
  402bc8:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  
}
  402bcc:	5d                   	pop    %rbp
  402bcd:	c3                   	retq   

0000000000402bce <alloc_buffer>:

uv_buf_t alloc_buffer(uv_handle_t* handle, size_t size) {
  402bce:	55                   	push   %rbp
  402bcf:	48 89 e5             	mov    %rsp,%rbp
  402bd2:	53                   	push   %rbx
  402bd3:	48 83 ec 18          	sub    $0x18,%rsp
  402bd7:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  402bdb:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  return uv_buf_init((char*) malloc(size), size);
  402bdf:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  402be3:	89 c3                	mov    %eax,%ebx
  402be5:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  402be9:	48 89 c7             	mov    %rax,%rdi
  402bec:	e8 8f ec ff ff       	callq  401880 <malloc@plt>
  402bf1:	89 de                	mov    %ebx,%esi
  402bf3:	48 89 c7             	mov    %rax,%rdi
  402bf6:	e8 15 f0 ff ff       	callq  401c10 <uv_buf_init@plt>
}
  402bfb:	48 83 c4 18          	add    $0x18,%rsp
  402bff:	5b                   	pop    %rbx
  402c00:	5d                   	pop    %rbp
  402c01:	c3                   	retq   

0000000000402c02 <fill_buffer>:

void fill_buffer(connection* conn, ssize_t nread, uv_buf_t buf)
{
  402c02:	55                   	push   %rbp
  402c03:	48 89 e5             	mov    %rsp,%rbp
  402c06:	48 83 ec 20          	sub    $0x20,%rsp
  402c0a:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  402c0e:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
  402c12:	48 89 55 e0          	mov    %rdx,-0x20(%rbp)
  402c16:	48 89 4d e8          	mov    %rcx,-0x18(%rbp)
  pthread_mutex_lock(&conn->buffer_mutex);
  402c1a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402c1e:	48 05 18 02 00 00    	add    $0x218,%rax
  402c24:	48 89 c7             	mov    %rax,%rdi
  402c27:	e8 94 ef ff ff       	callq  401bc0 <pthread_mutex_lock@plt>
  memcpy(conn->receive_buffer + conn->received_length, buf.base, nread);
  402c2c:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
  402c30:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  402c34:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
  402c38:	8b 89 40 06 00 00    	mov    0x640(%rcx),%ecx
  402c3e:	89 c9                	mov    %ecx,%ecx
  402c40:	48 8d b1 40 02 00 00 	lea    0x240(%rcx),%rsi
  402c47:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
  402c4b:	48 01 f1             	add    %rsi,%rcx
  402c4e:	48 89 c6             	mov    %rax,%rsi
  402c51:	48 89 cf             	mov    %rcx,%rdi
  402c54:	e8 17 f0 ff ff       	callq  401c70 <memcpy@plt>
  conn->received_length += nread;  
  402c59:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402c5d:	8b 90 40 06 00 00    	mov    0x640(%rax),%edx
  402c63:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  402c67:	01 c2                	add    %eax,%edx
  402c69:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402c6d:	89 90 40 06 00 00    	mov    %edx,0x640(%rax)
  pthread_mutex_unlock(&conn->buffer_mutex);
  402c73:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402c77:	48 05 18 02 00 00    	add    $0x218,%rax
  402c7d:	48 89 c7             	mov    %rax,%rdi
  402c80:	e8 db ef ff ff       	callq  401c60 <pthread_mutex_unlock@plt>
}
  402c85:	c9                   	leaveq 
  402c86:	c3                   	retq   

0000000000402c87 <on_read>:

void on_read(uv_stream_t* stream, ssize_t nread, uv_buf_t buf)
{
  402c87:	55                   	push   %rbp
  402c88:	48 89 e5             	mov    %rsp,%rbp
  402c8b:	48 83 ec 30          	sub    $0x30,%rsp
  402c8f:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  402c93:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  402c97:	48 89 55 d0          	mov    %rdx,-0x30(%rbp)
  402c9b:	48 89 4d d8          	mov    %rcx,-0x28(%rbp)
  connection* conn = (connection*)stream->data;
  402c9f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  402ca3:	48 8b 40 08          	mov    0x8(%rax),%rax
  402ca7:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  if (nread == -1 || conn->conn_state == cs_error) {
  402cab:	48 83 7d e0 ff       	cmpq   $0xffffffffffffffff,-0x20(%rbp)
  402cb0:	74 0f                	je     402cc1 <on_read+0x3a>
  402cb2:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402cb6:	8b 80 08 02 00 00    	mov    0x208(%rax),%eax
  402cbc:	83 f8 05             	cmp    $0x5,%eax
  402cbf:	75 3f                	jne    402d00 <on_read+0x79>
    #ifdef DOCUMENT_CONNECTIONS
    fprintf(stderr, "[%s] closing connection\n", conn->conn_id);
  402cc1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402cc5:	48 8d 90 0c 02 00 00 	lea    0x20c(%rax),%rdx
  402ccc:	48 8b 05 4d 35 20 00 	mov    0x20354d(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402cd3:	48 8b 00             	mov    (%rax),%rax
  402cd6:	48 8d 35 a1 25 00 00 	lea    0x25a1(%rip),%rsi        # 40527e <consonants+0x37e>
  402cdd:	48 89 c7             	mov    %rax,%rdi
  402ce0:	b8 00 00 00 00       	mov    $0x0,%eax
  402ce5:	e8 16 ef ff ff       	callq  401c00 <fprintf@plt>
    #endif
    quit_connection(conn, 0);
  402cea:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402cee:	be 00 00 00 00       	mov    $0x0,%esi
  402cf3:	48 89 c7             	mov    %rax,%rdi
  402cf6:	e8 d3 f0 ff ff       	callq  401dce <quit_connection>
    return;
  402cfb:	e9 30 01 00 00       	jmpq   402e30 <on_read+0x1a9>
  }
  
  ssize_t newlength = conn->received_length + nread;
  402d00:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402d04:	8b 80 40 06 00 00    	mov    0x640(%rax),%eax
  402d0a:	89 c2                	mov    %eax,%edx
  402d0c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  402d10:	48 01 d0             	add    %rdx,%rax
  402d13:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  
  switch(conn->conn_state) {
  402d17:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402d1b:	8b 80 08 02 00 00    	mov    0x208(%rax),%eax
  402d21:	83 f8 05             	cmp    $0x5,%eax
  402d24:	0f 87 06 01 00 00    	ja     402e30 <on_read+0x1a9>
  402d2a:	89 c0                	mov    %eax,%eax
  402d2c:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
  402d33:	00 
  402d34:	48 8d 05 5d 25 00 00 	lea    0x255d(%rip),%rax        # 405298 <consonants+0x398>
  402d3b:	8b 04 02             	mov    (%rdx,%rax,1),%eax
  402d3e:	48 63 d0             	movslq %eax,%rdx
  402d41:	48 8d 05 50 25 00 00 	lea    0x2550(%rip),%rax        # 405298 <consonants+0x398>
  402d48:	48 01 d0             	add    %rdx,%rax
  402d4b:	ff e0                	jmpq   *%rax
  case cs_wait_syn:
    if (newlength == SYN_LENGTH) {
  402d4d:	48 81 7d f0 26 02 00 	cmpq   $0x226,-0x10(%rbp)
  402d54:	00 
  402d55:	75 4d                	jne    402da4 <on_read+0x11d>
      conn->conn_state = cs_recv_syn;
  402d57:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402d5b:	c7 80 08 02 00 00 01 	movl   $0x1,0x208(%rax)
  402d62:	00 00 00 
      fill_buffer(conn, nread, buf);
  402d65:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  402d69:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
  402d6d:	48 8b 75 e0          	mov    -0x20(%rbp),%rsi
  402d71:	48 8b 7d f8          	mov    -0x8(%rbp),%rdi
  402d75:	48 89 d1             	mov    %rdx,%rcx
  402d78:	48 89 c2             	mov    %rax,%rdx
  402d7b:	e8 82 fe ff ff       	callq  402c02 <fill_buffer>
      threadpool_add(pool, handle_syn_wrapper, conn, 0);
  402d80:	48 8d 05 39 38 20 00 	lea    0x203839(%rip),%rax        # 6065c0 <pool>
  402d87:	48 8b 00             	mov    (%rax),%rax
  402d8a:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
  402d8e:	b9 00 00 00 00       	mov    $0x0,%ecx
  402d93:	48 8d 35 c4 fd ff ff 	lea    -0x23c(%rip),%rsi        # 402b5e <handle_syn_wrapper>
  402d9a:	48 89 c7             	mov    %rax,%rdi
  402d9d:	e8 ef 1a 00 00       	callq  404891 <threadpool_add>
  402da2:	eb 27                	jmp    402dcb <on_read+0x144>
    } else if (newlength > SYN_LENGTH) {
  402da4:	48 81 7d f0 26 02 00 	cmpq   $0x226,-0x10(%rbp)
  402dab:	00 
  402dac:	7f 1d                	jg     402dcb <on_read+0x144>
      /* ignore bogus data */
    } else {
      fill_buffer(conn, nread, buf);
  402dae:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  402db2:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
  402db6:	48 8b 75 e0          	mov    -0x20(%rbp),%rsi
  402dba:	48 8b 7d f8          	mov    -0x8(%rbp),%rdi
  402dbe:	48 89 d1             	mov    %rdx,%rcx
  402dc1:	48 89 c2             	mov    %rax,%rdx
  402dc4:	e8 39 fe ff ff       	callq  402c02 <fill_buffer>
    }
    
    break;
  402dc9:	eb 65                	jmp    402e30 <on_read+0x1a9>
  402dcb:	eb 63                	jmp    402e30 <on_read+0x1a9>
    
  case cs_recv_syn:
    break;
    
  case cs_wait_ack:
    if (newlength == ACK_LENGTH) {
  402dcd:	48 83 7d f0 66       	cmpq   $0x66,-0x10(%rbp)
  402dd2:	75 37                	jne    402e0b <on_read+0x184>
      conn->conn_state = cs_recv_ack;
  402dd4:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402dd8:	c7 80 08 02 00 00 03 	movl   $0x3,0x208(%rax)
  402ddf:	00 00 00 
      fill_buffer(conn, nread, buf);
  402de2:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  402de6:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
  402dea:	48 8b 75 e0          	mov    -0x20(%rbp),%rsi
  402dee:	48 8b 7d f8          	mov    -0x8(%rbp),%rdi
  402df2:	48 89 d1             	mov    %rdx,%rcx
  402df5:	48 89 c2             	mov    %rax,%rdx
  402df8:	e8 05 fe ff ff       	callq  402c02 <fill_buffer>
      handle_ack(conn);
  402dfd:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  402e01:	48 89 c7             	mov    %rax,%rdi
  402e04:	e8 bb fd ff ff       	callq  402bc4 <handle_ack>
  402e09:	eb 24                	jmp    402e2f <on_read+0x1a8>
    } else if (newlength > ACK_LENGTH) {
  402e0b:	48 83 7d f0 66       	cmpq   $0x66,-0x10(%rbp)
  402e10:	7f 1d                	jg     402e2f <on_read+0x1a8>
      /* ignore bogus data */
    } else {
      fill_buffer(conn, nread, buf);
  402e12:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  402e16:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
  402e1a:	48 8b 75 e0          	mov    -0x20(%rbp),%rsi
  402e1e:	48 8b 7d f8          	mov    -0x8(%rbp),%rdi
  402e22:	48 89 d1             	mov    %rdx,%rcx
  402e25:	48 89 c2             	mov    %rax,%rdx
  402e28:	e8 d5 fd ff ff       	callq  402c02 <fill_buffer>
    }
    break;
  402e2d:	eb 00                	jmp    402e2f <on_read+0x1a8>
  402e2f:	90                   	nop
    break;
    
  case cs_msg_loop:
    break;
  };
}
  402e30:	c9                   	leaveq 
  402e31:	c3                   	retq   

0000000000402e32 <on_connect>:

void on_connect(uv_stream_t* server, int status)
{
  402e32:	55                   	push   %rbp
  402e33:	48 89 e5             	mov    %rsp,%rbp
  402e36:	48 83 ec 40          	sub    $0x40,%rsp
  402e3a:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
  402e3e:	89 75 c4             	mov    %esi,-0x3c(%rbp)
  if (status == -1) {
  402e41:	83 7d c4 ff          	cmpl   $0xffffffff,-0x3c(%rbp)
  402e45:	75 28                	jne    402e6f <on_connect+0x3d>
    #ifdef DOCUMENT_CONNECTIONS
    fprintf(stderr, "[HYPRVS] connection attempt fail\n");
  402e47:	48 8b 05 d2 33 20 00 	mov    0x2033d2(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402e4e:	48 8b 00             	mov    (%rax),%rax
  402e51:	48 89 c1             	mov    %rax,%rcx
  402e54:	ba 21 00 00 00       	mov    $0x21,%edx
  402e59:	be 01 00 00 00       	mov    $0x1,%esi
  402e5e:	48 8d 3d 4b 24 00 00 	lea    0x244b(%rip),%rdi        # 4052b0 <consonants+0x3b0>
  402e65:	e8 46 ed ff ff       	callq  401bb0 <fwrite@plt>
    return;
  402e6a:	e9 64 02 00 00       	jmpq   4030d3 <on_connect+0x2a1>
    #endif
  }
  uv_tcp_t* client = malloc(sizeof(uv_tcp_t));
  402e6f:	bf d8 00 00 00       	mov    $0xd8,%edi
  402e74:	e8 07 ea ff ff       	callq  401880 <malloc@plt>
  402e79:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  if (uv_tcp_init(loop, client) == -1) {
  402e7d:	48 8d 05 84 37 20 00 	lea    0x203784(%rip),%rax        # 606608 <loop>
  402e84:	48 8b 00             	mov    (%rax),%rax
  402e87:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
  402e8b:	48 89 d6             	mov    %rdx,%rsi
  402e8e:	48 89 c7             	mov    %rax,%rdi
  402e91:	e8 0a eb ff ff       	callq  4019a0 <uv_tcp_init@plt>
  402e96:	83 f8 ff             	cmp    $0xffffffff,%eax
  402e99:	75 34                	jne    402ecf <on_connect+0x9d>
    #ifdef DOCUMENT_CONNECTIONS
    fprintf(stderr, "[HYPRVS] uv_tcp_init fail\n");
  402e9b:	48 8b 05 7e 33 20 00 	mov    0x20337e(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  402ea2:	48 8b 00             	mov    (%rax),%rax
  402ea5:	48 89 c1             	mov    %rax,%rcx
  402ea8:	ba 1a 00 00 00       	mov    $0x1a,%edx
  402ead:	be 01 00 00 00       	mov    $0x1,%esi
  402eb2:	48 8d 3d 19 24 00 00 	lea    0x2419(%rip),%rdi        # 4052d2 <consonants+0x3d2>
  402eb9:	e8 f2 ec ff ff       	callq  401bb0 <fwrite@plt>
    #endif 
    free(client);   
  402ebe:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  402ec2:	48 89 c7             	mov    %rax,%rdi
  402ec5:	e8 76 ea ff ff       	callq  401940 <free@plt>
    return;
  402eca:	e9 04 02 00 00       	jmpq   4030d3 <on_connect+0x2a1>
  }
  
  if (uv_accept(server, (uv_stream_t*)client) == 0) {
  402ecf:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
  402ed3:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  402ed7:	48 89 d6             	mov    %rdx,%rsi
  402eda:	48 89 c7             	mov    %rax,%rdi
  402edd:	e8 ce eb ff ff       	callq  401ab0 <uv_accept@plt>
  402ee2:	85 c0                	test   %eax,%eax
  402ee4:	0f 85 d8 01 00 00    	jne    4030c2 <on_connect+0x290>
    int connsocket = client->accepted_fd; /* AH HA HA HA BREAKING MULTIPLATFORM CODE */
  402eea:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  402eee:	8b 80 d4 00 00 00    	mov    0xd4(%rax),%eax
  402ef4:	89 45 ec             	mov    %eax,-0x14(%rbp)
    setsockopt(connsocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval));
  402ef7:	8b 45 ec             	mov    -0x14(%rbp),%eax
  402efa:	41 b8 10 00 00 00    	mov    $0x10,%r8d
  402f00:	48 8d 15 d9 36 20 00 	lea    0x2036d9(%rip),%rdx        # 6065e0 <tv>
  402f07:	48 89 d1             	mov    %rdx,%rcx
  402f0a:	ba 14 00 00 00       	mov    $0x14,%edx
  402f0f:	be 01 00 00 00       	mov    $0x1,%esi
  402f14:	89 c7                	mov    %eax,%edi
  402f16:	e8 c5 e9 ff ff       	callq  4018e0 <setsockopt@plt>
    setsockopt(connsocket, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin));
  402f1b:	8b 45 ec             	mov    -0x14(%rbp),%eax
  402f1e:	41 b8 08 00 00 00    	mov    $0x8,%r8d
  402f24:	48 8d 15 cd 36 20 00 	lea    0x2036cd(%rip),%rdx        # 6065f8 <lin>
  402f2b:	48 89 d1             	mov    %rdx,%rcx
  402f2e:	ba 0d 00 00 00       	mov    $0xd,%edx
  402f33:	be 01 00 00 00       	mov    $0x1,%esi
  402f38:	89 c7                	mov    %eax,%edi
  402f3a:	e8 a1 e9 ff ff       	callq  4018e0 <setsockopt@plt>

    /*byte buffer[MAX_MESSAGE_LENGTH], decbuffer[DECRYPTION_BUF_LENGTH], mac[MEGAKI_HASH_BYTES],
         tokstr[MEGAKI_TOKEN_BYTES];*/
         
    connection *c = malloc(sizeof(connection));
  402f3f:	bf 48 06 00 00       	mov    $0x648,%edi
  402f44:	e8 37 e9 ff ff       	callq  401880 <malloc@plt>
  402f49:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    memset(c, 0, sizeof(connection));
  402f4d:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  402f51:	ba 48 06 00 00       	mov    $0x648,%edx
  402f56:	be 00 00 00 00       	mov    $0x0,%esi
  402f5b:	48 89 c7             	mov    %rax,%rdi
  402f5e:	e8 8d e8 ff ff       	callq  4017f0 <memset@plt>
    client->data = c;
  402f63:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  402f67:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
  402f6b:	48 89 50 08          	mov    %rdx,0x8(%rax)
    c->stream = client;
  402f6f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  402f73:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
  402f77:	48 89 90 00 02 00 00 	mov    %rdx,0x200(%rax)
    
    #ifdef DOCUMENT_CONNECTIONS
    char cons[7];
    int consi;
    for (consi = 0; consi < 6; ++consi) {
  402f7e:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  402f85:	e9 a6 00 00 00       	jmpq   403030 <on_connect+0x1fe>
      if (consi % 2 == 0)
  402f8a:	8b 45 fc             	mov    -0x4(%rbp),%eax
  402f8d:	83 e0 01             	and    $0x1,%eax
  402f90:	85 c0                	test   %eax,%eax
  402f92:	75 58                	jne    402fec <on_connect+0x1ba>
        cons[consi] = consonants[rand() % (sizeof consonants - 1)];
  402f94:	e8 57 ec ff ff       	callq  401bf0 <rand@plt>
  402f99:	48 63 c8             	movslq %eax,%rcx
  402f9c:	48 ba 19 86 61 18 86 	movabs $0x8618618618618619,%rdx
  402fa3:	61 18 86 
  402fa6:	48 89 c8             	mov    %rcx,%rax
  402fa9:	48 f7 e2             	mul    %rdx
  402fac:	48 89 c8             	mov    %rcx,%rax
  402faf:	48 29 d0             	sub    %rdx,%rax
  402fb2:	48 d1 e8             	shr    %rax
  402fb5:	48 01 d0             	add    %rdx,%rax
  402fb8:	48 c1 e8 04          	shr    $0x4,%rax
  402fbc:	48 89 c2             	mov    %rax,%rdx
  402fbf:	48 89 d0             	mov    %rdx,%rax
  402fc2:	48 c1 e0 02          	shl    $0x2,%rax
  402fc6:	48 01 d0             	add    %rdx,%rax
  402fc9:	48 c1 e0 02          	shl    $0x2,%rax
  402fcd:	48 01 d0             	add    %rdx,%rax
  402fd0:	48 29 c1             	sub    %rax,%rcx
  402fd3:	48 89 ca             	mov    %rcx,%rdx
  402fd6:	48 8d 05 23 1f 00 00 	lea    0x1f23(%rip),%rax        # 404f00 <consonants>
  402fdd:	0f b6 14 10          	movzbl (%rax,%rdx,1),%edx
  402fe1:	8b 45 fc             	mov    -0x4(%rbp),%eax
  402fe4:	48 98                	cltq   
  402fe6:	88 54 05 d0          	mov    %dl,-0x30(%rbp,%rax,1)
  402fea:	eb 40                	jmp    40302c <on_connect+0x1fa>
      else cons[consi] = vowels[rand() % (sizeof vowels - 1)];
  402fec:	e8 ff eb ff ff       	callq  401bf0 <rand@plt>
  402ff1:	48 63 c8             	movslq %eax,%rcx
  402ff4:	48 ba cd cc cc cc cc 	movabs $0xcccccccccccccccd,%rdx
  402ffb:	cc cc cc 
  402ffe:	48 89 c8             	mov    %rcx,%rax
  403001:	48 f7 e2             	mul    %rdx
  403004:	48 c1 ea 02          	shr    $0x2,%rdx
  403008:	48 89 d0             	mov    %rdx,%rax
  40300b:	48 c1 e0 02          	shl    $0x2,%rax
  40300f:	48 01 d0             	add    %rdx,%rax
  403012:	48 29 c1             	sub    %rax,%rcx
  403015:	48 89 ca             	mov    %rcx,%rdx
  403018:	48 8d 05 db 1e 00 00 	lea    0x1edb(%rip),%rax        # 404efa <vowels>
  40301f:	0f b6 14 10          	movzbl (%rax,%rdx,1),%edx
  403023:	8b 45 fc             	mov    -0x4(%rbp),%eax
  403026:	48 98                	cltq   
  403028:	88 54 05 d0          	mov    %dl,-0x30(%rbp,%rax,1)
    c->stream = client;
    
    #ifdef DOCUMENT_CONNECTIONS
    char cons[7];
    int consi;
    for (consi = 0; consi < 6; ++consi) {
  40302c:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  403030:	83 7d fc 05          	cmpl   $0x5,-0x4(%rbp)
  403034:	0f 8e 50 ff ff ff    	jle    402f8a <on_connect+0x158>
      if (consi % 2 == 0)
        cons[consi] = consonants[rand() % (sizeof consonants - 1)];
      else cons[consi] = vowels[rand() % (sizeof vowels - 1)];
    }
    cons[6] = '\0';
  40303a:	c6 45 d6 00          	movb   $0x0,-0x2a(%rbp)
    memcpy(c->conn_id, cons, 7);
  40303e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  403042:	48 05 0c 02 00 00    	add    $0x20c,%rax
  403048:	8b 55 d0             	mov    -0x30(%rbp),%edx
  40304b:	89 10                	mov    %edx,(%rax)
  40304d:	0f b7 55 d4          	movzwl -0x2c(%rbp),%edx
  403051:	66 89 50 04          	mov    %dx,0x4(%rax)
  403055:	0f b6 55 d6          	movzbl -0x2a(%rbp),%edx
  403059:	88 50 06             	mov    %dl,0x6(%rax)
    fprintf(stderr, "[%s] opening connection\n", cons);
  40305c:	48 8b 05 bd 31 20 00 	mov    0x2031bd(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  403063:	48 8b 00             	mov    (%rax),%rax
  403066:	48 8d 55 d0          	lea    -0x30(%rbp),%rdx
  40306a:	48 8d 35 7c 22 00 00 	lea    0x227c(%rip),%rsi        # 4052ed <consonants+0x3ed>
  403071:	48 89 c7             	mov    %rax,%rdi
  403074:	b8 00 00 00 00       	mov    $0x0,%eax
  403079:	e8 82 eb ff ff       	callq  401c00 <fprintf@plt>
    #endif
    
    pthread_mutex_init(&c->buffer_mutex, NULL);
  40307e:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  403082:	48 05 18 02 00 00    	add    $0x218,%rax
  403088:	be 00 00 00 00       	mov    $0x0,%esi
  40308d:	48 89 c7             	mov    %rax,%rdi
  403090:	e8 5b e8 ff ff       	callq  4018f0 <pthread_mutex_init@plt>
    c->conn_state = cs_wait_syn;
  403095:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  403099:	c7 80 08 02 00 00 00 	movl   $0x0,0x208(%rax)
  4030a0:	00 00 00 
    uv_read_start((uv_stream_t*)client, alloc_buffer, on_read);
  4030a3:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  4030a7:	48 8d 15 d9 fb ff ff 	lea    -0x427(%rip),%rdx        # 402c87 <on_read>
  4030ae:	48 8d 0d 19 fb ff ff 	lea    -0x4e7(%rip),%rcx        # 402bce <alloc_buffer>
  4030b5:	48 89 ce             	mov    %rcx,%rsi
  4030b8:	48 89 c7             	mov    %rax,%rdi
  4030bb:	e8 70 e9 ff ff       	callq  401a30 <uv_read_start@plt>
  4030c0:	eb 11                	jmp    4030d3 <on_connect+0x2a1>
  } else {
    uv_close((uv_handle_t*) client, NULL);
  4030c2:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  4030c6:	be 00 00 00 00       	mov    $0x0,%esi
  4030cb:	48 89 c7             	mov    %rax,%rdi
  4030ce:	e8 3d ea ff ff       	callq  401b10 <uv_close@plt>
  }
}
  4030d3:	c9                   	leaveq 
  4030d4:	c3                   	retq   

00000000004030d5 <server>:
    fprintf(stderr, "fatal: %s\n", (reason)); \
    return(-1); \
  }
  
int server()
{
  4030d5:	55                   	push   %rbp
  4030d6:	48 89 e5             	mov    %rsp,%rbp
  4030d9:	48 83 ec 20          	sub    $0x20,%rsp
  int res;
  loop = uv_default_loop();
  4030dd:	e8 2e e8 ff ff       	callq  401910 <uv_default_loop@plt>
  4030e2:	48 8d 15 1f 35 20 00 	lea    0x20351f(%rip),%rdx        # 606608 <loop>
  4030e9:	48 89 02             	mov    %rax,(%rdx)
  
  struct sockaddr_in addr;
  addr = uv_ip4_addr(opt_addr, atoi(opt_port));
  4030ec:	48 8d 05 1d 35 20 00 	lea    0x20351d(%rip),%rax        # 606610 <opt_port>
  4030f3:	48 8b 00             	mov    (%rax),%rax
  4030f6:	48 89 c7             	mov    %rax,%rdi
  4030f9:	e8 52 e9 ff ff       	callq  401a50 <atoi@plt>
  4030fe:	89 c2                	mov    %eax,%edx
  403100:	48 8d 05 b1 34 20 00 	lea    0x2034b1(%rip),%rax        # 6065b8 <opt_addr>
  403107:	48 8b 00             	mov    (%rax),%rax
  40310a:	89 d6                	mov    %edx,%esi
  40310c:	48 89 c7             	mov    %rax,%rdi
  40310f:	e8 1c e7 ff ff       	callq  401830 <uv_ip4_addr@plt>
  403114:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
  403118:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
  /*  fprintf(stderr, "fatal: could not resolve local address %s:%d\n", opt_addr, atoi(opt_port);
    return(-1);
  }*/
  
  pool = threadpool_create(opt_threads, opt_queuelength, 0);
  40311c:	48 8d 05 a9 34 20 00 	lea    0x2034a9(%rip),%rax        # 6065cc <opt_queuelength>
  403123:	8b 08                	mov    (%rax),%ecx
  403125:	48 8d 05 ec 34 20 00 	lea    0x2034ec(%rip),%rax        # 606618 <opt_threads>
  40312c:	8b 00                	mov    (%rax),%eax
  40312e:	ba 00 00 00 00       	mov    $0x0,%edx
  403133:	89 ce                	mov    %ecx,%esi
  403135:	89 c7                	mov    %eax,%edi
  403137:	e8 98 15 00 00       	callq  4046d4 <threadpool_create>
  40313c:	48 8d 15 7d 34 20 00 	lea    0x20347d(%rip),%rdx        # 6065c0 <pool>
  403143:	48 89 02             	mov    %rax,(%rdx)
  if (pool == NULL) {
  403146:	48 8d 05 73 34 20 00 	lea    0x203473(%rip),%rax        # 6065c0 <pool>
  40314d:	48 8b 00             	mov    (%rax),%rax
  403150:	48 85 c0             	test   %rax,%rax
  403153:	75 3c                	jne    403191 <server+0xbc>
    fprintf(stderr, "fatal: could not create threadpool\n");
  403155:	48 8b 05 c4 30 20 00 	mov    0x2030c4(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  40315c:	48 8b 00             	mov    (%rax),%rax
  40315f:	48 89 c1             	mov    %rax,%rcx
  403162:	ba 23 00 00 00       	mov    $0x23,%edx
  403167:	be 01 00 00 00       	mov    $0x1,%esi
  40316c:	48 8d 3d 95 21 00 00 	lea    0x2195(%rip),%rdi        # 405308 <consonants+0x408>
  403173:	e8 38 ea ff ff       	callq  401bb0 <fwrite@plt>
    EVP_cleanup();
  403178:	e8 f3 e7 ff ff       	callq  401970 <EVP_cleanup@plt>
    ERR_free_strings();
  40317d:	e8 3e e8 ff ff       	callq  4019c0 <ERR_free_strings@plt>
    CRYPTO_cleanup_all_ex_data();
  403182:	e8 79 e6 ff ff       	callq  401800 <CRYPTO_cleanup_all_ex_data@plt>
    return(-1);
  403187:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  40318c:	e9 8a 01 00 00       	jmpq   40331b <server+0x246>
  }
  fprintf(stderr, "created threadpool of %d threads with a queue of %d\n",
  403191:	48 8d 05 34 34 20 00 	lea    0x203434(%rip),%rax        # 6065cc <opt_queuelength>
  403198:	8b 08                	mov    (%rax),%ecx
  40319a:	48 8d 05 77 34 20 00 	lea    0x203477(%rip),%rax        # 606618 <opt_threads>
  4031a1:	8b 10                	mov    (%rax),%edx
  4031a3:	48 8b 05 76 30 20 00 	mov    0x203076(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  4031aa:	48 8b 00             	mov    (%rax),%rax
  4031ad:	48 8d 35 7c 21 00 00 	lea    0x217c(%rip),%rsi        # 405330 <consonants+0x430>
  4031b4:	48 89 c7             	mov    %rax,%rdi
  4031b7:	b8 00 00 00 00       	mov    $0x0,%eax
  4031bc:	e8 3f ea ff ff       	callq  401c00 <fprintf@plt>
    opt_threads, opt_queuelength);
  
  res = uv_tcp_init(loop, &servconn);
  4031c1:	48 8d 05 40 34 20 00 	lea    0x203440(%rip),%rax        # 606608 <loop>
  4031c8:	48 8b 00             	mov    (%rax),%rax
  4031cb:	48 8d 15 0e 33 20 00 	lea    0x20330e(%rip),%rdx        # 6064e0 <servconn>
  4031d2:	48 89 d6             	mov    %rdx,%rsi
  4031d5:	48 89 c7             	mov    %rax,%rdi
  4031d8:	e8 c3 e7 ff ff       	callq  4019a0 <uv_tcp_init@plt>
  4031dd:	89 45 fc             	mov    %eax,-0x4(%rbp)
  CHECK(res, "could not init libuv tcp");
  4031e0:	83 7d fc ff          	cmpl   $0xffffffff,-0x4(%rbp)
  4031e4:	75 2f                	jne    403215 <server+0x140>
  4031e6:	48 8b 05 33 30 20 00 	mov    0x203033(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  4031ed:	48 8b 00             	mov    (%rax),%rax
  4031f0:	48 8d 15 6e 21 00 00 	lea    0x216e(%rip),%rdx        # 405365 <consonants+0x465>
  4031f7:	48 8d 35 80 21 00 00 	lea    0x2180(%rip),%rsi        # 40537e <consonants+0x47e>
  4031fe:	48 89 c7             	mov    %rax,%rdi
  403201:	b8 00 00 00 00       	mov    $0x0,%eax
  403206:	e8 f5 e9 ff ff       	callq  401c00 <fprintf@plt>
  40320b:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  403210:	e9 06 01 00 00       	jmpq   40331b <server+0x246>
  res = uv_tcp_bind(&servconn, addr);
  403215:	48 8b 55 e0          	mov    -0x20(%rbp),%rdx
  403219:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  40321d:	48 89 d6             	mov    %rdx,%rsi
  403220:	48 89 c2             	mov    %rax,%rdx
  403223:	48 8d 05 b6 32 20 00 	lea    0x2032b6(%rip),%rax        # 6064e0 <servconn>
  40322a:	48 89 c7             	mov    %rax,%rdi
  40322d:	e8 7e e7 ff ff       	callq  4019b0 <uv_tcp_bind@plt>
  403232:	89 45 fc             	mov    %eax,-0x4(%rbp)
  CHECK(res, "could not bind to local address");
  403235:	83 7d fc ff          	cmpl   $0xffffffff,-0x4(%rbp)
  403239:	75 2f                	jne    40326a <server+0x195>
  40323b:	48 8b 05 de 2f 20 00 	mov    0x202fde(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  403242:	48 8b 00             	mov    (%rax),%rax
  403245:	48 8d 15 44 21 00 00 	lea    0x2144(%rip),%rdx        # 405390 <consonants+0x490>
  40324c:	48 8d 35 2b 21 00 00 	lea    0x212b(%rip),%rsi        # 40537e <consonants+0x47e>
  403253:	48 89 c7             	mov    %rax,%rdi
  403256:	b8 00 00 00 00       	mov    $0x0,%eax
  40325b:	e8 a0 e9 ff ff       	callq  401c00 <fprintf@plt>
  403260:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  403265:	e9 b1 00 00 00       	jmpq   40331b <server+0x246>
  
  res = uv_listen((uv_stream_t*)&servconn, SOCKET_BACKLOG, on_connect);
  40326a:	48 8d 05 c1 fb ff ff 	lea    -0x43f(%rip),%rax        # 402e32 <on_connect>
  403271:	48 89 c2             	mov    %rax,%rdx
  403274:	be 00 08 00 00       	mov    $0x800,%esi
  403279:	48 8d 05 60 32 20 00 	lea    0x203260(%rip),%rax        # 6064e0 <servconn>
  403280:	48 89 c7             	mov    %rax,%rdi
  403283:	e8 38 e8 ff ff       	callq  401ac0 <uv_listen@plt>
  403288:	89 45 fc             	mov    %eax,-0x4(%rbp)
  CHECK(res, "could not listen for connections");
  40328b:	83 7d fc ff          	cmpl   $0xffffffff,-0x4(%rbp)
  40328f:	75 2c                	jne    4032bd <server+0x1e8>
  403291:	48 8b 05 88 2f 20 00 	mov    0x202f88(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  403298:	48 8b 00             	mov    (%rax),%rax
  40329b:	48 8d 15 0e 21 00 00 	lea    0x210e(%rip),%rdx        # 4053b0 <consonants+0x4b0>
  4032a2:	48 8d 35 d5 20 00 00 	lea    0x20d5(%rip),%rsi        # 40537e <consonants+0x47e>
  4032a9:	48 89 c7             	mov    %rax,%rdi
  4032ac:	b8 00 00 00 00       	mov    $0x0,%eax
  4032b1:	e8 4a e9 ff ff       	callq  401c00 <fprintf@plt>
  4032b6:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  4032bb:	eb 5e                	jmp    40331b <server+0x246>
  
  fprintf(stderr, "bound and listening on %s:%s\n", opt_addr, opt_port);
  4032bd:	48 8d 05 4c 33 20 00 	lea    0x20334c(%rip),%rax        # 606610 <opt_port>
  4032c4:	48 8b 08             	mov    (%rax),%rcx
  4032c7:	48 8d 05 ea 32 20 00 	lea    0x2032ea(%rip),%rax        # 6065b8 <opt_addr>
  4032ce:	48 8b 10             	mov    (%rax),%rdx
  4032d1:	48 8b 05 48 2f 20 00 	mov    0x202f48(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  4032d8:	48 8b 00             	mov    (%rax),%rax
  4032db:	48 8d 35 ef 20 00 00 	lea    0x20ef(%rip),%rsi        # 4053d1 <consonants+0x4d1>
  4032e2:	48 89 c7             	mov    %rax,%rdi
  4032e5:	b8 00 00 00 00       	mov    $0x0,%eax
  4032ea:	e8 11 e9 ff ff       	callq  401c00 <fprintf@plt>
  res = uv_run(loop, UV_RUN_DEFAULT);
  4032ef:	48 8d 05 12 33 20 00 	lea    0x203312(%rip),%rax        # 606608 <loop>
  4032f6:	48 8b 00             	mov    (%rax),%rax
  4032f9:	be 00 00 00 00       	mov    $0x0,%esi
  4032fe:	48 89 c7             	mov    %rax,%rdi
  403301:	e8 4a e6 ff ff       	callq  401950 <uv_run@plt>
  403306:	89 45 fc             	mov    %eax,-0x4(%rbp)
  EVP_cleanup();
  403309:	e8 62 e6 ff ff       	callq  401970 <EVP_cleanup@plt>
  ERR_free_strings();
  40330e:	e8 ad e6 ff ff       	callq  4019c0 <ERR_free_strings@plt>
  CRYPTO_cleanup_all_ex_data();
  403313:	e8 e8 e4 ff ff       	callq  401800 <CRYPTO_cleanup_all_ex_data@plt>
  
  return(res);
  403318:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
  40331b:	c9                   	leaveq 
  40331c:	c3                   	retq   

000000000040331d <handle_signal>:

void handle_signal(int s) {
  40331d:	55                   	push   %rbp
  40331e:	48 89 e5             	mov    %rsp,%rbp
  403321:	48 83 ec 10          	sub    $0x10,%rsp
  403325:	89 7d fc             	mov    %edi,-0x4(%rbp)
  
  fprintf(stderr, "received termination signal, quitting\n");
  403328:	48 8b 05 f1 2e 20 00 	mov    0x202ef1(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  40332f:	48 8b 00             	mov    (%rax),%rax
  403332:	48 89 c1             	mov    %rax,%rcx
  403335:	ba 26 00 00 00       	mov    $0x26,%edx
  40333a:	be 01 00 00 00       	mov    $0x1,%esi
  40333f:	48 8d 3d aa 20 00 00 	lea    0x20aa(%rip),%rdi        # 4053f0 <consonants+0x4f0>
  403346:	e8 65 e8 ff ff       	callq  401bb0 <fwrite@plt>
  onexit();
  40334b:	b8 00 00 00 00       	mov    $0x0,%eax
  403350:	e8 de eb ff ff       	callq  401f33 <onexit>
  exit(0);
  403355:	bf 00 00 00 00       	mov    $0x0,%edi
  40335a:	e8 01 e5 ff ff       	callq  401860 <exit@plt>

000000000040335f <process_option>:
}

void process_option(char* s, int allow_config)
{
  40335f:	55                   	push   %rbp
  403360:	48 89 e5             	mov    %rsp,%rbp
  403363:	48 81 ec 50 40 00 00 	sub    $0x4050,%rsp
  40336a:	48 89 bd b8 bf ff ff 	mov    %rdi,-0x4048(%rbp)
  403371:	89 b5 b4 bf ff ff    	mov    %esi,-0x404c(%rbp)
  char *left, *right, *p, *p1, *p2;
  size_t len, mode = 0;
  403377:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
  40337e:	00 
  FILE * conf;
  
  len = strlen(s);
  40337f:	48 8b 85 b8 bf ff ff 	mov    -0x4048(%rbp),%rax
  403386:	48 89 c7             	mov    %rax,%rdi
  403389:	e8 d2 e5 ff ff       	callq  401960 <strlen@plt>
  40338e:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
  if (len <= MAX_ARG_LENGTH) {
  403392:	48 81 7d d8 00 40 00 	cmpq   $0x4000,-0x28(%rbp)
  403399:	00 
  40339a:	0f 87 d9 03 00 00    	ja     403779 <process_option+0x41a>
    left = (char*)malloc((len + 1) * sizeof(char));
  4033a0:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  4033a4:	48 83 c0 01          	add    $0x1,%rax
  4033a8:	48 89 c7             	mov    %rax,%rdi
  4033ab:	e8 d0 e4 ff ff       	callq  401880 <malloc@plt>
  4033b0:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
    right = (char*)malloc((len + 1) * sizeof(char));
  4033b4:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  4033b8:	48 83 c0 01          	add    $0x1,%rax
  4033bc:	48 89 c7             	mov    %rax,%rdi
  4033bf:	e8 bc e4 ff ff       	callq  401880 <malloc@plt>
  4033c4:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    
    if (left == NULL || right == NULL) {
  4033c8:	48 83 7d d0 00       	cmpq   $0x0,-0x30(%rbp)
  4033cd:	74 07                	je     4033d6 <process_option+0x77>
  4033cf:	48 83 7d c8 00       	cmpq   $0x0,-0x38(%rbp)
  4033d4:	75 2d                	jne    403403 <process_option+0xa4>
      fprintf(stderr, "fatal: memory allocation failed. we shall not continue\n");
  4033d6:	48 8b 05 43 2e 20 00 	mov    0x202e43(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  4033dd:	48 8b 00             	mov    (%rax),%rax
  4033e0:	48 89 c1             	mov    %rax,%rcx
  4033e3:	ba 37 00 00 00       	mov    $0x37,%edx
  4033e8:	be 01 00 00 00       	mov    $0x1,%esi
  4033ed:	48 8d 3d 24 20 00 00 	lea    0x2024(%rip),%rdi        # 405418 <consonants+0x518>
  4033f4:	e8 b7 e7 ff ff       	callq  401bb0 <fwrite@plt>
      exit(-1);
  4033f9:	bf ff ff ff ff       	mov    $0xffffffff,%edi
  4033fe:	e8 5d e4 ff ff       	callq  401860 <exit@plt>
    }
    
    p1 = left;
  403403:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  403407:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    p2 = right;
  40340b:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  40340f:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    
    memset(left, 0, (len + 1) * sizeof(char));
  403413:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  403417:	48 8d 50 01          	lea    0x1(%rax),%rdx
  40341b:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  40341f:	be 00 00 00 00       	mov    $0x0,%esi
  403424:	48 89 c7             	mov    %rax,%rdi
  403427:	e8 c4 e3 ff ff       	callq  4017f0 <memset@plt>
    memset(right, 0, (len + 1) * sizeof(char));
  40342c:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  403430:	48 8d 50 01          	lea    0x1(%rax),%rdx
  403434:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  403438:	be 00 00 00 00       	mov    $0x0,%esi
  40343d:	48 89 c7             	mov    %rax,%rdi
  403440:	e8 ab e3 ff ff       	callq  4017f0 <memset@plt>
    
    mode = 0;
  403445:	48 c7 45 e0 00 00 00 	movq   $0x0,-0x20(%rbp)
  40344c:	00 
    for (p = s; *p; ++p) {
  40344d:	48 8b 85 b8 bf ff ff 	mov    -0x4048(%rbp),%rax
  403454:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  403458:	eb 54                	jmp    4034ae <process_option+0x14f>
      if (mode == 0 && *p == '=')
  40345a:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
  40345f:	75 15                	jne    403476 <process_option+0x117>
  403461:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403465:	0f b6 00             	movzbl (%rax),%eax
  403468:	3c 3d                	cmp    $0x3d,%al
  40346a:	75 0a                	jne    403476 <process_option+0x117>
        mode = 1;
  40346c:	48 c7 45 e0 01 00 00 	movq   $0x1,-0x20(%rbp)
  403473:	00 
  403474:	eb 33                	jmp    4034a9 <process_option+0x14a>
      else {
        if (mode == 0) 
  403476:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
  40347b:	75 17                	jne    403494 <process_option+0x135>
          *p1++ = *p;
  40347d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  403481:	48 8d 50 01          	lea    0x1(%rax),%rdx
  403485:	48 89 55 f0          	mov    %rdx,-0x10(%rbp)
  403489:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
  40348d:	0f b6 12             	movzbl (%rdx),%edx
  403490:	88 10                	mov    %dl,(%rax)
  403492:	eb 15                	jmp    4034a9 <process_option+0x14a>
        else
          *p2++ = *p;
  403494:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  403498:	48 8d 50 01          	lea    0x1(%rax),%rdx
  40349c:	48 89 55 e8          	mov    %rdx,-0x18(%rbp)
  4034a0:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
  4034a4:	0f b6 12             	movzbl (%rdx),%edx
  4034a7:	88 10                	mov    %dl,(%rax)
    
    memset(left, 0, (len + 1) * sizeof(char));
    memset(right, 0, (len + 1) * sizeof(char));
    
    mode = 0;
    for (p = s; *p; ++p) {
  4034a9:	48 83 45 f8 01       	addq   $0x1,-0x8(%rbp)
  4034ae:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4034b2:	0f b6 00             	movzbl (%rax),%eax
  4034b5:	84 c0                	test   %al,%al
  4034b7:	75 a1                	jne    40345a <process_option+0xfb>
        else
          *p2++ = *p;
      }
    }
    
    len = strlen(left);
  4034b9:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  4034bd:	48 89 c7             	mov    %rax,%rdi
  4034c0:	e8 9b e4 ff ff       	callq  401960 <strlen@plt>
  4034c5:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    if (!strcmp(left, "addr")) {
  4034c9:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  4034cd:	48 8d 35 7c 1f 00 00 	lea    0x1f7c(%rip),%rsi        # 405450 <consonants+0x550>
  4034d4:	48 89 c7             	mov    %rax,%rdi
  4034d7:	e8 24 e6 ff ff       	callq  401b00 <strcmp@plt>
  4034dc:	85 c0                	test   %eax,%eax
  4034de:	75 13                	jne    4034f3 <process_option+0x194>
      opt_addr = right;
  4034e0:	48 8d 05 d1 30 20 00 	lea    0x2030d1(%rip),%rax        # 6065b8 <opt_addr>
  4034e7:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
  4034eb:	48 89 10             	mov    %rdx,(%rax)
  4034ee:	e9 7a 02 00 00       	jmpq   40376d <process_option+0x40e>
    } else if (!strcmp(left, "port")) {
  4034f3:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  4034f7:	48 8d 35 57 1f 00 00 	lea    0x1f57(%rip),%rsi        # 405455 <consonants+0x555>
  4034fe:	48 89 c7             	mov    %rax,%rdi
  403501:	e8 fa e5 ff ff       	callq  401b00 <strcmp@plt>
  403506:	85 c0                	test   %eax,%eax
  403508:	75 13                	jne    40351d <process_option+0x1be>
      opt_port = right;
  40350a:	48 8d 05 ff 30 20 00 	lea    0x2030ff(%rip),%rax        # 606610 <opt_port>
  403511:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
  403515:	48 89 10             	mov    %rdx,(%rax)
  403518:	e9 50 02 00 00       	jmpq   40376d <process_option+0x40e>
    } else if (!strcmp(left, "daemonize")) {
  40351d:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  403521:	48 8d 35 32 1f 00 00 	lea    0x1f32(%rip),%rsi        # 40545a <consonants+0x55a>
  403528:	48 89 c7             	mov    %rax,%rdi
  40352b:	e8 d0 e5 ff ff       	callq  401b00 <strcmp@plt>
  403530:	85 c0                	test   %eax,%eax
  403532:	75 26                	jne    40355a <process_option+0x1fb>
      opt_daemonize = atoi(right);
  403534:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  403538:	48 89 c7             	mov    %rax,%rdi
  40353b:	e8 10 e5 ff ff       	callq  401a50 <atoi@plt>
  403540:	48 8d 15 81 30 20 00 	lea    0x203081(%rip),%rdx        # 6065c8 <opt_daemonize>
  403547:	89 02                	mov    %eax,(%rdx)
      free(right);
  403549:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  40354d:	48 89 c7             	mov    %rax,%rdi
  403550:	e8 eb e3 ff ff       	callq  401940 <free@plt>
  403555:	e9 13 02 00 00       	jmpq   40376d <process_option+0x40e>
    } else if (!strcmp(left, "cert")) {
  40355a:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  40355e:	48 8d 35 ff 1e 00 00 	lea    0x1eff(%rip),%rsi        # 405464 <consonants+0x564>
  403565:	48 89 c7             	mov    %rax,%rdi
  403568:	e8 93 e5 ff ff       	callq  401b00 <strcmp@plt>
  40356d:	85 c0                	test   %eax,%eax
  40356f:	75 13                	jne    403584 <process_option+0x225>
      opt_cert = right;
  403571:	48 8d 05 58 30 20 00 	lea    0x203058(%rip),%rax        # 6065d0 <opt_cert>
  403578:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
  40357c:	48 89 10             	mov    %rdx,(%rax)
  40357f:	e9 e9 01 00 00       	jmpq   40376d <process_option+0x40e>
    } else if (!strcmp(left, "cert-passphrase")) {
  403584:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  403588:	48 8d 35 da 1e 00 00 	lea    0x1eda(%rip),%rsi        # 405469 <consonants+0x569>
  40358f:	48 89 c7             	mov    %rax,%rdi
  403592:	e8 69 e5 ff ff       	callq  401b00 <strcmp@plt>
  403597:	85 c0                	test   %eax,%eax
  403599:	75 13                	jne    4035ae <process_option+0x24f>
      opt_cert_passphrase = right;
  40359b:	48 8d 05 4e 30 20 00 	lea    0x20304e(%rip),%rax        # 6065f0 <opt_cert_passphrase>
  4035a2:	48 8b 55 c8          	mov    -0x38(%rbp),%rdx
  4035a6:	48 89 10             	mov    %rdx,(%rax)
  4035a9:	e9 bf 01 00 00       	jmpq   40376d <process_option+0x40e>
    } else if (!strcmp(left, "threads")) {
  4035ae:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  4035b2:	48 8d 35 c0 1e 00 00 	lea    0x1ec0(%rip),%rsi        # 405479 <consonants+0x579>
  4035b9:	48 89 c7             	mov    %rax,%rdi
  4035bc:	e8 3f e5 ff ff       	callq  401b00 <strcmp@plt>
  4035c1:	85 c0                	test   %eax,%eax
  4035c3:	75 26                	jne    4035eb <process_option+0x28c>
      opt_threads = atoi(right);
  4035c5:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  4035c9:	48 89 c7             	mov    %rax,%rdi
  4035cc:	e8 7f e4 ff ff       	callq  401a50 <atoi@plt>
  4035d1:	48 8d 15 40 30 20 00 	lea    0x203040(%rip),%rdx        # 606618 <opt_threads>
  4035d8:	89 02                	mov    %eax,(%rdx)
      free(right);
  4035da:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  4035de:	48 89 c7             	mov    %rax,%rdi
  4035e1:	e8 5a e3 ff ff       	callq  401940 <free@plt>
  4035e6:	e9 82 01 00 00       	jmpq   40376d <process_option+0x40e>
    } else if (!strcmp(left, "queue-length")) {
  4035eb:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  4035ef:	48 8d 35 8b 1e 00 00 	lea    0x1e8b(%rip),%rsi        # 405481 <consonants+0x581>
  4035f6:	48 89 c7             	mov    %rax,%rdi
  4035f9:	e8 02 e5 ff ff       	callq  401b00 <strcmp@plt>
  4035fe:	85 c0                	test   %eax,%eax
  403600:	75 26                	jne    403628 <process_option+0x2c9>
      opt_queuelength = atoi(right);
  403602:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  403606:	48 89 c7             	mov    %rax,%rdi
  403609:	e8 42 e4 ff ff       	callq  401a50 <atoi@plt>
  40360e:	48 8d 15 b7 2f 20 00 	lea    0x202fb7(%rip),%rdx        # 6065cc <opt_queuelength>
  403615:	89 02                	mov    %eax,(%rdx)
      free(right);
  403617:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  40361b:	48 89 c7             	mov    %rax,%rdi
  40361e:	e8 1d e3 ff ff       	callq  401940 <free@plt>
  403623:	e9 45 01 00 00       	jmpq   40376d <process_option+0x40e>
    } else if (allow_config && !strcmp(left, "config")) {
  403628:	83 bd b4 bf ff ff 00 	cmpl   $0x0,-0x404c(%rbp)
  40362f:	0f 84 08 01 00 00    	je     40373d <process_option+0x3de>
  403635:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  403639:	48 8d 35 4e 1e 00 00 	lea    0x1e4e(%rip),%rsi        # 40548e <consonants+0x58e>
  403640:	48 89 c7             	mov    %rax,%rdi
  403643:	e8 b8 e4 ff ff       	callq  401b00 <strcmp@plt>
  403648:	85 c0                	test   %eax,%eax
  40364a:	0f 85 ed 00 00 00    	jne    40373d <process_option+0x3de>
      conf = fopen(right, "r");
  403650:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  403654:	48 8d 35 3a 1e 00 00 	lea    0x1e3a(%rip),%rsi        # 405495 <consonants+0x595>
  40365b:	48 89 c7             	mov    %rax,%rdi
  40365e:	e8 2d e2 ff ff       	callq  401890 <fopen@plt>
  403663:	48 89 45 c0          	mov    %rax,-0x40(%rbp)
      if (!conf) {
  403667:	48 83 7d c0 00       	cmpq   $0x0,-0x40(%rbp)
  40366c:	75 34                	jne    4036a2 <process_option+0x343>
        perror("fopen()");
  40366e:	48 8d 3d 22 1e 00 00 	lea    0x1e22(%rip),%rdi        # 405497 <consonants+0x597>
  403675:	e8 66 e5 ff ff       	callq  401be0 <perror@plt>
        fprintf(stderr, "could not open config file\n");
  40367a:	48 8b 05 9f 2b 20 00 	mov    0x202b9f(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  403681:	48 8b 00             	mov    (%rax),%rax
  403684:	48 89 c1             	mov    %rax,%rcx
  403687:	ba 1b 00 00 00       	mov    $0x1b,%edx
  40368c:	be 01 00 00 00       	mov    $0x1,%esi
  403691:	48 8d 3d 07 1e 00 00 	lea    0x1e07(%rip),%rdi        # 40549f <consonants+0x59f>
  403698:	e8 13 e5 ff ff       	callq  401bb0 <fwrite@plt>
    } else if (!strcmp(left, "queue-length")) {
      opt_queuelength = atoi(right);
      free(right);
    } else if (allow_config && !strcmp(left, "config")) {
      conf = fopen(right, "r");
      if (!conf) {
  40369d:	e9 cb 00 00 00       	jmpq   40376d <process_option+0x40e>
        perror("fopen()");
        fprintf(stderr, "could not open config file\n");
      } else {
        char line[CONFIG_MAXLINESIZE];
        
        while (!feof(conf)) {
  4036a2:	eb 6f                	jmp    403713 <process_option+0x3b4>
          memset(line, 0, sizeof(line));
  4036a4:	48 8d 85 c0 bf ff ff 	lea    -0x4040(%rbp),%rax
  4036ab:	ba 00 40 00 00       	mov    $0x4000,%edx
  4036b0:	be 00 00 00 00       	mov    $0x0,%esi
  4036b5:	48 89 c7             	mov    %rax,%rdi
  4036b8:	e8 33 e1 ff ff       	callq  4017f0 <memset@plt>
          fgets(line, CONFIG_MAXLINESIZE * sizeof(char), conf);
  4036bd:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
  4036c1:	48 8d 85 c0 bf ff ff 	lea    -0x4040(%rbp),%rax
  4036c8:	be 00 40 00 00       	mov    $0x4000,%esi
  4036cd:	48 89 c7             	mov    %rax,%rdi
  4036d0:	e8 2b e2 ff ff       	callq  401900 <fgets@plt>
          len = strlen(line);
  4036d5:	48 8d 85 c0 bf ff ff 	lea    -0x4040(%rbp),%rax
  4036dc:	48 89 c7             	mov    %rax,%rdi
  4036df:	e8 7c e2 ff ff       	callq  401960 <strlen@plt>
  4036e4:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
          
          if (len) {
  4036e8:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
  4036ed:	74 24                	je     403713 <process_option+0x3b4>
            line[len - 1] = '\0';
  4036ef:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  4036f3:	48 83 e8 01          	sub    $0x1,%rax
  4036f7:	c6 84 05 c0 bf ff ff 	movb   $0x0,-0x4040(%rbp,%rax,1)
  4036fe:	00 
            process_option(line, 0);
  4036ff:	48 8d 85 c0 bf ff ff 	lea    -0x4040(%rbp),%rax
  403706:	be 00 00 00 00       	mov    $0x0,%esi
  40370b:	48 89 c7             	mov    %rax,%rdi
  40370e:	e8 4c fc ff ff       	callq  40335f <process_option>
        perror("fopen()");
        fprintf(stderr, "could not open config file\n");
      } else {
        char line[CONFIG_MAXLINESIZE];
        
        while (!feof(conf)) {
  403713:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
  403717:	48 89 c7             	mov    %rax,%rdi
  40371a:	e8 31 e4 ff ff       	callq  401b50 <feof@plt>
  40371f:	85 c0                	test   %eax,%eax
  403721:	74 81                	je     4036a4 <process_option+0x345>
          if (len) {
            line[len - 1] = '\0';
            process_option(line, 0);
          }
        }
        free(right);
  403723:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  403727:	48 89 c7             	mov    %rax,%rdi
  40372a:	e8 11 e2 ff ff       	callq  401940 <free@plt>
        fclose(conf);
  40372f:	48 8b 45 c0          	mov    -0x40(%rbp),%rax
  403733:	48 89 c7             	mov    %rax,%rdi
  403736:	e8 25 e4 ff ff       	callq  401b60 <fclose@plt>
    } else if (!strcmp(left, "queue-length")) {
      opt_queuelength = atoi(right);
      free(right);
    } else if (allow_config && !strcmp(left, "config")) {
      conf = fopen(right, "r");
      if (!conf) {
  40373b:	eb 30                	jmp    40376d <process_option+0x40e>
        }
        free(right);
        fclose(conf);
      }
    } else {
      fprintf(stderr, "Unknown option: %s\n", left);
  40373d:	48 8b 05 dc 2a 20 00 	mov    0x202adc(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  403744:	48 8b 00             	mov    (%rax),%rax
  403747:	48 8b 55 d0          	mov    -0x30(%rbp),%rdx
  40374b:	48 8d 35 69 1d 00 00 	lea    0x1d69(%rip),%rsi        # 4054bb <consonants+0x5bb>
  403752:	48 89 c7             	mov    %rax,%rdi
  403755:	b8 00 00 00 00       	mov    $0x0,%eax
  40375a:	e8 a1 e4 ff ff       	callq  401c00 <fprintf@plt>
      free(right);
  40375f:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  403763:	48 89 c7             	mov    %rax,%rdi
  403766:	e8 d5 e1 ff ff       	callq  401940 <free@plt>
      return;
  40376b:	eb 0d                	jmp    40377a <process_option+0x41b>
    }
    free(left);
  40376d:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  403771:	48 89 c7             	mov    %rax,%rdi
  403774:	e8 c7 e1 ff ff       	callq  401940 <free@plt>
  }
  
  return;
  403779:	90                   	nop
}
  40377a:	c9                   	leaveq 
  40377b:	c3                   	retq   

000000000040377c <defaults>:

void defaults()
{
  40377c:	55                   	push   %rbp
  40377d:	48 89 e5             	mov    %rsp,%rbp
  opt_daemonize = 1;
  403780:	48 8d 05 41 2e 20 00 	lea    0x202e41(%rip),%rax        # 6065c8 <opt_daemonize>
  403787:	c7 00 01 00 00 00    	movl   $0x1,(%rax)
  opt_threads = 10;
  40378d:	48 8d 05 84 2e 20 00 	lea    0x202e84(%rip),%rax        # 606618 <opt_threads>
  403794:	c7 00 0a 00 00 00    	movl   $0xa,(%rax)
  opt_queuelength = 40;
  40379a:	48 8d 05 2b 2e 20 00 	lea    0x202e2b(%rip),%rax        # 6065cc <opt_queuelength>
  4037a1:	c7 00 28 00 00 00    	movl   $0x28,(%rax)
}
  4037a7:	5d                   	pop    %rbp
  4037a8:	c3                   	retq   

00000000004037a9 <main>:

int main(int argc, char** argv)
{
  4037a9:	55                   	push   %rbp
  4037aa:	48 89 e5             	mov    %rsp,%rbp
  4037ad:	48 81 ec c0 00 00 00 	sub    $0xc0,%rsp
  4037b4:	89 bd 4c ff ff ff    	mov    %edi,-0xb4(%rbp)
  4037ba:	48 89 b5 40 ff ff ff 	mov    %rsi,-0xc0(%rbp)
  
  return(0);*/
  
  char** arg;
  
  ERR_load_crypto_strings();
  4037c1:	e8 5a e1 ff ff       	callq  401920 <ERR_load_crypto_strings@plt>
  OpenSSL_add_all_ciphers();
  4037c6:	e8 05 e4 ff ff       	callq  401bd0 <OpenSSL_add_all_ciphers@plt>
  if (!tokinit(MAX_TOKENS, MAX_TOKEN_BUCKETS)) {
  4037cb:	be c8 00 00 00       	mov    $0xc8,%esi
  4037d0:	bf 64 00 00 00       	mov    $0x64,%edi
  4037d5:	e8 55 0a 00 00       	callq  40422f <tokinit>
  4037da:	85 c0                	test   %eax,%eax
  4037dc:	75 2d                	jne    40380b <main+0x62>
    fprintf(stderr, "fatal: could not load the token bank\n");
  4037de:	48 8b 05 3b 2a 20 00 	mov    0x202a3b(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  4037e5:	48 8b 00             	mov    (%rax),%rax
  4037e8:	48 89 c1             	mov    %rax,%rcx
  4037eb:	ba 25 00 00 00       	mov    $0x25,%edx
  4037f0:	be 01 00 00 00       	mov    $0x1,%esi
  4037f5:	48 8d 3d d4 1c 00 00 	lea    0x1cd4(%rip),%rdi        # 4054d0 <consonants+0x5d0>
  4037fc:	e8 af e3 ff ff       	callq  401bb0 <fwrite@plt>
    exit(-1);
  403801:	bf ff ff ff ff       	mov    $0xffffffff,%edi
  403806:	e8 55 e0 ff ff       	callq  401860 <exit@plt>
  }
  
  defaults();
  40380b:	b8 00 00 00 00       	mov    $0x0,%eax
  403810:	e8 67 ff ff ff       	callq  40377c <defaults>
  for (arg = argv + 1; arg < argv + argc; ++arg) {
  403815:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
  40381c:	48 83 c0 08          	add    $0x8,%rax
  403820:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  403824:	eb 19                	jmp    40383f <main+0x96>
    process_option(*arg, 1);
  403826:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40382a:	48 8b 00             	mov    (%rax),%rax
  40382d:	be 01 00 00 00       	mov    $0x1,%esi
  403832:	48 89 c7             	mov    %rax,%rdi
  403835:	e8 25 fb ff ff       	callq  40335f <process_option>
    fprintf(stderr, "fatal: could not load the token bank\n");
    exit(-1);
  }
  
  defaults();
  for (arg = argv + 1; arg < argv + argc; ++arg) {
  40383a:	48 83 45 f8 08       	addq   $0x8,-0x8(%rbp)
  40383f:	8b 85 4c ff ff ff    	mov    -0xb4(%rbp),%eax
  403845:	48 98                	cltq   
  403847:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
  40384e:	00 
  40384f:	48 8b 85 40 ff ff ff 	mov    -0xc0(%rbp),%rax
  403856:	48 01 d0             	add    %rdx,%rax
  403859:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
  40385d:	77 c7                	ja     403826 <main+0x7d>
    process_option(*arg, 1);
  }
  
  tv.tv_sec = RECEIVE_TIMEOUT;
  40385f:	48 8d 05 7a 2d 20 00 	lea    0x202d7a(%rip),%rax        # 6065e0 <tv>
  403866:	48 c7 00 1e 00 00 00 	movq   $0x1e,(%rax)
  tv.tv_usec = 0;
  40386d:	48 8d 05 6c 2d 20 00 	lea    0x202d6c(%rip),%rax        # 6065e0 <tv>
  403874:	48 c7 40 08 00 00 00 	movq   $0x0,0x8(%rax)
  40387b:	00 
  
  lin.l_onoff = 1;
  40387c:	48 8d 05 75 2d 20 00 	lea    0x202d75(%rip),%rax        # 6065f8 <lin>
  403883:	c7 00 01 00 00 00    	movl   $0x1,(%rax)
  lin.l_linger = LINGER_SECONDS;
  403889:	48 8d 05 68 2d 20 00 	lea    0x202d68(%rip),%rax        # 6065f8 <lin>
  403890:	c7 40 04 0a 00 00 00 	movl   $0xa,0x4(%rax)
  
  if (!opt_cert) {
  403897:	48 8d 05 32 2d 20 00 	lea    0x202d32(%rip),%rax        # 6065d0 <opt_cert>
  40389e:	48 8b 00             	mov    (%rax),%rax
  4038a1:	48 85 c0             	test   %rax,%rax
  4038a4:	75 2d                	jne    4038d3 <main+0x12a>
    fprintf(stderr, "fatal: no certificate provided\n");
  4038a6:	48 8b 05 73 29 20 00 	mov    0x202973(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  4038ad:	48 8b 00             	mov    (%rax),%rax
  4038b0:	48 89 c1             	mov    %rax,%rcx
  4038b3:	ba 1f 00 00 00       	mov    $0x1f,%edx
  4038b8:	be 01 00 00 00       	mov    $0x1,%esi
  4038bd:	48 8d 3d 34 1c 00 00 	lea    0x1c34(%rip),%rdi        # 4054f8 <consonants+0x5f8>
  4038c4:	e8 e7 e2 ff ff       	callq  401bb0 <fwrite@plt>
    return(-1);
  4038c9:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  4038ce:	e9 49 01 00 00       	jmpq   403a1c <main+0x273>
  }
  
  FILE * f = fopen(opt_cert, "r");
  4038d3:	48 8d 05 f6 2c 20 00 	lea    0x202cf6(%rip),%rax        # 6065d0 <opt_cert>
  4038da:	48 8b 00             	mov    (%rax),%rax
  4038dd:	48 8d 35 b1 1b 00 00 	lea    0x1bb1(%rip),%rsi        # 405495 <consonants+0x595>
  4038e4:	48 89 c7             	mov    %rax,%rdi
  4038e7:	e8 a4 df ff ff       	callq  401890 <fopen@plt>
  4038ec:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  if (!f) {
  4038f0:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
  4038f5:	75 32                	jne    403929 <main+0x180>
    fprintf(stderr, "fatal: could not open certificate file '%s' for reading\n", opt_cert);
  4038f7:	48 8d 05 d2 2c 20 00 	lea    0x202cd2(%rip),%rax        # 6065d0 <opt_cert>
  4038fe:	48 8b 10             	mov    (%rax),%rdx
  403901:	48 8b 05 18 29 20 00 	mov    0x202918(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  403908:	48 8b 00             	mov    (%rax),%rax
  40390b:	48 8d 35 06 1c 00 00 	lea    0x1c06(%rip),%rsi        # 405518 <consonants+0x618>
  403912:	48 89 c7             	mov    %rax,%rdi
  403915:	b8 00 00 00 00       	mov    $0x0,%eax
  40391a:	e8 e1 e2 ff ff       	callq  401c00 <fprintf@plt>
    return(-1);
  40391f:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  403924:	e9 f3 00 00 00       	jmpq   403a1c <main+0x273>
  }
  
  if (PEM_read_RSAPrivateKey(f, &server_private, NULL, opt_cert_passphrase) == NULL) {
  403929:	48 8d 05 c0 2c 20 00 	lea    0x202cc0(%rip),%rax        # 6065f0 <opt_cert_passphrase>
  403930:	48 8b 10             	mov    (%rax),%rdx
  403933:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  403937:	48 89 d1             	mov    %rdx,%rcx
  40393a:	ba 00 00 00 00       	mov    $0x0,%edx
  40393f:	48 8d 35 da 2c 20 00 	lea    0x202cda(%rip),%rsi        # 606620 <server_private>
  403946:	48 89 c7             	mov    %rax,%rdi
  403949:	e8 c2 e0 ff ff       	callq  401a10 <PEM_read_RSAPrivateKey@plt>
  40394e:	48 85 c0             	test   %rax,%rax
  403951:	75 38                	jne    40398b <main+0x1e2>
    fprintf(stderr, "fatal: failed reading PEM file: %s\n", ERR_reason_error_string(ERR_get_error()));
  403953:	e8 28 e1 ff ff       	callq  401a80 <ERR_get_error@plt>
  403958:	48 89 c7             	mov    %rax,%rdi
  40395b:	e8 e0 e2 ff ff       	callq  401c40 <ERR_reason_error_string@plt>
  403960:	48 89 c2             	mov    %rax,%rdx
  403963:	48 8b 05 b6 28 20 00 	mov    0x2028b6(%rip),%rax        # 606220 <_DYNAMIC+0x208>
  40396a:	48 8b 00             	mov    (%rax),%rax
  40396d:	48 8d 35 e4 1b 00 00 	lea    0x1be4(%rip),%rsi        # 405558 <consonants+0x658>
  403974:	48 89 c7             	mov    %rax,%rdi
  403977:	b8 00 00 00 00       	mov    $0x0,%eax
  40397c:	e8 7f e2 ff ff       	callq  401c00 <fprintf@plt>
    return(-1);
  403981:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  403986:	e9 91 00 00 00       	jmpq   403a1c <main+0x273>
  }
  fclose(f);
  40398b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  40398f:	48 89 c7             	mov    %rax,%rdi
  403992:	e8 c9 e1 ff ff       	callq  401b60 <fclose@plt>
  
  srand(time(NULL));
  403997:	bf 00 00 00 00       	mov    $0x0,%edi
  40399c:	e8 df e2 ff ff       	callq  401c80 <time@plt>
  4039a1:	89 c7                	mov    %eax,%edi
  4039a3:	e8 78 e1 ff ff       	callq  401b20 <srand@plt>
  
  struct sigaction siginth;  
  siginth.sa_handler = handle_signal;
  4039a8:	48 8d 05 6e f9 ff ff 	lea    -0x692(%rip),%rax        # 40331d <handle_signal>
  4039af:	48 89 85 50 ff ff ff 	mov    %rax,-0xb0(%rbp)
  sigemptyset(&siginth.sa_mask);
  4039b6:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
  4039bd:	48 83 c0 08          	add    $0x8,%rax
  4039c1:	48 89 c7             	mov    %rax,%rdi
  4039c4:	e8 d7 e1 ff ff       	callq  401ba0 <sigemptyset@plt>
  siginth.sa_flags = 0;
  4039c9:	c7 45 d8 00 00 00 00 	movl   $0x0,-0x28(%rbp)
  sigaction(SIGINT, &siginth, NULL);
  4039d0:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
  4039d7:	ba 00 00 00 00       	mov    $0x0,%edx
  4039dc:	48 89 c6             	mov    %rax,%rsi
  4039df:	bf 02 00 00 00       	mov    $0x2,%edi
  4039e4:	e8 17 e0 ff ff       	callq  401a00 <sigaction@plt>
  
  if (opt_daemonize) {
  4039e9:	48 8d 05 d8 2b 20 00 	lea    0x202bd8(%rip),%rax        # 6065c8 <opt_daemonize>
  4039f0:	8b 00                	mov    (%rax),%eax
  4039f2:	85 c0                	test   %eax,%eax
  4039f4:	74 1c                	je     403a12 <main+0x269>
    if (fork() == 0) {
  4039f6:	e8 95 e1 ff ff       	callq  401b90 <fork@plt>
  4039fb:	85 c0                	test   %eax,%eax
  4039fd:	75 0c                	jne    403a0b <main+0x262>
      return( server() );
  4039ff:	b8 00 00 00 00       	mov    $0x0,%eax
  403a04:	e8 cc f6 ff ff       	callq  4030d5 <server>
  403a09:	eb 11                	jmp    403a1c <main+0x273>
    } else {
      return(0);
  403a0b:	b8 00 00 00 00       	mov    $0x0,%eax
  403a10:	eb 0a                	jmp    403a1c <main+0x273>
    }
  } else {
    return( server() );
  403a12:	b8 00 00 00 00       	mov    $0x0,%eax
  403a17:	e8 b9 f6 ff ff       	callq  4030d5 <server>
  }
}
  403a1c:	c9                   	leaveq 
  403a1d:	c3                   	retq   

0000000000403a1e <mgk_memeql>:
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00 };
    
int mgk_memeql(const byte* a, const byte* b, length_t count)
{
  403a1e:	55                   	push   %rbp
  403a1f:	48 89 e5             	mov    %rsp,%rbp
  403a22:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  403a26:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  403a2a:	89 55 dc             	mov    %edx,-0x24(%rbp)
  int eql = 1;
  403a2d:	c7 45 fc 01 00 00 00 	movl   $0x1,-0x4(%rbp)
  unsigned int i;
  for (i = 0; i < count; ++i)
  403a34:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
  403a3b:	eb 29                	jmp    403a66 <mgk_memeql+0x48>
    if (a[i] != b[i]) eql = 0;
  403a3d:	8b 55 f8             	mov    -0x8(%rbp),%edx
  403a40:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  403a44:	48 01 d0             	add    %rdx,%rax
  403a47:	0f b6 10             	movzbl (%rax),%edx
  403a4a:	8b 4d f8             	mov    -0x8(%rbp),%ecx
  403a4d:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  403a51:	48 01 c8             	add    %rcx,%rax
  403a54:	0f b6 00             	movzbl (%rax),%eax
  403a57:	38 c2                	cmp    %al,%dl
  403a59:	74 07                	je     403a62 <mgk_memeql+0x44>
  403a5b:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    
int mgk_memeql(const byte* a, const byte* b, length_t count)
{
  int eql = 1;
  unsigned int i;
  for (i = 0; i < count; ++i)
  403a62:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
  403a66:	8b 45 f8             	mov    -0x8(%rbp),%eax
  403a69:	3b 45 dc             	cmp    -0x24(%rbp),%eax
  403a6c:	72 cf                	jb     403a3d <mgk_memeql+0x1f>
    if (a[i] != b[i]) eql = 0;
  return(eql);
  403a6e:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
  403a71:	5d                   	pop    %rbp
  403a72:	c3                   	retq   

0000000000403a73 <mgk_fill_magic>:

void mgk_fill_magic(byte* buf, magic_type type)
{
  403a73:	55                   	push   %rbp
  403a74:	48 89 e5             	mov    %rsp,%rbp
  403a77:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  403a7b:	89 75 f4             	mov    %esi,-0xc(%rbp)
  buf[0] = 'M';
  403a7e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403a82:	c6 00 4d             	movb   $0x4d,(%rax)
  buf[1] = 'G';
  403a85:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403a89:	48 83 c0 01          	add    $0x1,%rax
  403a8d:	c6 00 47             	movb   $0x47,(%rax)
  buf[2] = 'K';
  403a90:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403a94:	48 83 c0 02          	add    $0x2,%rax
  403a98:	c6 00 4b             	movb   $0x4b,(%rax)
  buf[3] = 0xEA;
  403a9b:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403a9f:	48 83 c0 03          	add    $0x3,%rax
  403aa3:	c6 00 ea             	movb   $0xea,(%rax)
  buf[4] = 0xCA;
  403aa6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403aaa:	48 83 c0 04          	add    $0x4,%rax
  403aae:	c6 00 ca             	movb   $0xca,(%rax)
  switch (type) {
  403ab1:	83 7d f4 04          	cmpl   $0x4,-0xc(%rbp)
  403ab5:	77 65                	ja     403b1c <mgk_fill_magic+0xa9>
  403ab7:	8b 45 f4             	mov    -0xc(%rbp),%eax
  403aba:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
  403ac1:	00 
  403ac2:	48 8d 05 17 1b 00 00 	lea    0x1b17(%rip),%rax        # 4055e0 <MEGAKI_SERVICE_UNAVAILABLE_ERROR+0x20>
  403ac9:	8b 04 02             	mov    (%rdx,%rax,1),%eax
  403acc:	48 63 d0             	movslq %eax,%rdx
  403acf:	48 8d 05 0a 1b 00 00 	lea    0x1b0a(%rip),%rax        # 4055e0 <MEGAKI_SERVICE_UNAVAILABLE_ERROR+0x20>
  403ad6:	48 01 d0             	add    %rdx,%rax
  403ad9:	ff e0                	jmpq   *%rax
  case magic_syn: buf[5] = 0x01; break;
  403adb:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403adf:	48 83 c0 05          	add    $0x5,%rax
  403ae3:	c6 00 01             	movb   $0x1,(%rax)
  403ae6:	eb 40                	jmp    403b28 <mgk_fill_magic+0xb5>
  case magic_synack: buf[5] = 0x02; break;
  403ae8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403aec:	48 83 c0 05          	add    $0x5,%rax
  403af0:	c6 00 02             	movb   $0x2,(%rax)
  403af3:	eb 33                	jmp    403b28 <mgk_fill_magic+0xb5>
  case magic_ack: buf[5] = 0x03; break;
  403af5:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403af9:	48 83 c0 05          	add    $0x5,%rax
  403afd:	c6 00 03             	movb   $0x3,(%rax)
  403b00:	eb 26                	jmp    403b28 <mgk_fill_magic+0xb5>
  case magic_msg: buf[5] = 0x04; break;
  403b02:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403b06:	48 83 c0 05          	add    $0x5,%rax
  403b0a:	c6 00 04             	movb   $0x4,(%rax)
  403b0d:	eb 19                	jmp    403b28 <mgk_fill_magic+0xb5>
  case magic_restart: buf[5] = 0x05; break;
  403b0f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403b13:	48 83 c0 05          	add    $0x5,%rax
  403b17:	c6 00 05             	movb   $0x5,(%rax)
  403b1a:	eb 0c                	jmp    403b28 <mgk_fill_magic+0xb5>
  default: buf[5] = 0xFF; break;
  403b1c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403b20:	48 83 c0 05          	add    $0x5,%rax
  403b24:	c6 00 ff             	movb   $0xff,(%rax)
  403b27:	90                   	nop
  }
}
  403b28:	5d                   	pop    %rbp
  403b29:	c3                   	retq   

0000000000403b2a <mgk_check_magic>:

magic_type mgk_check_magic(const byte* buf)
{
  403b2a:	55                   	push   %rbp
  403b2b:	48 89 e5             	mov    %rsp,%rbp
  403b2e:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  if (buf[0] == 'M' && buf[1] == 'G' && buf[2] == 'K' &&
  403b32:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403b36:	0f b6 00             	movzbl (%rax),%eax
  403b39:	3c 4d                	cmp    $0x4d,%al
  403b3b:	0f 85 a0 00 00 00    	jne    403be1 <mgk_check_magic+0xb7>
  403b41:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403b45:	48 83 c0 01          	add    $0x1,%rax
  403b49:	0f b6 00             	movzbl (%rax),%eax
  403b4c:	3c 47                	cmp    $0x47,%al
  403b4e:	0f 85 8d 00 00 00    	jne    403be1 <mgk_check_magic+0xb7>
  403b54:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403b58:	48 83 c0 02          	add    $0x2,%rax
  403b5c:	0f b6 00             	movzbl (%rax),%eax
  403b5f:	3c 4b                	cmp    $0x4b,%al
  403b61:	75 7e                	jne    403be1 <mgk_check_magic+0xb7>
      buf[3] == 0xEA && buf[4] == 0xCA) {
  403b63:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403b67:	48 83 c0 03          	add    $0x3,%rax
  403b6b:	0f b6 00             	movzbl (%rax),%eax
  }
}

magic_type mgk_check_magic(const byte* buf)
{
  if (buf[0] == 'M' && buf[1] == 'G' && buf[2] == 'K' &&
  403b6e:	3c ea                	cmp    $0xea,%al
  403b70:	75 6f                	jne    403be1 <mgk_check_magic+0xb7>
      buf[3] == 0xEA && buf[4] == 0xCA) {
  403b72:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403b76:	48 83 c0 04          	add    $0x4,%rax
  403b7a:	0f b6 00             	movzbl (%rax),%eax
  403b7d:	3c ca                	cmp    $0xca,%al
  403b7f:	75 60                	jne    403be1 <mgk_check_magic+0xb7>
    switch (buf[5]) {
  403b81:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403b85:	48 83 c0 05          	add    $0x5,%rax
  403b89:	0f b6 00             	movzbl (%rax),%eax
  403b8c:	0f b6 c0             	movzbl %al,%eax
  403b8f:	83 f8 05             	cmp    $0x5,%eax
  403b92:	77 46                	ja     403bda <mgk_check_magic+0xb0>
  403b94:	89 c0                	mov    %eax,%eax
  403b96:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
  403b9d:	00 
  403b9e:	48 8d 05 4f 1a 00 00 	lea    0x1a4f(%rip),%rax        # 4055f4 <MEGAKI_SERVICE_UNAVAILABLE_ERROR+0x34>
  403ba5:	8b 04 02             	mov    (%rdx,%rax,1),%eax
  403ba8:	48 63 d0             	movslq %eax,%rdx
  403bab:	48 8d 05 42 1a 00 00 	lea    0x1a42(%rip),%rax        # 4055f4 <MEGAKI_SERVICE_UNAVAILABLE_ERROR+0x34>
  403bb2:	48 01 d0             	add    %rdx,%rax
  403bb5:	ff e0                	jmpq   *%rax
    case 0x01: return magic_syn;
  403bb7:	b8 00 00 00 00       	mov    $0x0,%eax
  403bbc:	eb 28                	jmp    403be6 <mgk_check_magic+0xbc>
    case 0x02: return magic_synack;
  403bbe:	b8 01 00 00 00       	mov    $0x1,%eax
  403bc3:	eb 21                	jmp    403be6 <mgk_check_magic+0xbc>
    case 0x03: return magic_ack;
  403bc5:	b8 02 00 00 00       	mov    $0x2,%eax
  403bca:	eb 1a                	jmp    403be6 <mgk_check_magic+0xbc>
    case 0x04: return magic_msg;
  403bcc:	b8 03 00 00 00       	mov    $0x3,%eax
  403bd1:	eb 13                	jmp    403be6 <mgk_check_magic+0xbc>
    case 0x05: return magic_restart;
  403bd3:	b8 04 00 00 00       	mov    $0x4,%eax
  403bd8:	eb 0c                	jmp    403be6 <mgk_check_magic+0xbc>
    default: return magic_invalid;
  403bda:	b8 05 00 00 00       	mov    $0x5,%eax
  403bdf:	eb 05                	jmp    403be6 <mgk_check_magic+0xbc>
    }
  } else return magic_invalid;
  403be1:	b8 05 00 00 00       	mov    $0x5,%eax
}
  403be6:	5d                   	pop    %rbp
  403be7:	c3                   	retq   

0000000000403be8 <popmin>:
#define HEAP_LCHILD(a)      (2*(a))
#define HEAP_RCHILD(a)      (2*(a)+1)
#define HEAP_PARENT(a)      ((a)/2)

token_idx popmin(tokenbucket** lastbucket)
{
  403be8:	55                   	push   %rbp
  403be9:	48 89 e5             	mov    %rsp,%rbp
  403bec:	48 83 ec 30          	sub    $0x30,%rsp
  403bf0:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
  token_idx minid = tokenheap[HEAP_ROOT];
  403bf4:	48 8d 05 35 2a 20 00 	lea    0x202a35(%rip),%rax        # 606630 <tokenheap>
  403bfb:	48 8b 00             	mov    (%rax),%rax
  403bfe:	0f b7 40 02          	movzwl 0x2(%rax),%eax
  403c02:	66 89 45 fe          	mov    %ax,-0x2(%rbp)
  heapswap(HEAP_ROOT, tokencount + HEAP_ROOT - 1);
  403c06:	48 8d 05 33 2a 20 00 	lea    0x202a33(%rip),%rax        # 606640 <tokencount>
  403c0d:	8b 00                	mov    (%rax),%eax
  403c0f:	0f b7 c0             	movzwl %ax,%eax
  403c12:	89 c6                	mov    %eax,%esi
  403c14:	bf 01 00 00 00       	mov    $0x1,%edi
  403c19:	e8 ae 04 00 00       	callq  4040cc <heapswap>
  
  --tokencount;
  403c1e:	48 8d 05 1b 2a 20 00 	lea    0x202a1b(%rip),%rax        # 606640 <tokencount>
  403c25:	8b 00                	mov    (%rax),%eax
  403c27:	8d 50 ff             	lea    -0x1(%rax),%edx
  403c2a:	48 8d 05 0f 2a 20 00 	lea    0x202a0f(%rip),%rax        # 606640 <tokencount>
  403c31:	89 10                	mov    %edx,(%rax)
  heapifydown(HEAP_ROOT);
  403c33:	bf 01 00 00 00       	mov    $0x1,%edi
  403c38:	e8 7b 02 00 00       	callq  403eb8 <heapifydown>
  ++tokencount;
  403c3d:	48 8d 05 fc 29 20 00 	lea    0x2029fc(%rip),%rax        # 606640 <tokencount>
  403c44:	8b 00                	mov    (%rax),%eax
  403c46:	8d 50 01             	lea    0x1(%rax),%edx
  403c49:	48 8d 05 f0 29 20 00 	lea    0x2029f0(%rip),%rax        # 606640 <tokencount>
  403c50:	89 10                	mov    %edx,(%rax)
  //if (tokencount==100&&tokenheap[1]==tokenheap[100])raise(SIGINT);
  token_idx h = hash(tokenlist[minid].entry.token);
  403c52:	48 8d 05 df 29 20 00 	lea    0x2029df(%rip),%rax        # 606638 <tokenlist>
  403c59:	48 8b 10             	mov    (%rax),%rdx
  403c5c:	0f b7 45 fe          	movzwl -0x2(%rbp),%eax
  403c60:	48 c1 e0 03          	shl    $0x3,%rax
  403c64:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
  403c6b:	00 
  403c6c:	48 29 c1             	sub    %rax,%rcx
  403c6f:	48 89 c8             	mov    %rcx,%rax
  403c72:	48 01 d0             	add    %rdx,%rax
  403c75:	48 89 c7             	mov    %rax,%rdi
  403c78:	e8 57 05 00 00       	callq  4041d4 <hash>
  403c7d:	66 89 45 fc          	mov    %ax,-0x4(%rbp)
  tokenbucket *pp, *pb = findh(tokenlist[minid].entry.token, h, &pp);
  403c81:	0f b7 4d fc          	movzwl -0x4(%rbp),%ecx
  403c85:	48 8d 05 ac 29 20 00 	lea    0x2029ac(%rip),%rax        # 606638 <tokenlist>
  403c8c:	48 8b 10             	mov    (%rax),%rdx
  403c8f:	0f b7 45 fe          	movzwl -0x2(%rbp),%eax
  403c93:	48 c1 e0 03          	shl    $0x3,%rax
  403c97:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
  403c9e:	00 
  403c9f:	48 29 c6             	sub    %rax,%rsi
  403ca2:	48 89 f0             	mov    %rsi,%rax
  403ca5:	48 01 d0             	add    %rdx,%rax
  403ca8:	48 8d 55 e8          	lea    -0x18(%rbp),%rdx
  403cac:	89 ce                	mov    %ecx,%esi
  403cae:	48 89 c7             	mov    %rax,%rdi
  403cb1:	e8 8a 00 00 00       	callq  403d40 <findh>
  403cb6:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  if (pp)
  403cba:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  403cbe:	48 85 c0             	test   %rax,%rax
  403cc1:	74 12                	je     403cd5 <popmin+0xed>
    pp->next = pb->next;
  403cc3:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  403cc7:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
  403ccb:	48 8b 52 08          	mov    0x8(%rdx),%rdx
  403ccf:	48 89 50 08          	mov    %rdx,0x8(%rax)
  403cd3:	eb 1c                	jmp    403cf1 <popmin+0x109>
  else 
    tokenhashmap[h] = NULL;
  403cd5:	48 8d 05 6c 29 20 00 	lea    0x20296c(%rip),%rax        # 606648 <tokenhashmap>
  403cdc:	48 8b 00             	mov    (%rax),%rax
  403cdf:	0f b7 55 fc          	movzwl -0x4(%rbp),%edx
  403ce3:	48 c1 e2 03          	shl    $0x3,%rdx
  403ce7:	48 01 d0             	add    %rdx,%rax
  403cea:	48 c7 00 00 00 00 00 	movq   $0x0,(%rax)
  
  *lastbucket = pb;
  403cf1:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  403cf5:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
  403cf9:	48 89 10             	mov    %rdx,(%rax)
  return minid;
  403cfc:	0f b7 45 fe          	movzwl -0x2(%rbp),%eax
}
  403d00:	c9                   	leaveq 
  403d01:	c3                   	retq   

0000000000403d02 <gettimestamp>:

token_timestamp gettimestamp()
{
  403d02:	55                   	push   %rbp
  403d03:	48 89 e5             	mov    %rsp,%rbp
  return((token_timestamp)clock());
  403d06:	e8 d5 dd ff ff       	callq  401ae0 <clock@plt>
}
  403d0b:	5d                   	pop    %rbp
  403d0c:	c3                   	retq   

0000000000403d0d <find>:

tokenbucket* find(byte* token, tokenbucket** prev)
{
  403d0d:	55                   	push   %rbp
  403d0e:	48 89 e5             	mov    %rsp,%rbp
  403d11:	48 83 ec 10          	sub    $0x10,%rsp
  403d15:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  403d19:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
  return(findh(token, hash(token), prev));
  403d1d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403d21:	48 89 c7             	mov    %rax,%rdi
  403d24:	e8 ab 04 00 00       	callq  4041d4 <hash>
  403d29:	0f b7 c8             	movzwl %ax,%ecx
  403d2c:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
  403d30:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403d34:	89 ce                	mov    %ecx,%esi
  403d36:	48 89 c7             	mov    %rax,%rdi
  403d39:	e8 02 00 00 00       	callq  403d40 <findh>
}
  403d3e:	c9                   	leaveq 
  403d3f:	c3                   	retq   

0000000000403d40 <findh>:

tokenbucket* findh(byte* token, token_idx h, tokenbucket** prev)
{
  403d40:	55                   	push   %rbp
  403d41:	48 89 e5             	mov    %rsp,%rbp
  403d44:	48 83 ec 30          	sub    $0x30,%rsp
  403d48:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  403d4c:	89 f0                	mov    %esi,%eax
  403d4e:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
  403d52:	66 89 45 e4          	mov    %ax,-0x1c(%rbp)
  tokenbucket *f, *p;
  p = NULL;
  403d56:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
  403d5d:	00 
  f = tokenhashmap[h];
  403d5e:	48 8d 05 e3 28 20 00 	lea    0x2028e3(%rip),%rax        # 606648 <tokenhashmap>
  403d65:	48 8b 00             	mov    (%rax),%rax
  403d68:	0f b7 55 e4          	movzwl -0x1c(%rbp),%edx
  403d6c:	48 c1 e2 03          	shl    $0x3,%rdx
  403d70:	48 01 d0             	add    %rdx,%rax
  403d73:	48 8b 00             	mov    (%rax),%rax
  403d76:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  while (f && (memcmp(token, tokenlist[f->i].entry.token, MEGAKI_TOKEN_BYTES) != 0)) {
  403d7a:	eb 14                	jmp    403d90 <findh+0x50>
    p = f;
  403d7c:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403d80:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    f = f->next;
  403d84:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403d88:	48 8b 40 08          	mov    0x8(%rax),%rax
  403d8c:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
tokenbucket* findh(byte* token, token_idx h, tokenbucket** prev)
{
  tokenbucket *f, *p;
  p = NULL;
  f = tokenhashmap[h];
  while (f && (memcmp(token, tokenlist[f->i].entry.token, MEGAKI_TOKEN_BYTES) != 0)) {
  403d90:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
  403d95:	74 44                	je     403ddb <findh+0x9b>
  403d97:	48 8d 05 9a 28 20 00 	lea    0x20289a(%rip),%rax        # 606638 <tokenlist>
  403d9e:	48 8b 10             	mov    (%rax),%rdx
  403da1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  403da5:	0f b7 00             	movzwl (%rax),%eax
  403da8:	0f b7 c0             	movzwl %ax,%eax
  403dab:	48 c1 e0 03          	shl    $0x3,%rax
  403daf:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
  403db6:	00 
  403db7:	48 29 c1             	sub    %rax,%rcx
  403dba:	48 89 c8             	mov    %rcx,%rax
  403dbd:	48 01 d0             	add    %rdx,%rax
  403dc0:	48 89 c1             	mov    %rax,%rcx
  403dc3:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  403dc7:	ba 10 00 00 00       	mov    $0x10,%edx
  403dcc:	48 89 ce             	mov    %rcx,%rsi
  403dcf:	48 89 c7             	mov    %rax,%rdi
  403dd2:	e8 69 dd ff ff       	callq  401b40 <memcmp@plt>
  403dd7:	85 c0                	test   %eax,%eax
  403dd9:	75 a1                	jne    403d7c <findh+0x3c>
    p = f;
    f = f->next;
  }
  if (prev) *prev = p;
  403ddb:	48 83 7d d8 00       	cmpq   $0x0,-0x28(%rbp)
  403de0:	74 0b                	je     403ded <findh+0xad>
  403de2:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  403de6:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
  403dea:	48 89 10             	mov    %rdx,(%rax)
  return(f); 
  403ded:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
}
  403df1:	c9                   	leaveq 
  403df2:	c3                   	retq   

0000000000403df3 <heapifyup>:

void heapifyup(token_idx hi)
{
  403df3:	55                   	push   %rbp
  403df4:	48 89 e5             	mov    %rsp,%rbp
  403df7:	48 83 ec 10          	sub    $0x10,%rsp
  403dfb:	89 f8                	mov    %edi,%eax
  403dfd:	66 89 45 fc          	mov    %ax,-0x4(%rbp)
  while (HEAP_PARENT(hi) >= HEAP_ROOT && tokenlist[tokenheap[HEAP_PARENT(hi)]].time > tokenlist[tokenheap[hi]].time) {
  403e01:	eb 22                	jmp    403e25 <heapifyup+0x32>
    heapswap(hi, HEAP_PARENT(hi));
  403e03:	0f b7 45 fc          	movzwl -0x4(%rbp),%eax
  403e07:	66 d1 e8             	shr    %ax
  403e0a:	0f b7 d0             	movzwl %ax,%edx
  403e0d:	0f b7 45 fc          	movzwl -0x4(%rbp),%eax
  403e11:	89 d6                	mov    %edx,%esi
  403e13:	89 c7                	mov    %eax,%edi
  403e15:	e8 b2 02 00 00       	callq  4040cc <heapswap>
    hi = HEAP_PARENT(hi);
  403e1a:	0f b7 45 fc          	movzwl -0x4(%rbp),%eax
  403e1e:	66 d1 e8             	shr    %ax
  403e21:	66 89 45 fc          	mov    %ax,-0x4(%rbp)
  return(f); 
}

void heapifyup(token_idx hi)
{
  while (HEAP_PARENT(hi) >= HEAP_ROOT && tokenlist[tokenheap[HEAP_PARENT(hi)]].time > tokenlist[tokenheap[hi]].time) {
  403e25:	66 83 7d fc 01       	cmpw   $0x1,-0x4(%rbp)
  403e2a:	0f 86 86 00 00 00    	jbe    403eb6 <heapifyup+0xc3>
  403e30:	48 8d 05 01 28 20 00 	lea    0x202801(%rip),%rax        # 606638 <tokenlist>
  403e37:	48 8b 10             	mov    (%rax),%rdx
  403e3a:	48 8d 05 ef 27 20 00 	lea    0x2027ef(%rip),%rax        # 606630 <tokenheap>
  403e41:	48 8b 00             	mov    (%rax),%rax
  403e44:	0f b7 4d fc          	movzwl -0x4(%rbp),%ecx
  403e48:	66 d1 e9             	shr    %cx
  403e4b:	0f b7 c9             	movzwl %cx,%ecx
  403e4e:	48 01 c9             	add    %rcx,%rcx
  403e51:	48 01 c8             	add    %rcx,%rax
  403e54:	0f b7 00             	movzwl (%rax),%eax
  403e57:	0f b7 c0             	movzwl %ax,%eax
  403e5a:	48 c1 e0 03          	shl    $0x3,%rax
  403e5e:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
  403e65:	00 
  403e66:	48 29 c1             	sub    %rax,%rcx
  403e69:	48 89 c8             	mov    %rcx,%rax
  403e6c:	48 01 d0             	add    %rdx,%rax
  403e6f:	8b 50 34             	mov    0x34(%rax),%edx
  403e72:	48 8d 05 bf 27 20 00 	lea    0x2027bf(%rip),%rax        # 606638 <tokenlist>
  403e79:	48 8b 08             	mov    (%rax),%rcx
  403e7c:	48 8d 05 ad 27 20 00 	lea    0x2027ad(%rip),%rax        # 606630 <tokenheap>
  403e83:	48 8b 00             	mov    (%rax),%rax
  403e86:	0f b7 75 fc          	movzwl -0x4(%rbp),%esi
  403e8a:	48 01 f6             	add    %rsi,%rsi
  403e8d:	48 01 f0             	add    %rsi,%rax
  403e90:	0f b7 00             	movzwl (%rax),%eax
  403e93:	0f b7 c0             	movzwl %ax,%eax
  403e96:	48 c1 e0 03          	shl    $0x3,%rax
  403e9a:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
  403ea1:	00 
  403ea2:	48 29 c6             	sub    %rax,%rsi
  403ea5:	48 89 f0             	mov    %rsi,%rax
  403ea8:	48 01 c8             	add    %rcx,%rax
  403eab:	8b 40 34             	mov    0x34(%rax),%eax
  403eae:	39 c2                	cmp    %eax,%edx
  403eb0:	0f 87 4d ff ff ff    	ja     403e03 <heapifyup+0x10>
    heapswap(hi, HEAP_PARENT(hi));
    hi = HEAP_PARENT(hi);
  }
}
  403eb6:	c9                   	leaveq 
  403eb7:	c3                   	retq   

0000000000403eb8 <heapifydown>:

void heapifydown(token_idx hi)
{
  403eb8:	55                   	push   %rbp
  403eb9:	48 89 e5             	mov    %rsp,%rbp
  403ebc:	48 83 ec 10          	sub    $0x10,%rsp
  403ec0:	89 f8                	mov    %edi,%eax
  403ec2:	66 89 45 fc          	mov    %ax,-0x4(%rbp)
  /* hope to god compiler optimizes this */
  while (((HEAP_LCHILD(hi) <= tokencount && tokenlist[tokenheap[hi]].time > tokenlist[tokenheap[HEAP_LCHILD(hi)]].time) ||
  403ec6:	e9 c4 00 00 00       	jmpq   403f8f <heapifydown+0xd7>
    (HEAP_RCHILD(hi) <= tokencount && tokenlist[tokenheap[hi]].time > tokenlist[tokenheap[HEAP_RCHILD(hi)]].time))) {
    if (tokenlist[tokenheap[HEAP_LCHILD(hi)]].time < tokenlist[tokenheap[HEAP_RCHILD(hi)]].time) {
  403ecb:	48 8d 05 66 27 20 00 	lea    0x202766(%rip),%rax        # 606638 <tokenlist>
  403ed2:	48 8b 10             	mov    (%rax),%rdx
  403ed5:	48 8d 05 54 27 20 00 	lea    0x202754(%rip),%rax        # 606630 <tokenheap>
  403edc:	48 8b 00             	mov    (%rax),%rax
  403edf:	0f b7 4d fc          	movzwl -0x4(%rbp),%ecx
  403ee3:	48 c1 e1 02          	shl    $0x2,%rcx
  403ee7:	48 01 c8             	add    %rcx,%rax
  403eea:	0f b7 00             	movzwl (%rax),%eax
  403eed:	0f b7 c0             	movzwl %ax,%eax
  403ef0:	48 c1 e0 03          	shl    $0x3,%rax
  403ef4:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
  403efb:	00 
  403efc:	48 29 c1             	sub    %rax,%rcx
  403eff:	48 89 c8             	mov    %rcx,%rax
  403f02:	48 01 d0             	add    %rdx,%rax
  403f05:	8b 50 34             	mov    0x34(%rax),%edx
  403f08:	48 8d 05 29 27 20 00 	lea    0x202729(%rip),%rax        # 606638 <tokenlist>
  403f0f:	48 8b 08             	mov    (%rax),%rcx
  403f12:	48 8d 05 17 27 20 00 	lea    0x202717(%rip),%rax        # 606630 <tokenheap>
  403f19:	48 8b 00             	mov    (%rax),%rax
  403f1c:	0f b7 75 fc          	movzwl -0x4(%rbp),%esi
  403f20:	48 c1 e6 02          	shl    $0x2,%rsi
  403f24:	48 83 c6 02          	add    $0x2,%rsi
  403f28:	48 01 f0             	add    %rsi,%rax
  403f2b:	0f b7 00             	movzwl (%rax),%eax
  403f2e:	0f b7 c0             	movzwl %ax,%eax
  403f31:	48 c1 e0 03          	shl    $0x3,%rax
  403f35:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
  403f3c:	00 
  403f3d:	48 29 c6             	sub    %rax,%rsi
  403f40:	48 89 f0             	mov    %rsi,%rax
  403f43:	48 01 c8             	add    %rcx,%rax
  403f46:	8b 40 34             	mov    0x34(%rax),%eax
  403f49:	39 c2                	cmp    %eax,%edx
  403f4b:	73 1c                	jae    403f69 <heapifydown+0xb1>
      heapswap(hi, HEAP_LCHILD(hi));
  403f4d:	0f b7 45 fc          	movzwl -0x4(%rbp),%eax
  403f51:	01 c0                	add    %eax,%eax
  403f53:	0f b7 d0             	movzwl %ax,%edx
  403f56:	0f b7 45 fc          	movzwl -0x4(%rbp),%eax
  403f5a:	89 d6                	mov    %edx,%esi
  403f5c:	89 c7                	mov    %eax,%edi
  403f5e:	e8 69 01 00 00       	callq  4040cc <heapswap>
      hi = HEAP_LCHILD(hi);
  403f63:	66 d1 65 fc          	shlw   -0x4(%rbp)
  403f67:	eb 26                	jmp    403f8f <heapifydown+0xd7>
    } else {
      heapswap(hi, HEAP_RCHILD(hi));
  403f69:	0f b7 45 fc          	movzwl -0x4(%rbp),%eax
  403f6d:	01 c0                	add    %eax,%eax
  403f6f:	83 c0 01             	add    $0x1,%eax
  403f72:	0f b7 d0             	movzwl %ax,%edx
  403f75:	0f b7 45 fc          	movzwl -0x4(%rbp),%eax
  403f79:	89 d6                	mov    %edx,%esi
  403f7b:	89 c7                	mov    %eax,%edi
  403f7d:	e8 4a 01 00 00       	callq  4040cc <heapswap>
      hi = HEAP_RCHILD(hi);
  403f82:	0f b7 45 fc          	movzwl -0x4(%rbp),%eax
  403f86:	01 c0                	add    %eax,%eax
  403f88:	83 c0 01             	add    $0x1,%eax
  403f8b:	66 89 45 fc          	mov    %ax,-0x4(%rbp)
}

void heapifydown(token_idx hi)
{
  /* hope to god compiler optimizes this */
  while (((HEAP_LCHILD(hi) <= tokencount && tokenlist[tokenheap[hi]].time > tokenlist[tokenheap[HEAP_LCHILD(hi)]].time) ||
  403f8f:	0f b7 45 fc          	movzwl -0x4(%rbp),%eax
  403f93:	01 c0                	add    %eax,%eax
  403f95:	89 c2                	mov    %eax,%edx
  403f97:	48 8d 05 a2 26 20 00 	lea    0x2026a2(%rip),%rax        # 606640 <tokencount>
  403f9e:	8b 00                	mov    (%rax),%eax
  403fa0:	39 c2                	cmp    %eax,%edx
  403fa2:	0f 87 81 00 00 00    	ja     404029 <heapifydown+0x171>
  403fa8:	48 8d 05 89 26 20 00 	lea    0x202689(%rip),%rax        # 606638 <tokenlist>
  403faf:	48 8b 10             	mov    (%rax),%rdx
  403fb2:	48 8d 05 77 26 20 00 	lea    0x202677(%rip),%rax        # 606630 <tokenheap>
  403fb9:	48 8b 00             	mov    (%rax),%rax
  403fbc:	0f b7 4d fc          	movzwl -0x4(%rbp),%ecx
  403fc0:	48 01 c9             	add    %rcx,%rcx
  403fc3:	48 01 c8             	add    %rcx,%rax
  403fc6:	0f b7 00             	movzwl (%rax),%eax
  403fc9:	0f b7 c0             	movzwl %ax,%eax
  403fcc:	48 c1 e0 03          	shl    $0x3,%rax
  403fd0:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
  403fd7:	00 
  403fd8:	48 29 c1             	sub    %rax,%rcx
  403fdb:	48 89 c8             	mov    %rcx,%rax
  403fde:	48 01 d0             	add    %rdx,%rax
  403fe1:	8b 50 34             	mov    0x34(%rax),%edx
  403fe4:	48 8d 05 4d 26 20 00 	lea    0x20264d(%rip),%rax        # 606638 <tokenlist>
  403feb:	48 8b 08             	mov    (%rax),%rcx
  403fee:	48 8d 05 3b 26 20 00 	lea    0x20263b(%rip),%rax        # 606630 <tokenheap>
  403ff5:	48 8b 00             	mov    (%rax),%rax
  403ff8:	0f b7 75 fc          	movzwl -0x4(%rbp),%esi
  403ffc:	48 c1 e6 02          	shl    $0x2,%rsi
  404000:	48 01 f0             	add    %rsi,%rax
  404003:	0f b7 00             	movzwl (%rax),%eax
  404006:	0f b7 c0             	movzwl %ax,%eax
  404009:	48 c1 e0 03          	shl    $0x3,%rax
  40400d:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
  404014:	00 
  404015:	48 29 c6             	sub    %rax,%rsi
  404018:	48 89 f0             	mov    %rsi,%rax
  40401b:	48 01 c8             	add    %rcx,%rax
  40401e:	8b 40 34             	mov    0x34(%rax),%eax
  404021:	39 c2                	cmp    %eax,%edx
  404023:	0f 87 a2 fe ff ff    	ja     403ecb <heapifydown+0x13>
    (HEAP_RCHILD(hi) <= tokencount && tokenlist[tokenheap[hi]].time > tokenlist[tokenheap[HEAP_RCHILD(hi)]].time))) {
  404029:	0f b7 45 fc          	movzwl -0x4(%rbp),%eax
  40402d:	01 c0                	add    %eax,%eax
  40402f:	83 c0 01             	add    $0x1,%eax
  404032:	89 c2                	mov    %eax,%edx
  404034:	48 8d 05 05 26 20 00 	lea    0x202605(%rip),%rax        # 606640 <tokencount>
  40403b:	8b 00                	mov    (%rax),%eax
}

void heapifydown(token_idx hi)
{
  /* hope to god compiler optimizes this */
  while (((HEAP_LCHILD(hi) <= tokencount && tokenlist[tokenheap[hi]].time > tokenlist[tokenheap[HEAP_LCHILD(hi)]].time) ||
  40403d:	39 c2                	cmp    %eax,%edx
  40403f:	0f 87 85 00 00 00    	ja     4040ca <heapifydown+0x212>
    (HEAP_RCHILD(hi) <= tokencount && tokenlist[tokenheap[hi]].time > tokenlist[tokenheap[HEAP_RCHILD(hi)]].time))) {
  404045:	48 8d 05 ec 25 20 00 	lea    0x2025ec(%rip),%rax        # 606638 <tokenlist>
  40404c:	48 8b 10             	mov    (%rax),%rdx
  40404f:	48 8d 05 da 25 20 00 	lea    0x2025da(%rip),%rax        # 606630 <tokenheap>
  404056:	48 8b 00             	mov    (%rax),%rax
  404059:	0f b7 4d fc          	movzwl -0x4(%rbp),%ecx
  40405d:	48 01 c9             	add    %rcx,%rcx
  404060:	48 01 c8             	add    %rcx,%rax
  404063:	0f b7 00             	movzwl (%rax),%eax
  404066:	0f b7 c0             	movzwl %ax,%eax
  404069:	48 c1 e0 03          	shl    $0x3,%rax
  40406d:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
  404074:	00 
  404075:	48 29 c1             	sub    %rax,%rcx
  404078:	48 89 c8             	mov    %rcx,%rax
  40407b:	48 01 d0             	add    %rdx,%rax
  40407e:	8b 50 34             	mov    0x34(%rax),%edx
  404081:	48 8d 05 b0 25 20 00 	lea    0x2025b0(%rip),%rax        # 606638 <tokenlist>
  404088:	48 8b 08             	mov    (%rax),%rcx
  40408b:	48 8d 05 9e 25 20 00 	lea    0x20259e(%rip),%rax        # 606630 <tokenheap>
  404092:	48 8b 00             	mov    (%rax),%rax
  404095:	0f b7 75 fc          	movzwl -0x4(%rbp),%esi
  404099:	48 c1 e6 02          	shl    $0x2,%rsi
  40409d:	48 83 c6 02          	add    $0x2,%rsi
  4040a1:	48 01 f0             	add    %rsi,%rax
  4040a4:	0f b7 00             	movzwl (%rax),%eax
  4040a7:	0f b7 c0             	movzwl %ax,%eax
  4040aa:	48 c1 e0 03          	shl    $0x3,%rax
  4040ae:	48 8d 34 c5 00 00 00 	lea    0x0(,%rax,8),%rsi
  4040b5:	00 
  4040b6:	48 29 c6             	sub    %rax,%rsi
  4040b9:	48 89 f0             	mov    %rsi,%rax
  4040bc:	48 01 c8             	add    %rcx,%rax
  4040bf:	8b 40 34             	mov    0x34(%rax),%eax
  4040c2:	39 c2                	cmp    %eax,%edx
  4040c4:	0f 87 01 fe ff ff    	ja     403ecb <heapifydown+0x13>
    } else {
      heapswap(hi, HEAP_RCHILD(hi));
      hi = HEAP_RCHILD(hi);
    }
  }
}
  4040ca:	c9                   	leaveq 
  4040cb:	c3                   	retq   

00000000004040cc <heapswap>:

void heapswap(token_idx hi1, token_idx hi2)
{
  4040cc:	55                   	push   %rbp
  4040cd:	48 89 e5             	mov    %rsp,%rbp
  4040d0:	89 fa                	mov    %edi,%edx
  4040d2:	89 f0                	mov    %esi,%eax
  4040d4:	66 89 55 dc          	mov    %dx,-0x24(%rbp)
  4040d8:	66 89 45 d8          	mov    %ax,-0x28(%rbp)
  tokintentry* t1 = &tokenlist[tokenheap[hi1]], *t2 = &tokenlist[tokenheap[hi2]];
  4040dc:	48 8d 05 55 25 20 00 	lea    0x202555(%rip),%rax        # 606638 <tokenlist>
  4040e3:	48 8b 10             	mov    (%rax),%rdx
  4040e6:	48 8d 05 43 25 20 00 	lea    0x202543(%rip),%rax        # 606630 <tokenheap>
  4040ed:	48 8b 00             	mov    (%rax),%rax
  4040f0:	0f b7 4d dc          	movzwl -0x24(%rbp),%ecx
  4040f4:	48 01 c9             	add    %rcx,%rcx
  4040f7:	48 01 c8             	add    %rcx,%rax
  4040fa:	0f b7 00             	movzwl (%rax),%eax
  4040fd:	0f b7 c0             	movzwl %ax,%eax
  404100:	48 c1 e0 03          	shl    $0x3,%rax
  404104:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
  40410b:	00 
  40410c:	48 29 c1             	sub    %rax,%rcx
  40410f:	48 89 c8             	mov    %rcx,%rax
  404112:	48 01 d0             	add    %rdx,%rax
  404115:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  404119:	48 8d 05 18 25 20 00 	lea    0x202518(%rip),%rax        # 606638 <tokenlist>
  404120:	48 8b 10             	mov    (%rax),%rdx
  404123:	48 8d 05 06 25 20 00 	lea    0x202506(%rip),%rax        # 606630 <tokenheap>
  40412a:	48 8b 00             	mov    (%rax),%rax
  40412d:	0f b7 4d d8          	movzwl -0x28(%rbp),%ecx
  404131:	48 01 c9             	add    %rcx,%rcx
  404134:	48 01 c8             	add    %rcx,%rax
  404137:	0f b7 00             	movzwl (%rax),%eax
  40413a:	0f b7 c0             	movzwl %ax,%eax
  40413d:	48 c1 e0 03          	shl    $0x3,%rax
  404141:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
  404148:	00 
  404149:	48 29 c1             	sub    %rax,%rcx
  40414c:	48 89 c8             	mov    %rcx,%rax
  40414f:	48 01 d0             	add    %rdx,%rax
  404152:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  t1->heapidx = hi2; t2->heapidx = hi1;
  404156:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40415a:	0f b7 55 d8          	movzwl -0x28(%rbp),%edx
  40415e:	66 89 50 30          	mov    %dx,0x30(%rax)
  404162:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  404166:	0f b7 55 dc          	movzwl -0x24(%rbp),%edx
  40416a:	66 89 50 30          	mov    %dx,0x30(%rax)
  token_idx t = tokenheap[hi1];
  40416e:	48 8d 05 bb 24 20 00 	lea    0x2024bb(%rip),%rax        # 606630 <tokenheap>
  404175:	48 8b 00             	mov    (%rax),%rax
  404178:	0f b7 55 dc          	movzwl -0x24(%rbp),%edx
  40417c:	48 01 d2             	add    %rdx,%rdx
  40417f:	48 01 d0             	add    %rdx,%rax
  404182:	0f b7 00             	movzwl (%rax),%eax
  404185:	66 89 45 ee          	mov    %ax,-0x12(%rbp)
  tokenheap[hi1] = tokenheap[hi2];
  404189:	48 8d 05 a0 24 20 00 	lea    0x2024a0(%rip),%rax        # 606630 <tokenheap>
  404190:	48 8b 00             	mov    (%rax),%rax
  404193:	0f b7 55 dc          	movzwl -0x24(%rbp),%edx
  404197:	48 01 d2             	add    %rdx,%rdx
  40419a:	48 01 c2             	add    %rax,%rdx
  40419d:	48 8d 05 8c 24 20 00 	lea    0x20248c(%rip),%rax        # 606630 <tokenheap>
  4041a4:	48 8b 00             	mov    (%rax),%rax
  4041a7:	0f b7 4d d8          	movzwl -0x28(%rbp),%ecx
  4041ab:	48 01 c9             	add    %rcx,%rcx
  4041ae:	48 01 c8             	add    %rcx,%rax
  4041b1:	0f b7 00             	movzwl (%rax),%eax
  4041b4:	66 89 02             	mov    %ax,(%rdx)
  tokenheap[hi2] = t;
  4041b7:	48 8d 05 72 24 20 00 	lea    0x202472(%rip),%rax        # 606630 <tokenheap>
  4041be:	48 8b 00             	mov    (%rax),%rax
  4041c1:	0f b7 55 d8          	movzwl -0x28(%rbp),%edx
  4041c5:	48 01 d2             	add    %rdx,%rdx
  4041c8:	48 01 c2             	add    %rax,%rdx
  4041cb:	0f b7 45 ee          	movzwl -0x12(%rbp),%eax
  4041cf:	66 89 02             	mov    %ax,(%rdx)
}
  4041d2:	5d                   	pop    %rbp
  4041d3:	c3                   	retq   

00000000004041d4 <hash>:

token_idx hash(byte* token)
{
  4041d4:	55                   	push   %rbp
  4041d5:	48 89 e5             	mov    %rsp,%rbp
  4041d8:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  uint32_t hash = FNV_OFFSET;
  4041dc:	c7 45 fc c5 9d 1c 81 	movl   $0x811c9dc5,-0x4(%rbp)
  int i;
  for (i = 0; i < MEGAKI_TOKEN_BYTES; ++i) {
  4041e3:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
  4041ea:	eb 26                	jmp    404212 <hash+0x3e>
    hash ^= token[i];
  4041ec:	8b 45 f8             	mov    -0x8(%rbp),%eax
  4041ef:	48 63 d0             	movslq %eax,%rdx
  4041f2:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  4041f6:	48 01 d0             	add    %rdx,%rax
  4041f9:	0f b6 00             	movzbl (%rax),%eax
  4041fc:	0f b6 c0             	movzbl %al,%eax
  4041ff:	31 45 fc             	xor    %eax,-0x4(%rbp)
    hash *= FNV_PRIME;
  404202:	8b 45 fc             	mov    -0x4(%rbp),%eax
  404205:	69 c0 93 01 00 01    	imul   $0x1000193,%eax,%eax
  40420b:	89 45 fc             	mov    %eax,-0x4(%rbp)

token_idx hash(byte* token)
{
  uint32_t hash = FNV_OFFSET;
  int i;
  for (i = 0; i < MEGAKI_TOKEN_BYTES; ++i) {
  40420e:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
  404212:	83 7d f8 0f          	cmpl   $0xf,-0x8(%rbp)
  404216:	7e d4                	jle    4041ec <hash+0x18>
    hash ^= token[i];
    hash *= FNV_PRIME;
  }
  return hash % maxbuckets;
  404218:	48 8d 05 25 24 20 00 	lea    0x202425(%rip),%rax        # 606644 <maxbuckets>
  40421f:	8b 08                	mov    (%rax),%ecx
  404221:	8b 45 fc             	mov    -0x4(%rbp),%eax
  404224:	ba 00 00 00 00       	mov    $0x0,%edx
  404229:	f7 f1                	div    %ecx
  40422b:	89 d0                	mov    %edx,%eax
}
  40422d:	5d                   	pop    %rbp
  40422e:	c3                   	retq   

000000000040422f <tokinit>:

int tokinit(unsigned int maxtoks, unsigned int maxbucks)
{
  40422f:	55                   	push   %rbp
  404230:	48 89 e5             	mov    %rsp,%rbp
  404233:	48 83 ec 10          	sub    $0x10,%rsp
  404237:	89 7d fc             	mov    %edi,-0x4(%rbp)
  40423a:	89 75 f8             	mov    %esi,-0x8(%rbp)
  tokenlist = (tokintentry*)malloc(maxtoks * sizeof(tokintentry));
  40423d:	8b 45 fc             	mov    -0x4(%rbp),%eax
  404240:	48 c1 e0 03          	shl    $0x3,%rax
  404244:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
  40424b:	00 
  40424c:	48 29 c2             	sub    %rax,%rdx
  40424f:	48 89 d0             	mov    %rdx,%rax
  404252:	48 89 c7             	mov    %rax,%rdi
  404255:	e8 26 d6 ff ff       	callq  401880 <malloc@plt>
  40425a:	48 89 c2             	mov    %rax,%rdx
  40425d:	48 8d 05 d4 23 20 00 	lea    0x2023d4(%rip),%rax        # 606638 <tokenlist>
  404264:	48 89 10             	mov    %rdx,(%rax)
  if (tokenlist == NULL)
  404267:	48 8d 05 ca 23 20 00 	lea    0x2023ca(%rip),%rax        # 606638 <tokenlist>
  40426e:	48 8b 00             	mov    (%rax),%rax
  404271:	48 85 c0             	test   %rax,%rax
  404274:	75 0a                	jne    404280 <tokinit+0x51>
    return(0);
  404276:	b8 00 00 00 00       	mov    $0x0,%eax
  40427b:	e9 0a 01 00 00       	jmpq   40438a <tokinit+0x15b>
    
  tokenhashmap = (tokenbucket**)malloc(maxbucks * sizeof(tokenbucket*));
  404280:	8b 45 f8             	mov    -0x8(%rbp),%eax
  404283:	48 c1 e0 03          	shl    $0x3,%rax
  404287:	48 89 c7             	mov    %rax,%rdi
  40428a:	e8 f1 d5 ff ff       	callq  401880 <malloc@plt>
  40428f:	48 89 c2             	mov    %rax,%rdx
  404292:	48 8d 05 af 23 20 00 	lea    0x2023af(%rip),%rax        # 606648 <tokenhashmap>
  404299:	48 89 10             	mov    %rdx,(%rax)
  if (tokenhashmap == NULL)
  40429c:	48 8d 05 a5 23 20 00 	lea    0x2023a5(%rip),%rax        # 606648 <tokenhashmap>
  4042a3:	48 8b 00             	mov    (%rax),%rax
  4042a6:	48 85 c0             	test   %rax,%rax
  4042a9:	75 0a                	jne    4042b5 <tokinit+0x86>
    return(0);
  4042ab:	b8 00 00 00 00       	mov    $0x0,%eax
  4042b0:	e9 d5 00 00 00       	jmpq   40438a <tokinit+0x15b>
    
  tokenheap = (token_idx*)malloc((2 * maxtoks + 1) * sizeof(token_idx));
  4042b5:	8b 45 fc             	mov    -0x4(%rbp),%eax
  4042b8:	01 c0                	add    %eax,%eax
  4042ba:	83 c0 01             	add    $0x1,%eax
  4042bd:	89 c0                	mov    %eax,%eax
  4042bf:	48 01 c0             	add    %rax,%rax
  4042c2:	48 89 c7             	mov    %rax,%rdi
  4042c5:	e8 b6 d5 ff ff       	callq  401880 <malloc@plt>
  4042ca:	48 89 c2             	mov    %rax,%rdx
  4042cd:	48 8d 05 5c 23 20 00 	lea    0x20235c(%rip),%rax        # 606630 <tokenheap>
  4042d4:	48 89 10             	mov    %rdx,(%rax)
  if (tokenheap == NULL)
  4042d7:	48 8d 05 52 23 20 00 	lea    0x202352(%rip),%rax        # 606630 <tokenheap>
  4042de:	48 8b 00             	mov    (%rax),%rax
  4042e1:	48 85 c0             	test   %rax,%rax
  4042e4:	75 0a                	jne    4042f0 <tokinit+0xc1>
    return(0);
  4042e6:	b8 00 00 00 00       	mov    $0x0,%eax
  4042eb:	e9 9a 00 00 00       	jmpq   40438a <tokinit+0x15b>
    
  memset(tokenlist, 0, maxtoks * sizeof(tokintentry));
  4042f0:	8b 45 fc             	mov    -0x4(%rbp),%eax
  4042f3:	48 c1 e0 03          	shl    $0x3,%rax
  4042f7:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
  4042fe:	00 
  4042ff:	48 29 c2             	sub    %rax,%rdx
  404302:	48 8d 05 2f 23 20 00 	lea    0x20232f(%rip),%rax        # 606638 <tokenlist>
  404309:	48 8b 00             	mov    (%rax),%rax
  40430c:	be 00 00 00 00       	mov    $0x0,%esi
  404311:	48 89 c7             	mov    %rax,%rdi
  404314:	e8 d7 d4 ff ff       	callq  4017f0 <memset@plt>
  memset(tokenhashmap, 0, maxbucks * sizeof(tokenbucket*));
  404319:	8b 45 f8             	mov    -0x8(%rbp),%eax
  40431c:	48 8d 14 c5 00 00 00 	lea    0x0(,%rax,8),%rdx
  404323:	00 
  404324:	48 8d 05 1d 23 20 00 	lea    0x20231d(%rip),%rax        # 606648 <tokenhashmap>
  40432b:	48 8b 00             	mov    (%rax),%rax
  40432e:	be 00 00 00 00       	mov    $0x0,%esi
  404333:	48 89 c7             	mov    %rax,%rdi
  404336:	e8 b5 d4 ff ff       	callq  4017f0 <memset@plt>
  memset(tokenheap, 0, (2 * maxtoks + 1) * sizeof(token_idx));
  40433b:	8b 45 fc             	mov    -0x4(%rbp),%eax
  40433e:	01 c0                	add    %eax,%eax
  404340:	83 c0 01             	add    $0x1,%eax
  404343:	89 c0                	mov    %eax,%eax
  404345:	48 8d 14 00          	lea    (%rax,%rax,1),%rdx
  404349:	48 8d 05 e0 22 20 00 	lea    0x2022e0(%rip),%rax        # 606630 <tokenheap>
  404350:	48 8b 00             	mov    (%rax),%rax
  404353:	be 00 00 00 00       	mov    $0x0,%esi
  404358:	48 89 c7             	mov    %rax,%rdi
  40435b:	e8 90 d4 ff ff       	callq  4017f0 <memset@plt>
  
  maxtokens = maxtoks;
  404360:	48 8d 05 c1 22 20 00 	lea    0x2022c1(%rip),%rax        # 606628 <maxtokens>
  404367:	8b 55 fc             	mov    -0x4(%rbp),%edx
  40436a:	89 10                	mov    %edx,(%rax)
  maxbuckets = maxbucks;
  40436c:	48 8d 05 d1 22 20 00 	lea    0x2022d1(%rip),%rax        # 606644 <maxbuckets>
  404373:	8b 55 f8             	mov    -0x8(%rbp),%edx
  404376:	89 10                	mov    %edx,(%rax)
  tokencount = 0;
  404378:	48 8d 05 c1 22 20 00 	lea    0x2022c1(%rip),%rax        # 606640 <tokencount>
  40437f:	c7 00 00 00 00 00    	movl   $0x0,(%rax)
  return(1);
  404385:	b8 01 00 00 00       	mov    $0x1,%eax
}
  40438a:	c9                   	leaveq 
  40438b:	c3                   	retq   

000000000040438c <tok_create>:

tokentry* tok_create(byte* token)
{
  40438c:	55                   	push   %rbp
  40438d:	48 89 e5             	mov    %rsp,%rbp
  404390:	48 83 ec 40          	sub    $0x40,%rsp
  404394:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
  //if (tokencount>1&&tokenheap[1]==tokenheap[2])raise(SIGINT);
  /*int qq,s0=0;
  for(qq=1;qq<=tokencount;++qq){if(tokenheap[qq]==0){if(s0)raise(SIGINT);s0=1;}}
  */
  token_idx i = tokencount, final = HEAP_ROOT + tokencount - 1;
  404398:	48 8d 05 a1 22 20 00 	lea    0x2022a1(%rip),%rax        # 606640 <tokencount>
  40439f:	8b 00                	mov    (%rax),%eax
  4043a1:	66 89 45 fe          	mov    %ax,-0x2(%rbp)
  4043a5:	48 8d 05 94 22 20 00 	lea    0x202294(%rip),%rax        # 606640 <tokencount>
  4043ac:	8b 00                	mov    (%rax),%eax
  4043ae:	66 89 45 fc          	mov    %ax,-0x4(%rbp)
  //if(token[0]==0xb9)raise(SIGINT);
  tokenbucket* tb = NULL;
  4043b2:	48 c7 45 d8 00 00 00 	movq   $0x0,-0x28(%rbp)
  4043b9:	00 
  if (tokencount >= maxtokens) {
  4043ba:	48 8d 05 7f 22 20 00 	lea    0x20227f(%rip),%rax        # 606640 <tokencount>
  4043c1:	8b 10                	mov    (%rax),%edx
  4043c3:	48 8d 05 5e 22 20 00 	lea    0x20225e(%rip),%rax        # 606628 <maxtokens>
  4043ca:	8b 00                	mov    (%rax),%eax
  4043cc:	39 c2                	cmp    %eax,%edx
  4043ce:	72 12                	jb     4043e2 <tok_create+0x56>
    i = popmin(&tb);
  4043d0:	48 8d 45 d8          	lea    -0x28(%rbp),%rax
  4043d4:	48 89 c7             	mov    %rax,%rdi
  4043d7:	e8 0c f8 ff ff       	callq  403be8 <popmin>
  4043dc:	66 89 45 fe          	mov    %ax,-0x2(%rbp)
  4043e0:	eb 25                	jmp    404407 <tok_create+0x7b>
  } else {
    final = HEAP_ROOT + tokencount;
  4043e2:	48 8d 05 57 22 20 00 	lea    0x202257(%rip),%rax        # 606640 <tokencount>
  4043e9:	8b 00                	mov    (%rax),%eax
  4043eb:	83 c0 01             	add    $0x1,%eax
  4043ee:	66 89 45 fc          	mov    %ax,-0x4(%rbp)
    ++tokencount;
  4043f2:	48 8d 05 47 22 20 00 	lea    0x202247(%rip),%rax        # 606640 <tokencount>
  4043f9:	8b 00                	mov    (%rax),%eax
  4043fb:	8d 50 01             	lea    0x1(%rax),%edx
  4043fe:	48 8d 05 3b 22 20 00 	lea    0x20223b(%rip),%rax        # 606640 <tokencount>
  404405:	89 10                	mov    %edx,(%rax)
  }
  
  tokintentry *e = tokenlist + i;
  404407:	48 8d 05 2a 22 20 00 	lea    0x20222a(%rip),%rax        # 606638 <tokenlist>
  40440e:	48 8b 10             	mov    (%rax),%rdx
  404411:	0f b7 45 fe          	movzwl -0x2(%rbp),%eax
  404415:	48 c1 e0 03          	shl    $0x3,%rax
  404419:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
  404420:	00 
  404421:	48 29 c1             	sub    %rax,%rcx
  404424:	48 89 c8             	mov    %rcx,%rax
  404427:	48 01 d0             	add    %rdx,%rax
  40442a:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
  e->time = gettimestamp();
  40442e:	b8 00 00 00 00       	mov    $0x0,%eax
  404433:	e8 ca f8 ff ff       	callq  403d02 <gettimestamp>
  404438:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
  40443c:	89 42 34             	mov    %eax,0x34(%rdx)
  e->heapidx = final;
  40443f:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  404443:	0f b7 55 fc          	movzwl -0x4(%rbp),%edx
  404447:	66 89 50 30          	mov    %dx,0x30(%rax)
  memcpy(e->entry.token, token, MEGAKI_TOKEN_BYTES);
  40444b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  40444f:	48 8b 4d c8          	mov    -0x38(%rbp),%rcx
  404453:	ba 10 00 00 00       	mov    $0x10,%edx
  404458:	48 89 ce             	mov    %rcx,%rsi
  40445b:	48 89 c7             	mov    %rax,%rdi
  40445e:	e8 0d d8 ff ff       	callq  401c70 <memcpy@plt>
  tokenheap[final] = i;
  404463:	48 8d 05 c6 21 20 00 	lea    0x2021c6(%rip),%rax        # 606630 <tokenheap>
  40446a:	48 8b 00             	mov    (%rax),%rax
  40446d:	0f b7 55 fc          	movzwl -0x4(%rbp),%edx
  404471:	48 01 d2             	add    %rdx,%rdx
  404474:	48 01 c2             	add    %rax,%rdx
  404477:	0f b7 45 fe          	movzwl -0x2(%rbp),%eax
  40447b:	66 89 02             	mov    %ax,(%rdx)
  //if (tokencount==100&&tokenheap[1]==tokenheap[100])raise(SIGINT);
  heapifyup(final);
  40447e:	0f b7 45 fc          	movzwl -0x4(%rbp),%eax
  404482:	89 c7                	mov    %eax,%edi
  404484:	e8 6a f9 ff ff       	callq  403df3 <heapifyup>
  //if (tokencount==100&&tokenheap[1]==tokenheap[100])raise(SIGINT);
  
  token_idx h = hash(token);
  404489:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  40448d:	48 89 c7             	mov    %rax,%rdi
  404490:	e8 3f fd ff ff       	callq  4041d4 <hash>
  404495:	66 89 45 e6          	mov    %ax,-0x1a(%rbp)
  if (!tb)
  404499:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  40449d:	48 85 c0             	test   %rax,%rax
  4044a0:	75 0e                	jne    4044b0 <tok_create+0x124>
    tb = (tokenbucket*)malloc(sizeof(tokenbucket));
  4044a2:	bf 10 00 00 00       	mov    $0x10,%edi
  4044a7:	e8 d4 d3 ff ff       	callq  401880 <malloc@plt>
  4044ac:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
  tb->i = i;
  4044b0:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  4044b4:	0f b7 55 fe          	movzwl -0x2(%rbp),%edx
  4044b8:	66 89 10             	mov    %dx,(%rax)
  tb->next = NULL;
  4044bb:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  4044bf:	48 c7 40 08 00 00 00 	movq   $0x0,0x8(%rax)
  4044c6:	00 
  
  tokenbucket * f = NULL;
  4044c7:	48 c7 45 f0 00 00 00 	movq   $0x0,-0x10(%rbp)
  4044ce:	00 
  if (!tokenhashmap[h]) {if((unsigned int)tb<(unsigned int)0xFFFU)raise(SIGINT);
  4044cf:	48 8d 05 72 21 20 00 	lea    0x202172(%rip),%rax        # 606648 <tokenhashmap>
  4044d6:	48 8b 00             	mov    (%rax),%rax
  4044d9:	0f b7 55 e6          	movzwl -0x1a(%rbp),%edx
  4044dd:	48 c1 e2 03          	shl    $0x3,%rdx
  4044e1:	48 01 d0             	add    %rdx,%rax
  4044e4:	48 8b 00             	mov    (%rax),%rax
  4044e7:	48 85 c0             	test   %rax,%rax
  4044ea:	75 33                	jne    40451f <tok_create+0x193>
  4044ec:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  4044f0:	3d fe 0f 00 00       	cmp    $0xffe,%eax
  4044f5:	77 0a                	ja     404501 <tok_create+0x175>
  4044f7:	bf 02 00 00 00       	mov    $0x2,%edi
  4044fc:	e8 8f d5 ff ff       	callq  401a90 <raise@plt>
    tokenhashmap[h] = tb;}
  404501:	48 8d 05 40 21 20 00 	lea    0x202140(%rip),%rax        # 606648 <tokenhashmap>
  404508:	48 8b 00             	mov    (%rax),%rax
  40450b:	0f b7 55 e6          	movzwl -0x1a(%rbp),%edx
  40450f:	48 c1 e2 03          	shl    $0x3,%rdx
  404513:	48 01 c2             	add    %rax,%rdx
  404516:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  40451a:	48 89 02             	mov    %rax,(%rdx)
  40451d:	eb 43                	jmp    404562 <tok_create+0x1d6>
  else {
    f = tokenhashmap[h];
  40451f:	48 8d 05 22 21 20 00 	lea    0x202122(%rip),%rax        # 606648 <tokenhashmap>
  404526:	48 8b 00             	mov    (%rax),%rax
  404529:	0f b7 55 e6          	movzwl -0x1a(%rbp),%edx
  40452d:	48 c1 e2 03          	shl    $0x3,%rdx
  404531:	48 01 d0             	add    %rdx,%rax
  404534:	48 8b 00             	mov    (%rax),%rax
  404537:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    while (f->next)
  40453b:	eb 0c                	jmp    404549 <tok_create+0x1bd>
      f = f->next;
  40453d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  404541:	48 8b 40 08          	mov    0x8(%rax),%rax
  404545:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  tokenbucket * f = NULL;
  if (!tokenhashmap[h]) {if((unsigned int)tb<(unsigned int)0xFFFU)raise(SIGINT);
    tokenhashmap[h] = tb;}
  else {
    f = tokenhashmap[h];
    while (f->next)
  404549:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  40454d:	48 8b 40 08          	mov    0x8(%rax),%rax
  404551:	48 85 c0             	test   %rax,%rax
  404554:	75 e7                	jne    40453d <tok_create+0x1b1>
      f = f->next;
    f->next = tb;
  404556:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
  40455a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  40455e:	48 89 50 08          	mov    %rdx,0x8(%rax)
  }
  
  return(&e->entry);
  404562:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
}
  404566:	c9                   	leaveq 
  404567:	c3                   	retq   

0000000000404568 <tok_renew>:

tokentry* tok_renew(byte* token)
{
  404568:	55                   	push   %rbp
  404569:	48 89 e5             	mov    %rsp,%rbp
  40456c:	53                   	push   %rbx
  40456d:	48 83 ec 28          	sub    $0x28,%rsp
  404571:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
  tokenbucket* tb = find(token, NULL);
  404575:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  404579:	be 00 00 00 00       	mov    $0x0,%esi
  40457e:	48 89 c7             	mov    %rax,%rdi
  404581:	e8 87 f7 ff ff       	callq  403d0d <find>
  404586:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
  if (!tb)
  40458a:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
  40458f:	75 0a                	jne    40459b <tok_renew+0x33>
    return NULL;
  404591:	b8 00 00 00 00       	mov    $0x0,%eax
  404596:	e9 97 00 00 00       	jmpq   404632 <tok_renew+0xca>
  else {
    tokenlist[tb->i].time = gettimestamp();
  40459b:	48 8d 05 96 20 20 00 	lea    0x202096(%rip),%rax        # 606638 <tokenlist>
  4045a2:	48 8b 10             	mov    (%rax),%rdx
  4045a5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  4045a9:	0f b7 00             	movzwl (%rax),%eax
  4045ac:	0f b7 c0             	movzwl %ax,%eax
  4045af:	48 c1 e0 03          	shl    $0x3,%rax
  4045b3:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
  4045ba:	00 
  4045bb:	48 29 c1             	sub    %rax,%rcx
  4045be:	48 89 c8             	mov    %rcx,%rax
  4045c1:	48 8d 1c 02          	lea    (%rdx,%rax,1),%rbx
  4045c5:	b8 00 00 00 00       	mov    $0x0,%eax
  4045ca:	e8 33 f7 ff ff       	callq  403d02 <gettimestamp>
  4045cf:	89 43 34             	mov    %eax,0x34(%rbx)
    heapifydown(tokenlist[tb->i].heapidx);
  4045d2:	48 8d 05 5f 20 20 00 	lea    0x20205f(%rip),%rax        # 606638 <tokenlist>
  4045d9:	48 8b 10             	mov    (%rax),%rdx
  4045dc:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  4045e0:	0f b7 00             	movzwl (%rax),%eax
  4045e3:	0f b7 c0             	movzwl %ax,%eax
  4045e6:	48 c1 e0 03          	shl    $0x3,%rax
  4045ea:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
  4045f1:	00 
  4045f2:	48 29 c1             	sub    %rax,%rcx
  4045f5:	48 89 c8             	mov    %rcx,%rax
  4045f8:	48 01 d0             	add    %rdx,%rax
  4045fb:	0f b7 40 30          	movzwl 0x30(%rax),%eax
  4045ff:	0f b7 c0             	movzwl %ax,%eax
  404602:	89 c7                	mov    %eax,%edi
  404604:	e8 af f8 ff ff       	callq  403eb8 <heapifydown>
    return (tokentry*)&tokenlist[tb->i];
  404609:	48 8d 05 28 20 20 00 	lea    0x202028(%rip),%rax        # 606638 <tokenlist>
  404610:	48 8b 10             	mov    (%rax),%rdx
  404613:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  404617:	0f b7 00             	movzwl (%rax),%eax
  40461a:	0f b7 c0             	movzwl %ax,%eax
  40461d:	48 c1 e0 03          	shl    $0x3,%rax
  404621:	48 8d 0c c5 00 00 00 	lea    0x0(,%rax,8),%rcx
  404628:	00 
  404629:	48 29 c1             	sub    %rax,%rcx
  40462c:	48 89 c8             	mov    %rcx,%rax
  40462f:	48 01 d0             	add    %rdx,%rax
  }
}
  404632:	48 83 c4 28          	add    $0x28,%rsp
  404636:	5b                   	pop    %rbx
  404637:	5d                   	pop    %rbp
  404638:	c3                   	retq   

0000000000404639 <tokshutdown>:

void tokshutdown()
{
  404639:	55                   	push   %rbp
  40463a:	48 89 e5             	mov    %rsp,%rbp
  40463d:	48 83 ec 10          	sub    $0x10,%rsp
  token_idx i;
  for (i = 0; i < maxbuckets; ++i) {
  404641:	66 c7 45 fe 00 00    	movw   $0x0,-0x2(%rbp)
  404647:	eb 42                	jmp    40468b <tokshutdown+0x52>
    tokenbucket * tb = tokenhashmap[i];
  404649:	48 8d 05 f8 1f 20 00 	lea    0x201ff8(%rip),%rax        # 606648 <tokenhashmap>
  404650:	48 8b 00             	mov    (%rax),%rax
  404653:	0f b7 55 fe          	movzwl -0x2(%rbp),%edx
  404657:	48 c1 e2 03          	shl    $0x3,%rdx
  40465b:	48 01 d0             	add    %rdx,%rax
  40465e:	48 8b 00             	mov    (%rax),%rax
  404661:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    while (tb) {
  404665:	eb 18                	jmp    40467f <tokshutdown+0x46>
      free(tb);
  404667:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  40466b:	48 89 c7             	mov    %rax,%rdi
  40466e:	e8 cd d2 ff ff       	callq  401940 <free@plt>
      tb = tb->next;
  404673:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  404677:	48 8b 40 08          	mov    0x8(%rax),%rax
  40467b:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
void tokshutdown()
{
  token_idx i;
  for (i = 0; i < maxbuckets; ++i) {
    tokenbucket * tb = tokenhashmap[i];
    while (tb) {
  40467f:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
  404684:	75 e1                	jne    404667 <tokshutdown+0x2e>
}

void tokshutdown()
{
  token_idx i;
  for (i = 0; i < maxbuckets; ++i) {
  404686:	66 83 45 fe 01       	addw   $0x1,-0x2(%rbp)
  40468b:	0f b7 55 fe          	movzwl -0x2(%rbp),%edx
  40468f:	48 8d 05 ae 1f 20 00 	lea    0x201fae(%rip),%rax        # 606644 <maxbuckets>
  404696:	8b 00                	mov    (%rax),%eax
  404698:	39 c2                	cmp    %eax,%edx
  40469a:	72 ad                	jb     404649 <tokshutdown+0x10>
    while (tb) {
      free(tb);
      tb = tb->next;
    }
  }
  free(tokenhashmap);
  40469c:	48 8d 05 a5 1f 20 00 	lea    0x201fa5(%rip),%rax        # 606648 <tokenhashmap>
  4046a3:	48 8b 00             	mov    (%rax),%rax
  4046a6:	48 89 c7             	mov    %rax,%rdi
  4046a9:	e8 92 d2 ff ff       	callq  401940 <free@plt>
  free(tokenlist);
  4046ae:	48 8d 05 83 1f 20 00 	lea    0x201f83(%rip),%rax        # 606638 <tokenlist>
  4046b5:	48 8b 00             	mov    (%rax),%rax
  4046b8:	48 89 c7             	mov    %rax,%rdi
  4046bb:	e8 80 d2 ff ff       	callq  401940 <free@plt>
  free(tokenheap);
  4046c0:	48 8d 05 69 1f 20 00 	lea    0x201f69(%rip),%rax        # 606630 <tokenheap>
  4046c7:	48 8b 00             	mov    (%rax),%rax
  4046ca:	48 89 c7             	mov    %rax,%rdi
  4046cd:	e8 6e d2 ff ff       	callq  401940 <free@plt>
}
  4046d2:	c9                   	leaveq 
  4046d3:	c3                   	retq   

00000000004046d4 <threadpool_create>:
static void *threadpool_thread(void *threadpool);

int threadpool_free(threadpool_t *pool);

threadpool_t *threadpool_create(int thread_count, int queue_size, int flags)
{
  4046d4:	55                   	push   %rbp
  4046d5:	48 89 e5             	mov    %rsp,%rbp
  4046d8:	48 83 ec 20          	sub    $0x20,%rsp
  4046dc:	89 7d ec             	mov    %edi,-0x14(%rbp)
  4046df:	89 75 e8             	mov    %esi,-0x18(%rbp)
  4046e2:	89 55 e4             	mov    %edx,-0x1c(%rbp)
    threadpool_t *pool;
    int i;

    /* TODO: Check for negative or otherwise very big input parameters */

    if((pool = (threadpool_t *)malloc(sizeof(threadpool_t))) == NULL) {
  4046e5:	bf 88 00 00 00       	mov    $0x88,%edi
  4046ea:	e8 91 d1 ff ff       	callq  401880 <malloc@plt>
  4046ef:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  4046f3:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
  4046f8:	75 05                	jne    4046ff <threadpool_create+0x2b>
        goto err;
  4046fa:	e9 78 01 00 00       	jmpq   404877 <threadpool_create+0x1a3>
    }

    /* Initialize */
    pool->thread_count = 0;
  4046ff:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  404703:	c7 40 68 00 00 00 00 	movl   $0x0,0x68(%rax)
    pool->queue_size = queue_size;
  40470a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  40470e:	8b 55 e8             	mov    -0x18(%rbp),%edx
  404711:	89 50 6c             	mov    %edx,0x6c(%rax)
    pool->head = pool->tail = pool->count = 0;
  404714:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  404718:	c7 40 78 00 00 00 00 	movl   $0x0,0x78(%rax)
  40471f:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  404723:	8b 50 78             	mov    0x78(%rax),%edx
  404726:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  40472a:	89 50 74             	mov    %edx,0x74(%rax)
  40472d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  404731:	8b 50 74             	mov    0x74(%rax),%edx
  404734:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  404738:	89 50 70             	mov    %edx,0x70(%rax)
    pool->shutdown = pool->started = 0;
  40473b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  40473f:	c7 80 80 00 00 00 00 	movl   $0x0,0x80(%rax)
  404746:	00 00 00 
  404749:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  40474d:	8b 90 80 00 00 00    	mov    0x80(%rax),%edx
  404753:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  404757:	89 50 7c             	mov    %edx,0x7c(%rax)

    /* Allocate thread and task queue */
    pool->threads = (pthread_t *)malloc(sizeof(pthread_t) * thread_count);
  40475a:	8b 45 ec             	mov    -0x14(%rbp),%eax
  40475d:	48 98                	cltq   
  40475f:	48 c1 e0 03          	shl    $0x3,%rax
  404763:	48 89 c7             	mov    %rax,%rdi
  404766:	e8 15 d1 ff ff       	callq  401880 <malloc@plt>
  40476b:	48 89 c2             	mov    %rax,%rdx
  40476e:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  404772:	48 89 50 58          	mov    %rdx,0x58(%rax)
    pool->queue = (threadpool_task_t *)malloc
        (sizeof(threadpool_task_t) * queue_size);
  404776:	8b 45 e8             	mov    -0x18(%rbp),%eax
  404779:	48 98                	cltq   
  40477b:	48 c1 e0 04          	shl    $0x4,%rax
  40477f:	48 89 c7             	mov    %rax,%rdi
  404782:	e8 f9 d0 ff ff       	callq  401880 <malloc@plt>
  404787:	48 89 c2             	mov    %rax,%rdx
    pool->head = pool->tail = pool->count = 0;
    pool->shutdown = pool->started = 0;

    /* Allocate thread and task queue */
    pool->threads = (pthread_t *)malloc(sizeof(pthread_t) * thread_count);
    pool->queue = (threadpool_task_t *)malloc
  40478a:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  40478e:	48 89 50 60          	mov    %rdx,0x60(%rax)
        (sizeof(threadpool_task_t) * queue_size);

    /* Initialize mutex and conditional variable first */
    if((pthread_mutex_init(&(pool->lock), NULL) != 0) ||
  404792:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  404796:	be 00 00 00 00       	mov    $0x0,%esi
  40479b:	48 89 c7             	mov    %rax,%rdi
  40479e:	e8 4d d1 ff ff       	callq  4018f0 <pthread_mutex_init@plt>
  4047a3:	85 c0                	test   %eax,%eax
  4047a5:	0f 85 cc 00 00 00    	jne    404877 <threadpool_create+0x1a3>
       (pthread_cond_init(&(pool->notify), NULL) != 0) ||
  4047ab:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  4047af:	48 83 c0 28          	add    $0x28,%rax
  4047b3:	be 00 00 00 00       	mov    $0x0,%esi
  4047b8:	48 89 c7             	mov    %rax,%rdi
  4047bb:	e8 d0 d1 ff ff       	callq  401990 <pthread_cond_init@plt>
    pool->threads = (pthread_t *)malloc(sizeof(pthread_t) * thread_count);
    pool->queue = (threadpool_task_t *)malloc
        (sizeof(threadpool_task_t) * queue_size);

    /* Initialize mutex and conditional variable first */
    if((pthread_mutex_init(&(pool->lock), NULL) != 0) ||
  4047c0:	85 c0                	test   %eax,%eax
  4047c2:	0f 85 af 00 00 00    	jne    404877 <threadpool_create+0x1a3>
       (pthread_cond_init(&(pool->notify), NULL) != 0) ||
       (pool->threads == NULL) ||
  4047c8:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  4047cc:	48 8b 40 58          	mov    0x58(%rax),%rax
    pool->queue = (threadpool_task_t *)malloc
        (sizeof(threadpool_task_t) * queue_size);

    /* Initialize mutex and conditional variable first */
    if((pthread_mutex_init(&(pool->lock), NULL) != 0) ||
       (pthread_cond_init(&(pool->notify), NULL) != 0) ||
  4047d0:	48 85 c0             	test   %rax,%rax
  4047d3:	0f 84 9e 00 00 00    	je     404877 <threadpool_create+0x1a3>
       (pool->threads == NULL) ||
       (pool->queue == NULL)) {
  4047d9:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  4047dd:	48 8b 40 60          	mov    0x60(%rax),%rax
        (sizeof(threadpool_task_t) * queue_size);

    /* Initialize mutex and conditional variable first */
    if((pthread_mutex_init(&(pool->lock), NULL) != 0) ||
       (pthread_cond_init(&(pool->notify), NULL) != 0) ||
       (pool->threads == NULL) ||
  4047e1:	48 85 c0             	test   %rax,%rax
  4047e4:	0f 84 8d 00 00 00    	je     404877 <threadpool_create+0x1a3>
       (pool->queue == NULL)) {
        goto err;
    }

    /* Start worker threads */
    for(i = 0; i < thread_count; i++) {
  4047ea:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  4047f1:	eb 76                	jmp    404869 <threadpool_create+0x195>
        if(pthread_create(&(pool->threads[i]), NULL,
  4047f3:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  4047f7:	48 8b 40 58          	mov    0x58(%rax),%rax
  4047fb:	8b 55 fc             	mov    -0x4(%rbp),%edx
  4047fe:	48 63 d2             	movslq %edx,%rdx
  404801:	48 c1 e2 03          	shl    $0x3,%rdx
  404805:	48 8d 3c 10          	lea    (%rax,%rdx,1),%rdi
  404809:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  40480d:	48 89 c1             	mov    %rax,%rcx
  404810:	48 8d 15 46 03 00 00 	lea    0x346(%rip),%rdx        # 404b5d <threadpool_thread>
  404817:	be 00 00 00 00       	mov    $0x0,%esi
  40481c:	e8 5f d1 ff ff       	callq  401980 <pthread_create@plt>
  404821:	85 c0                	test   %eax,%eax
  404823:	74 18                	je     40483d <threadpool_create+0x169>
                          threadpool_thread, (void*)pool) != 0) {
            threadpool_destroy(pool, 0);
  404825:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  404829:	be 00 00 00 00       	mov    $0x0,%esi
  40482e:	48 89 c7             	mov    %rax,%rdi
  404831:	e8 95 01 00 00       	callq  4049cb <threadpool_destroy>
            return NULL;
  404836:	b8 00 00 00 00       	mov    $0x0,%eax
  40483b:	eb 52                	jmp    40488f <threadpool_create+0x1bb>
        }
        pool->thread_count++;
  40483d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  404841:	8b 40 68             	mov    0x68(%rax),%eax
  404844:	8d 50 01             	lea    0x1(%rax),%edx
  404847:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  40484b:	89 50 68             	mov    %edx,0x68(%rax)
        pool->started++;
  40484e:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  404852:	8b 80 80 00 00 00    	mov    0x80(%rax),%eax
  404858:	8d 50 01             	lea    0x1(%rax),%edx
  40485b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  40485f:	89 90 80 00 00 00    	mov    %edx,0x80(%rax)
       (pool->queue == NULL)) {
        goto err;
    }

    /* Start worker threads */
    for(i = 0; i < thread_count; i++) {
  404865:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  404869:	8b 45 fc             	mov    -0x4(%rbp),%eax
  40486c:	3b 45 ec             	cmp    -0x14(%rbp),%eax
  40486f:	7c 82                	jl     4047f3 <threadpool_create+0x11f>
        }
        pool->thread_count++;
        pool->started++;
    }

    return pool;
  404871:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  404875:	eb 18                	jmp    40488f <threadpool_create+0x1bb>

 err:
    if(pool) {
  404877:	48 83 7d f0 00       	cmpq   $0x0,-0x10(%rbp)
  40487c:	74 0c                	je     40488a <threadpool_create+0x1b6>
        threadpool_free(pool);
  40487e:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  404882:	48 89 c7             	mov    %rax,%rdi
  404885:	e8 43 02 00 00       	callq  404acd <threadpool_free>
    }
    return NULL;
  40488a:	b8 00 00 00 00       	mov    $0x0,%eax
}
  40488f:	c9                   	leaveq 
  404890:	c3                   	retq   

0000000000404891 <threadpool_add>:

int threadpool_add(threadpool_t *pool, void (*function)(void *),
                   void *argument, int flags)
{
  404891:	55                   	push   %rbp
  404892:	48 89 e5             	mov    %rsp,%rbp
  404895:	48 83 ec 30          	sub    $0x30,%rsp
  404899:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  40489d:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  4048a1:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
  4048a5:	89 4d d4             	mov    %ecx,-0x2c(%rbp)
    int err = 0;
  4048a8:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    int next;

    if(pool == NULL || function == NULL) {
  4048af:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
  4048b4:	74 07                	je     4048bd <threadpool_add+0x2c>
  4048b6:	48 83 7d e0 00       	cmpq   $0x0,-0x20(%rbp)
  4048bb:	75 0a                	jne    4048c7 <threadpool_add+0x36>
        return threadpool_invalid;
  4048bd:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  4048c2:	e9 02 01 00 00       	jmpq   4049c9 <threadpool_add+0x138>
    }

    if(pthread_mutex_lock(&(pool->lock)) != 0) {
  4048c7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  4048cb:	48 89 c7             	mov    %rax,%rdi
  4048ce:	e8 ed d2 ff ff       	callq  401bc0 <pthread_mutex_lock@plt>
  4048d3:	85 c0                	test   %eax,%eax
  4048d5:	74 0a                	je     4048e1 <threadpool_add+0x50>
        return threadpool_lock_failure;
  4048d7:	b8 fe ff ff ff       	mov    $0xfffffffe,%eax
  4048dc:	e9 e8 00 00 00       	jmpq   4049c9 <threadpool_add+0x138>
    }

    next = pool->tail + 1;
  4048e1:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  4048e5:	8b 40 74             	mov    0x74(%rax),%eax
  4048e8:	83 c0 01             	add    $0x1,%eax
  4048eb:	89 45 f8             	mov    %eax,-0x8(%rbp)
    next = (next == pool->queue_size) ? 0 : next;
  4048ee:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  4048f2:	8b 40 6c             	mov    0x6c(%rax),%eax
  4048f5:	3b 45 f8             	cmp    -0x8(%rbp),%eax
  4048f8:	74 05                	je     4048ff <threadpool_add+0x6e>
  4048fa:	8b 45 f8             	mov    -0x8(%rbp),%eax
  4048fd:	eb 05                	jmp    404904 <threadpool_add+0x73>
  4048ff:	b8 00 00 00 00       	mov    $0x0,%eax
  404904:	89 45 f8             	mov    %eax,-0x8(%rbp)

    do {
        /* Are we full ? */
        if(pool->count == pool->queue_size) {
  404907:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  40490b:	8b 50 78             	mov    0x78(%rax),%edx
  40490e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  404912:	8b 40 6c             	mov    0x6c(%rax),%eax
  404915:	39 c2                	cmp    %eax,%edx
  404917:	75 0c                	jne    404925 <threadpool_add+0x94>
            err = threadpool_queue_full;
  404919:	c7 45 fc fd ff ff ff 	movl   $0xfffffffd,-0x4(%rbp)
            break;
  404920:	e9 8a 00 00 00       	jmpq   4049af <threadpool_add+0x11e>
        }

        /* Are we shutting down ? */
        if(pool->shutdown) {
  404925:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  404929:	8b 40 7c             	mov    0x7c(%rax),%eax
  40492c:	85 c0                	test   %eax,%eax
  40492e:	74 09                	je     404939 <threadpool_add+0xa8>
            err = threadpool_shutdown;
  404930:	c7 45 fc fc ff ff ff 	movl   $0xfffffffc,-0x4(%rbp)
            break;
  404937:	eb 76                	jmp    4049af <threadpool_add+0x11e>
        }

        /* Add task to queue */
        pool->queue[pool->tail].function = function;
  404939:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  40493d:	48 8b 50 60          	mov    0x60(%rax),%rdx
  404941:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  404945:	8b 40 74             	mov    0x74(%rax),%eax
  404948:	48 98                	cltq   
  40494a:	48 c1 e0 04          	shl    $0x4,%rax
  40494e:	48 01 c2             	add    %rax,%rdx
  404951:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  404955:	48 89 02             	mov    %rax,(%rdx)
        pool->queue[pool->tail].argument = argument;
  404958:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  40495c:	48 8b 50 60          	mov    0x60(%rax),%rdx
  404960:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  404964:	8b 40 74             	mov    0x74(%rax),%eax
  404967:	48 98                	cltq   
  404969:	48 c1 e0 04          	shl    $0x4,%rax
  40496d:	48 01 c2             	add    %rax,%rdx
  404970:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  404974:	48 89 42 08          	mov    %rax,0x8(%rdx)
        pool->tail = next;
  404978:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  40497c:	8b 55 f8             	mov    -0x8(%rbp),%edx
  40497f:	89 50 74             	mov    %edx,0x74(%rax)
        pool->count += 1;
  404982:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  404986:	8b 40 78             	mov    0x78(%rax),%eax
  404989:	8d 50 01             	lea    0x1(%rax),%edx
  40498c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  404990:	89 50 78             	mov    %edx,0x78(%rax)

        /* pthread_cond_broadcast */
        if(pthread_cond_signal(&(pool->notify)) != 0) {
  404993:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  404997:	48 83 c0 28          	add    $0x28,%rax
  40499b:	48 89 c7             	mov    %rax,%rdi
  40499e:	e8 ad ce ff ff       	callq  401850 <pthread_cond_signal@plt>
  4049a3:	85 c0                	test   %eax,%eax
  4049a5:	74 08                	je     4049af <threadpool_add+0x11e>
            err = threadpool_lock_failure;
  4049a7:	c7 45 fc fe ff ff ff 	movl   $0xfffffffe,-0x4(%rbp)
            break;
  4049ae:	90                   	nop
        }
    } while(0);

    if(pthread_mutex_unlock(&pool->lock) != 0) {
  4049af:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  4049b3:	48 89 c7             	mov    %rax,%rdi
  4049b6:	e8 a5 d2 ff ff       	callq  401c60 <pthread_mutex_unlock@plt>
  4049bb:	85 c0                	test   %eax,%eax
  4049bd:	74 07                	je     4049c6 <threadpool_add+0x135>
        err = threadpool_lock_failure;
  4049bf:	c7 45 fc fe ff ff ff 	movl   $0xfffffffe,-0x4(%rbp)
    }

    return err;
  4049c6:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
  4049c9:	c9                   	leaveq 
  4049ca:	c3                   	retq   

00000000004049cb <threadpool_destroy>:

int threadpool_destroy(threadpool_t *pool, int flags)
{
  4049cb:	55                   	push   %rbp
  4049cc:	48 89 e5             	mov    %rsp,%rbp
  4049cf:	48 83 ec 20          	sub    $0x20,%rsp
  4049d3:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  4049d7:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    int i, err = 0;
  4049da:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)

    if(pool == NULL) {
  4049e1:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
  4049e6:	75 0a                	jne    4049f2 <threadpool_destroy+0x27>
        return threadpool_invalid;
  4049e8:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  4049ed:	e9 d9 00 00 00       	jmpq   404acb <threadpool_destroy+0x100>
    }

    if(pthread_mutex_lock(&(pool->lock)) != 0) {
  4049f2:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  4049f6:	48 89 c7             	mov    %rax,%rdi
  4049f9:	e8 c2 d1 ff ff       	callq  401bc0 <pthread_mutex_lock@plt>
  4049fe:	85 c0                	test   %eax,%eax
  404a00:	74 0a                	je     404a0c <threadpool_destroy+0x41>
        return threadpool_lock_failure;
  404a02:	b8 fe ff ff ff       	mov    $0xfffffffe,%eax
  404a07:	e9 bf 00 00 00       	jmpq   404acb <threadpool_destroy+0x100>
    }

    do {
        /* Already shutting down */
        if(pool->shutdown) {
  404a0c:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  404a10:	8b 40 7c             	mov    0x7c(%rax),%eax
  404a13:	85 c0                	test   %eax,%eax
  404a15:	74 0c                	je     404a23 <threadpool_destroy+0x58>
            err = threadpool_shutdown;
  404a17:	c7 45 f8 fc ff ff ff 	movl   $0xfffffffc,-0x8(%rbp)
            break;
  404a1e:	e9 93 00 00 00       	jmpq   404ab6 <threadpool_destroy+0xeb>
        }

        pool->shutdown = (flags & threadpool_graceful) ?
  404a23:	8b 45 e4             	mov    -0x1c(%rbp),%eax
  404a26:	83 e0 01             	and    $0x1,%eax
            graceful_shutdown : immediate_shutdown;
  404a29:	85 c0                	test   %eax,%eax
  404a2b:	74 07                	je     404a34 <threadpool_destroy+0x69>
  404a2d:	b8 02 00 00 00       	mov    $0x2,%eax
  404a32:	eb 05                	jmp    404a39 <threadpool_destroy+0x6e>
  404a34:	b8 01 00 00 00       	mov    $0x1,%eax
        if(pool->shutdown) {
            err = threadpool_shutdown;
            break;
        }

        pool->shutdown = (flags & threadpool_graceful) ?
  404a39:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
  404a3d:	89 42 7c             	mov    %eax,0x7c(%rdx)
            graceful_shutdown : immediate_shutdown;

        /* Wake up all worker threads */
        if((pthread_cond_broadcast(&(pool->notify)) != 0) ||
  404a40:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  404a44:	48 83 c0 28          	add    $0x28,%rax
  404a48:	48 89 c7             	mov    %rax,%rdi
  404a4b:	e8 e0 d1 ff ff       	callq  401c30 <pthread_cond_broadcast@plt>
  404a50:	85 c0                	test   %eax,%eax
  404a52:	75 10                	jne    404a64 <threadpool_destroy+0x99>
           (pthread_mutex_unlock(&(pool->lock)) != 0)) {
  404a54:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  404a58:	48 89 c7             	mov    %rax,%rdi
  404a5b:	e8 00 d2 ff ff       	callq  401c60 <pthread_mutex_unlock@plt>

        pool->shutdown = (flags & threadpool_graceful) ?
            graceful_shutdown : immediate_shutdown;

        /* Wake up all worker threads */
        if((pthread_cond_broadcast(&(pool->notify)) != 0) ||
  404a60:	85 c0                	test   %eax,%eax
  404a62:	74 09                	je     404a6d <threadpool_destroy+0xa2>
           (pthread_mutex_unlock(&(pool->lock)) != 0)) {
            err = threadpool_lock_failure;
  404a64:	c7 45 f8 fe ff ff ff 	movl   $0xfffffffe,-0x8(%rbp)
            break;
  404a6b:	eb 49                	jmp    404ab6 <threadpool_destroy+0xeb>
        }

        /* Join all worker thread */
        for(i = 0; i < pool->thread_count; i++) {
  404a6d:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  404a74:	eb 34                	jmp    404aaa <threadpool_destroy+0xdf>
            if(pthread_join(pool->threads[i], NULL) != 0) {
  404a76:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  404a7a:	48 8b 40 58          	mov    0x58(%rax),%rax
  404a7e:	8b 55 fc             	mov    -0x4(%rbp),%edx
  404a81:	48 63 d2             	movslq %edx,%rdx
  404a84:	48 c1 e2 03          	shl    $0x3,%rdx
  404a88:	48 01 d0             	add    %rdx,%rax
  404a8b:	48 8b 00             	mov    (%rax),%rax
  404a8e:	be 00 00 00 00       	mov    $0x0,%esi
  404a93:	48 89 c7             	mov    %rax,%rdi
  404a96:	e8 55 cf ff ff       	callq  4019f0 <pthread_join@plt>
  404a9b:	85 c0                	test   %eax,%eax
  404a9d:	74 07                	je     404aa6 <threadpool_destroy+0xdb>
                err = threadpool_thread_failure;
  404a9f:	c7 45 f8 fb ff ff ff 	movl   $0xfffffffb,-0x8(%rbp)
            err = threadpool_lock_failure;
            break;
        }

        /* Join all worker thread */
        for(i = 0; i < pool->thread_count; i++) {
  404aa6:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  404aaa:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  404aae:	8b 40 68             	mov    0x68(%rax),%eax
  404ab1:	3b 45 fc             	cmp    -0x4(%rbp),%eax
  404ab4:	7f c0                	jg     404a76 <threadpool_destroy+0xab>
            }
        }
    } while(0);

    /* Only if everything went well do we deallocate the pool */
    if(!err) {
  404ab6:	83 7d f8 00          	cmpl   $0x0,-0x8(%rbp)
  404aba:	75 0c                	jne    404ac8 <threadpool_destroy+0xfd>
        threadpool_free(pool);
  404abc:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  404ac0:	48 89 c7             	mov    %rax,%rdi
  404ac3:	e8 05 00 00 00       	callq  404acd <threadpool_free>
    }
    return err;
  404ac8:	8b 45 f8             	mov    -0x8(%rbp),%eax
}
  404acb:	c9                   	leaveq 
  404acc:	c3                   	retq   

0000000000404acd <threadpool_free>:

int threadpool_free(threadpool_t *pool)
{
  404acd:	55                   	push   %rbp
  404ace:	48 89 e5             	mov    %rsp,%rbp
  404ad1:	48 83 ec 10          	sub    $0x10,%rsp
  404ad5:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    if(pool == NULL || pool->started > 0) {
  404ad9:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
  404ade:	74 0e                	je     404aee <threadpool_free+0x21>
  404ae0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404ae4:	8b 80 80 00 00 00    	mov    0x80(%rax),%eax
  404aea:	85 c0                	test   %eax,%eax
  404aec:	7e 07                	jle    404af5 <threadpool_free+0x28>
        return -1;
  404aee:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  404af3:	eb 66                	jmp    404b5b <threadpool_free+0x8e>
    }

    /* Did we manage to allocate ? */
    if(pool->threads) {
  404af5:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404af9:	48 8b 40 58          	mov    0x58(%rax),%rax
  404afd:	48 85 c0             	test   %rax,%rax
  404b00:	74 48                	je     404b4a <threadpool_free+0x7d>
        free(pool->threads);
  404b02:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404b06:	48 8b 40 58          	mov    0x58(%rax),%rax
  404b0a:	48 89 c7             	mov    %rax,%rdi
  404b0d:	e8 2e ce ff ff       	callq  401940 <free@plt>
        free(pool->queue);
  404b12:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404b16:	48 8b 40 60          	mov    0x60(%rax),%rax
  404b1a:	48 89 c7             	mov    %rax,%rdi
  404b1d:	e8 1e ce ff ff       	callq  401940 <free@plt>
 
        /* Because we allocate pool->threads after initializing the
           mutex and condition variable, we're sure they're
           initialized. Let's lock the mutex just in case. */
        pthread_mutex_lock(&(pool->lock));
  404b22:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404b26:	48 89 c7             	mov    %rax,%rdi
  404b29:	e8 92 d0 ff ff       	callq  401bc0 <pthread_mutex_lock@plt>
        pthread_mutex_destroy(&(pool->lock));
  404b2e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404b32:	48 89 c7             	mov    %rax,%rdi
  404b35:	e8 e6 d0 ff ff       	callq  401c20 <pthread_mutex_destroy@plt>
        pthread_cond_destroy(&(pool->notify));
  404b3a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404b3e:	48 83 c0 28          	add    $0x28,%rax
  404b42:	48 89 c7             	mov    %rax,%rdi
  404b45:	e8 86 cc ff ff       	callq  4017d0 <pthread_cond_destroy@plt>
    }
    free(pool);    
  404b4a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404b4e:	48 89 c7             	mov    %rax,%rdi
  404b51:	e8 ea cd ff ff       	callq  401940 <free@plt>
    return 0;
  404b56:	b8 00 00 00 00       	mov    $0x0,%eax
}
  404b5b:	c9                   	leaveq 
  404b5c:	c3                   	retq   

0000000000404b5d <threadpool_thread>:


static void *threadpool_thread(void *threadpool)
{
  404b5d:	55                   	push   %rbp
  404b5e:	48 89 e5             	mov    %rsp,%rbp
  404b61:	48 83 ec 30          	sub    $0x30,%rsp
  404b65:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
    threadpool_t *pool = (threadpool_t *)threadpool;
  404b69:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  404b6d:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    threadpool_task_t task;

    for(;;) {
        /* Lock must be taken to wait on conditional variable */
        pthread_mutex_lock(&(pool->lock));
  404b71:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404b75:	48 89 c7             	mov    %rax,%rdi
  404b78:	e8 43 d0 ff ff       	callq  401bc0 <pthread_mutex_lock@plt>

        /* Wait on condition variable, check for spurious wakeups.
           When returning from pthread_cond_wait(), we own the lock. */
        while((pool->count == 0) && (!pool->shutdown)) {
  404b7d:	eb 17                	jmp    404b96 <threadpool_thread+0x39>
            pthread_cond_wait(&(pool->notify), &(pool->lock));
  404b7f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404b83:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
  404b87:	48 83 c2 28          	add    $0x28,%rdx
  404b8b:	48 89 c6             	mov    %rax,%rsi
  404b8e:	48 89 d7             	mov    %rdx,%rdi
  404b91:	e8 9a cf ff ff       	callq  401b30 <pthread_cond_wait@plt>
        /* Lock must be taken to wait on conditional variable */
        pthread_mutex_lock(&(pool->lock));

        /* Wait on condition variable, check for spurious wakeups.
           When returning from pthread_cond_wait(), we own the lock. */
        while((pool->count == 0) && (!pool->shutdown)) {
  404b96:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404b9a:	8b 40 78             	mov    0x78(%rax),%eax
  404b9d:	85 c0                	test   %eax,%eax
  404b9f:	75 0b                	jne    404bac <threadpool_thread+0x4f>
  404ba1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404ba5:	8b 40 7c             	mov    0x7c(%rax),%eax
  404ba8:	85 c0                	test   %eax,%eax
  404baa:	74 d3                	je     404b7f <threadpool_thread+0x22>
            pthread_cond_wait(&(pool->notify), &(pool->lock));
        }

        if((pool->shutdown == immediate_shutdown) ||
  404bac:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404bb0:	8b 40 7c             	mov    0x7c(%rax),%eax
  404bb3:	83 f8 01             	cmp    $0x1,%eax
  404bb6:	0f 84 c1 00 00 00    	je     404c7d <threadpool_thread+0x120>
           ((pool->shutdown == graceful_shutdown) &&
  404bbc:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404bc0:	8b 40 7c             	mov    0x7c(%rax),%eax
           When returning from pthread_cond_wait(), we own the lock. */
        while((pool->count == 0) && (!pool->shutdown)) {
            pthread_cond_wait(&(pool->notify), &(pool->lock));
        }

        if((pool->shutdown == immediate_shutdown) ||
  404bc3:	83 f8 02             	cmp    $0x2,%eax
  404bc6:	75 0f                	jne    404bd7 <threadpool_thread+0x7a>
           ((pool->shutdown == graceful_shutdown) &&
            (pool->count == 0))) {
  404bc8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404bcc:	8b 40 78             	mov    0x78(%rax),%eax
        while((pool->count == 0) && (!pool->shutdown)) {
            pthread_cond_wait(&(pool->notify), &(pool->lock));
        }

        if((pool->shutdown == immediate_shutdown) ||
           ((pool->shutdown == graceful_shutdown) &&
  404bcf:	85 c0                	test   %eax,%eax
  404bd1:	0f 84 a6 00 00 00    	je     404c7d <threadpool_thread+0x120>
            (pool->count == 0))) {
            break;
        }

        /* Grab our task */
        task.function = pool->queue[pool->head].function;
  404bd7:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404bdb:	48 8b 50 60          	mov    0x60(%rax),%rdx
  404bdf:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404be3:	8b 40 70             	mov    0x70(%rax),%eax
  404be6:	48 98                	cltq   
  404be8:	48 c1 e0 04          	shl    $0x4,%rax
  404bec:	48 01 d0             	add    %rdx,%rax
  404bef:	48 8b 00             	mov    (%rax),%rax
  404bf2:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
        task.argument = pool->queue[pool->head].argument;
  404bf6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404bfa:	48 8b 50 60          	mov    0x60(%rax),%rdx
  404bfe:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404c02:	8b 40 70             	mov    0x70(%rax),%eax
  404c05:	48 98                	cltq   
  404c07:	48 c1 e0 04          	shl    $0x4,%rax
  404c0b:	48 01 d0             	add    %rdx,%rax
  404c0e:	48 8b 40 08          	mov    0x8(%rax),%rax
  404c12:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
        pool->head += 1;
  404c16:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404c1a:	8b 40 70             	mov    0x70(%rax),%eax
  404c1d:	8d 50 01             	lea    0x1(%rax),%edx
  404c20:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404c24:	89 50 70             	mov    %edx,0x70(%rax)
        pool->head = (pool->head == pool->queue_size) ? 0 : pool->head;
  404c27:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404c2b:	8b 50 70             	mov    0x70(%rax),%edx
  404c2e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404c32:	8b 40 6c             	mov    0x6c(%rax),%eax
  404c35:	39 c2                	cmp    %eax,%edx
  404c37:	74 09                	je     404c42 <threadpool_thread+0xe5>
  404c39:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404c3d:	8b 40 70             	mov    0x70(%rax),%eax
  404c40:	eb 05                	jmp    404c47 <threadpool_thread+0xea>
  404c42:	b8 00 00 00 00       	mov    $0x0,%eax
  404c47:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
  404c4b:	89 42 70             	mov    %eax,0x70(%rdx)
        pool->count -= 1;
  404c4e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404c52:	8b 40 78             	mov    0x78(%rax),%eax
  404c55:	8d 50 ff             	lea    -0x1(%rax),%edx
  404c58:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404c5c:	89 50 78             	mov    %edx,0x78(%rax)

        /* Unlock */
        pthread_mutex_unlock(&(pool->lock));
  404c5f:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404c63:	48 89 c7             	mov    %rax,%rdi
  404c66:	e8 f5 cf ff ff       	callq  401c60 <pthread_mutex_unlock@plt>

        /* Get to work */
        (*(task.function))(task.argument);
  404c6b:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  404c6f:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
  404c73:	48 89 d7             	mov    %rdx,%rdi
  404c76:	ff d0                	callq  *%rax
    }
  404c78:	e9 f4 fe ff ff       	jmpq   404b71 <threadpool_thread+0x14>

    pool->started--;
  404c7d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404c81:	8b 80 80 00 00 00    	mov    0x80(%rax),%eax
  404c87:	8d 50 ff             	lea    -0x1(%rax),%edx
  404c8a:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404c8e:	89 90 80 00 00 00    	mov    %edx,0x80(%rax)

    pthread_mutex_unlock(&(pool->lock));
  404c94:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  404c98:	48 89 c7             	mov    %rax,%rdi
  404c9b:	e8 c0 cf ff ff       	callq  401c60 <pthread_mutex_unlock@plt>
    pthread_exit(NULL);
  404ca0:	bf 00 00 00 00       	mov    $0x0,%edi
  404ca5:	e8 76 cd ff ff       	callq  401a20 <pthread_exit@plt>

0000000000404caa <hexdump>:
#include "hexdump.h"
#include <stdio.h>

void hexdump (FILE *f, char *desc, void *addr, int len) {
  404caa:	55                   	push   %rbp
  404cab:	48 89 e5             	mov    %rsp,%rbp
  404cae:	48 83 ec 50          	sub    $0x50,%rsp
  404cb2:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
  404cb6:	48 89 75 c0          	mov    %rsi,-0x40(%rbp)
  404cba:	48 89 55 b8          	mov    %rdx,-0x48(%rbp)
  404cbe:	89 4d b4             	mov    %ecx,-0x4c(%rbp)
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;
  404cc1:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
  404cc5:	48 89 45 f0          	mov    %rax,-0x10(%rbp)

    // Output description if given.
    if (desc != NULL)
  404cc9:	48 83 7d c0 00       	cmpq   $0x0,-0x40(%rbp)
  404cce:	74 1c                	je     404cec <hexdump+0x42>
        fprintf (f, "%s:\n", desc);
  404cd0:	48 8b 55 c0          	mov    -0x40(%rbp),%rdx
  404cd4:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  404cd8:	48 8d 35 2d 09 00 00 	lea    0x92d(%rip),%rsi        # 40560c <MEGAKI_SERVICE_UNAVAILABLE_ERROR+0x4c>
  404cdf:	48 89 c7             	mov    %rax,%rdi
  404ce2:	b8 00 00 00 00       	mov    $0x0,%eax
  404ce7:	e8 14 cf ff ff       	callq  401c00 <fprintf@plt>

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
  404cec:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  404cf3:	e9 f1 00 00 00       	jmpq   404de9 <hexdump+0x13f>
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
  404cf8:	8b 45 fc             	mov    -0x4(%rbp),%eax
  404cfb:	83 e0 0f             	and    $0xf,%eax
  404cfe:	85 c0                	test   %eax,%eax
  404d00:	75 3d                	jne    404d3f <hexdump+0x95>
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
  404d02:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
  404d06:	74 1c                	je     404d24 <hexdump+0x7a>
                fprintf (f, "  %s\n", buff);
  404d08:	48 8d 55 d0          	lea    -0x30(%rbp),%rdx
  404d0c:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  404d10:	48 8d 35 fa 08 00 00 	lea    0x8fa(%rip),%rsi        # 405611 <MEGAKI_SERVICE_UNAVAILABLE_ERROR+0x51>
  404d17:	48 89 c7             	mov    %rax,%rdi
  404d1a:	b8 00 00 00 00       	mov    $0x0,%eax
  404d1f:	e8 dc ce ff ff       	callq  401c00 <fprintf@plt>

            // Output the offset.
            fprintf (f, "  %04x ", i);
  404d24:	8b 55 fc             	mov    -0x4(%rbp),%edx
  404d27:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  404d2b:	48 8d 35 e5 08 00 00 	lea    0x8e5(%rip),%rsi        # 405617 <MEGAKI_SERVICE_UNAVAILABLE_ERROR+0x57>
  404d32:	48 89 c7             	mov    %rax,%rdi
  404d35:	b8 00 00 00 00       	mov    $0x0,%eax
  404d3a:	e8 c1 ce ff ff       	callq  401c00 <fprintf@plt>
        }

        // Now the hex code for the specific character.
        fprintf (f, " %02x", pc[i]);
  404d3f:	8b 45 fc             	mov    -0x4(%rbp),%eax
  404d42:	48 63 d0             	movslq %eax,%rdx
  404d45:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  404d49:	48 01 d0             	add    %rdx,%rax
  404d4c:	0f b6 00             	movzbl (%rax),%eax
  404d4f:	0f b6 d0             	movzbl %al,%edx
  404d52:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  404d56:	48 8d 35 c2 08 00 00 	lea    0x8c2(%rip),%rsi        # 40561f <MEGAKI_SERVICE_UNAVAILABLE_ERROR+0x5f>
  404d5d:	48 89 c7             	mov    %rax,%rdi
  404d60:	b8 00 00 00 00       	mov    $0x0,%eax
  404d65:	e8 96 ce ff ff       	callq  401c00 <fprintf@plt>

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
  404d6a:	8b 45 fc             	mov    -0x4(%rbp),%eax
  404d6d:	48 63 d0             	movslq %eax,%rdx
  404d70:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  404d74:	48 01 d0             	add    %rdx,%rax
  404d77:	0f b6 00             	movzbl (%rax),%eax
  404d7a:	3c 1f                	cmp    $0x1f,%al
  404d7c:	76 14                	jbe    404d92 <hexdump+0xe8>
  404d7e:	8b 45 fc             	mov    -0x4(%rbp),%eax
  404d81:	48 63 d0             	movslq %eax,%rdx
  404d84:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  404d88:	48 01 d0             	add    %rdx,%rax
  404d8b:	0f b6 00             	movzbl (%rax),%eax
  404d8e:	3c 7e                	cmp    $0x7e,%al
  404d90:	76 17                	jbe    404da9 <hexdump+0xff>
            buff[i % 16] = '.';
  404d92:	8b 45 fc             	mov    -0x4(%rbp),%eax
  404d95:	99                   	cltd   
  404d96:	c1 ea 1c             	shr    $0x1c,%edx
  404d99:	01 d0                	add    %edx,%eax
  404d9b:	83 e0 0f             	and    $0xf,%eax
  404d9e:	29 d0                	sub    %edx,%eax
  404da0:	48 98                	cltq   
  404da2:	c6 44 05 d0 2e       	movb   $0x2e,-0x30(%rbp,%rax,1)
  404da7:	eb 24                	jmp    404dcd <hexdump+0x123>
        else
            buff[i % 16] = pc[i];
  404da9:	8b 45 fc             	mov    -0x4(%rbp),%eax
  404dac:	99                   	cltd   
  404dad:	c1 ea 1c             	shr    $0x1c,%edx
  404db0:	01 d0                	add    %edx,%eax
  404db2:	83 e0 0f             	and    $0xf,%eax
  404db5:	29 d0                	sub    %edx,%eax
  404db7:	8b 55 fc             	mov    -0x4(%rbp),%edx
  404dba:	48 63 ca             	movslq %edx,%rcx
  404dbd:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
  404dc1:	48 01 ca             	add    %rcx,%rdx
  404dc4:	0f b6 12             	movzbl (%rdx),%edx
  404dc7:	48 98                	cltq   
  404dc9:	88 54 05 d0          	mov    %dl,-0x30(%rbp,%rax,1)
        buff[(i % 16) + 1] = '\0';
  404dcd:	8b 45 fc             	mov    -0x4(%rbp),%eax
  404dd0:	99                   	cltd   
  404dd1:	c1 ea 1c             	shr    $0x1c,%edx
  404dd4:	01 d0                	add    %edx,%eax
  404dd6:	83 e0 0f             	and    $0xf,%eax
  404dd9:	29 d0                	sub    %edx,%eax
  404ddb:	83 c0 01             	add    $0x1,%eax
  404dde:	48 98                	cltq   
  404de0:	c6 44 05 d0 00       	movb   $0x0,-0x30(%rbp,%rax,1)
    // Output description if given.
    if (desc != NULL)
        fprintf (f, "%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
  404de5:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  404de9:	8b 45 fc             	mov    -0x4(%rbp),%eax
  404dec:	3b 45 b4             	cmp    -0x4c(%rbp),%eax
  404def:	0f 8c 03 ff ff ff    	jl     404cf8 <hexdump+0x4e>
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
  404df5:	eb 21                	jmp    404e18 <hexdump+0x16e>
        fprintf (f, "   ");
  404df7:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  404dfb:	48 89 c1             	mov    %rax,%rcx
  404dfe:	ba 03 00 00 00       	mov    $0x3,%edx
  404e03:	be 01 00 00 00       	mov    $0x1,%esi
  404e08:	48 8d 3d 16 08 00 00 	lea    0x816(%rip),%rdi        # 405625 <MEGAKI_SERVICE_UNAVAILABLE_ERROR+0x65>
  404e0f:	e8 9c cd ff ff       	callq  401bb0 <fwrite@plt>
        i++;
  404e14:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
  404e18:	8b 45 fc             	mov    -0x4(%rbp),%eax
  404e1b:	83 e0 0f             	and    $0xf,%eax
  404e1e:	85 c0                	test   %eax,%eax
  404e20:	75 d5                	jne    404df7 <hexdump+0x14d>
        fprintf (f, "   ");
        i++;
    }

    // And print the final ASCII bit.
    fprintf (f, "  %s\n", buff);
  404e22:	48 8d 55 d0          	lea    -0x30(%rbp),%rdx
  404e26:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  404e2a:	48 8d 35 e0 07 00 00 	lea    0x7e0(%rip),%rsi        # 405611 <MEGAKI_SERVICE_UNAVAILABLE_ERROR+0x51>
  404e31:	48 89 c7             	mov    %rax,%rdi
  404e34:	b8 00 00 00 00       	mov    $0x0,%eax
  404e39:	e8 c2 cd ff ff       	callq  401c00 <fprintf@plt>
}
  404e3e:	c9                   	leaveq 
  404e3f:	c3                   	retq   

0000000000404e40 <__libc_csu_init>:
  404e40:	41 57                	push   %r15
  404e42:	41 89 ff             	mov    %edi,%r15d
  404e45:	41 56                	push   %r14
  404e47:	49 89 f6             	mov    %rsi,%r14
  404e4a:	41 55                	push   %r13
  404e4c:	49 89 d5             	mov    %rdx,%r13
  404e4f:	41 54                	push   %r12
  404e51:	4c 8d 25 a8 11 20 00 	lea    0x2011a8(%rip),%r12        # 606000 <__frame_dummy_init_array_entry>
  404e58:	55                   	push   %rbp
  404e59:	48 8d 2d a8 11 20 00 	lea    0x2011a8(%rip),%rbp        # 606008 <__init_array_end>
  404e60:	53                   	push   %rbx
  404e61:	4c 29 e5             	sub    %r12,%rbp
  404e64:	31 db                	xor    %ebx,%ebx
  404e66:	48 c1 fd 03          	sar    $0x3,%rbp
  404e6a:	48 83 ec 08          	sub    $0x8,%rsp
  404e6e:	e8 25 c9 ff ff       	callq  401798 <_init>
  404e73:	48 85 ed             	test   %rbp,%rbp
  404e76:	74 1e                	je     404e96 <__libc_csu_init+0x56>
  404e78:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  404e7f:	00 
  404e80:	4c 89 ea             	mov    %r13,%rdx
  404e83:	4c 89 f6             	mov    %r14,%rsi
  404e86:	44 89 ff             	mov    %r15d,%edi
  404e89:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  404e8d:	48 83 c3 01          	add    $0x1,%rbx
  404e91:	48 39 eb             	cmp    %rbp,%rbx
  404e94:	75 ea                	jne    404e80 <__libc_csu_init+0x40>
  404e96:	48 83 c4 08          	add    $0x8,%rsp
  404e9a:	5b                   	pop    %rbx
  404e9b:	5d                   	pop    %rbp
  404e9c:	41 5c                	pop    %r12
  404e9e:	41 5d                	pop    %r13
  404ea0:	41 5e                	pop    %r14
  404ea2:	41 5f                	pop    %r15
  404ea4:	c3                   	retq   
  404ea5:	66 66 2e 0f 1f 84 00 	data32 nopw %cs:0x0(%rax,%rax,1)
  404eac:	00 00 00 00 

0000000000404eb0 <__libc_csu_fini>:
  404eb0:	f3 c3                	repz retq 

Disassembly of section .fini:

0000000000404eb4 <_fini>:
  404eb4:	48 83 ec 08          	sub    $0x8,%rsp
  404eb8:	48 83 c4 08          	add    $0x8,%rsp
  404ebc:	c3                   	retq   
