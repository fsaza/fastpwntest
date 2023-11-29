#                                                                  by             FSAZ
from pwn import *
from LibcSearcher import *
import random
import string
import time
print("\n--------------------------------------\n	fast pwn test\n	针对二进制服务进行快速测试\n	by\n	fsaz\n--------------------------------------\n")
print("注意：此测试可能会造成服务器的崩溃!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
#setos-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
errorbz=1
while errorbz==1:
	print("输入目标系统:'android', 'baremetal', 'cgc', 'freebsd', 'linux', 'windows'")
	ospass=['android', 'baremetal', 'cgc', 'freebsd', 'linux', 'windows']
	oos=input("->")
	error=0
	for pass1 in ospass:
		if pass1==oos:
			errorbz=0
			error=error-1
			print("-*check pass*-")
			break
		error=error+1
		if error==6:
			print("error-*001*-:Unknown system")
#setarch---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
errorbz=1
while errorbz==1:
	print("输入目标架构:'aarch64', 'alpha', 'amd64', 'arm', 'avr', 'cris', 'i386', 'ia64', 'm68k', 'mips', 'mips64', 'msp430', 'none', 'powerpc', 'powerpc64', 'riscv32', 'riscv64', 's390', 'sparc', 'sparc64', 'thumb', 'vax'")
	arrchpass=['aarch64', 'alpha', 'amd64', 'arm', 'avr', 'cris', 'i386', 'ia64', 'm68k', 'mips', 'mips64', 'msp430', 'none', 'powerpc', 'powerpc64', 'riscv32', 'riscv64', 's390', 'sparc', 'sparc64', 'thumb', 'vax']
	aarch=input("->")
	error=0
	for pass1 in arrchpass:
		if pass1==aarch:
			errorbz=0
			error=error-1
			print("-*check pass*-")
			break
		error=error+1
		if error==22:
			print("error-*002*-:Unknown arch")
#setit-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
context(os=oos, arch=aarch, log_level='debug')
print("请输入要生成的poc位数,这取决于你要测试的目标程序的功能")
number=int(input("->"))
print("请输入ip/域名")
ip=input("->")
print("请输入端口:")
port=input("->")
test=remote(ip,port)
test.close()
print("-*check pass*-")
print("请指定在接收到什么字符串时发送poc:\n1.接收到指定字符串后发送测试poc\n2.接收到指定字符串后发送指定字符串")
sett=int(input("->"))
if sett==1:
	print("将会在在这串字符串后开始测试:")
	teststr1=input("->")
xhjs=0
i='1'
teststr=[]
testpoc=[]
if sett==2:
	while i==1:
		xhjs+=1
		print("接收到此字符串后：")
		teststr.append(input("->"))
		print("会发送：")
		testpoc.append(input("->"))
		print("1.再设置一层 2.结束")
		i=int(input("->"))
if sett!= 1 and sett != 2:
	print("error-*003*-:Unknown command code")
#part1-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
print("进行随机字符串测试")
a=0
while a<5:
	
	a=a+1
	randomstrtest=''.join(random.sample(['z','y','x','w','v','u','t','s','r','q','p','o','n','m','l','k','j','i','h','g','f','e','d','c','b','a','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','I','S','T','U','V','W','X','Y','Z','!','`','~','#','$','%','^','^','&','*','(',')'], number))
	test=remote(ip,port)
	if sett==1:
		test.recvuntil(teststr1)	
	if sett==2:
		xhjs1=0
		while xhjs>xhjs1:
			test.recvuntil(teststr[xhjs])
			test.send(teststr[xhjs])	
	if sett!= 1 and sett != 2:
		print("error-*004*-:Unknown command code")
	test.send(randomstrtest)
	print(str(b'->'+test.recvline()))
	test.close()
#part2-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#大量空字符，大量大地址，重复shell
