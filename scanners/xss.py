import requests
from threading import *
import time
class xss(Thread):

		def __init__(self,u,payload):

				Thread.__init__(self)

				self.u = u
				self.pay = payload
		def run(self):

				self.u = self.u+self.pay 

				print ("- testing : ",self.pay)  

				req = requests.get(self.u)

				if self.pay in req.text:
				#	print ("--SQL injection has been detected :  ",url,i)
					print ()
					good.append(self.pay)

				

def test_xss(u,pay):
	for i in pay :
		t = xss(url,i)
		t.start()


url = input ("Target domain : ")

file_pay = open("injection_xss.txt","r")

l_pay = []

for i in file_pay.readlines():
	i = i.strip("\n")
	l_pay.append(i)

file_pay.close()

y = 0
th = 4
l_2 = []
l_3 = []
good = []
while y <= len(l_pay):

	test_xss(url,l_pay[y:y+th])

	for c in l_pay[y:y+th]:
		l_2.append(c)

	y += y+th 
	time.sleep(0.5)

	if y > len(l_pay):

		for i in l_pay:

			if not i in l_2:

				l_3.append(i)

		test_xss(url,l_3)

print ("===============================\n")

for i in good :
	print ("--XSS found in : ",url,i)
	print()