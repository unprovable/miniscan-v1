# Import the useful stuff...
import requests
import urllib2
import random
import re

# So, this is where we'll define the 'magic' :P
# 
# The aim is to build a basic, functioning, no fuss scanner. To do this, we have 'scanner.py',
# and this just organises the what vulns are processed where. The real work is done here, in
# the 'vulns.py' file. 
# 
# The structure is this:
# 	Base class of 'vuln' - this defines all the basic pieces of a vuln. The title, description, 
#		CVSS score and vector, as well as the basic scanning functions, send_scan_append, which 
#		appends an attack sring to a URL, and send_scan_append, which puts an attack string in
#		a POST request.
#	Vuln classes - here, we define the required specifics for each vuln type. So, XSS doesn't 
#		really have any 'negative response' strings; either the stuff gets reflected or it doesn't
#		(Yes, I'm ignoring DOM based XSS here). 
#
# Now that we have this, we can define child classess. These will inherit all the 'pieces' of 
# the vuln class, and then add their own funtionality and variables. So, they'll usually replace
# the response_pos and response_neg lists appropriately. If they don't then the lists are still 
# there, they're just blank.
#
# Note, this framework currently doesn't support time-based blind SQLi. This wouldn't be too hard 
# build in, but it's not there at the moment.
# 
# Also, at some point, we're going to replace the fixed response strings with response regex - 
# that way we can just regex the output for relevant strings. :D But this is a future problem...
# 
class vuln:
	# here we need to put the standard vuln types and requirements
	# First up is CVSS - by the standard, it needs the score *and* vector
	cvss_score = 10.0
	cvss_vector= "AV:N/AC:L/AU:N/C:C/I:C/A:C"
	# Now a title and Vuln Description
	vuln_title = "Very Serious Problem"
	vuln_desc = "You have a very serious problem."
	# Now define what the test strings list should look like:
	test_strings = [""]
	# as well as the pos and neg response strings:
	responses_pos = [""]
	responses_neg = [""]
	# This is a testing function - it tests the connection, and if the site gives
	# a non-error HTTP response (as in, NOT codes 4xx (401, 403, 404, 418, etc.) 
	# then we can declare that the site is 'live'. We do this by returning a 
	# boolean of 'True' if it's live. Else, we print the error and GTFO!!
	def live_test(self,target):
		try:
			izlive = urllib2.urlopen(target).read()
		except Exception, e:
			print "Host not live or target not valid"
			print "ERR0R: ",e
			return False
		# If we didn't error out, and we got some data back, then we'll continue.
		if izlive is not None:
			print "Target Acquired..."
			return True
		# If we didn't error but got no data, then we're not really testing anything,
		# potentially, so we'll just say 'false' to getting data, and deal with what
		# that might 'mean' later on...
		else:
			return False
	# Now define some scanning methods.
	# Here's one...
	def send_scan_append(self,target):
		# We're going to return a list of responses from our test strings
		resp_list = []
		# Now, we pull the test_strings from whatever child class we're currently in:
		for i in self.test_strings:
			# ... and we try and send them.
			try:
				print "Sending "+i
				# Here comes the magic...
				response = urllib2.urlopen(target+i).read()
				# This is in case we get a blank repsonse... urllib2 handles errors by 
				# giving blank responses...
				if response is not None:
					# However, if we have some data, add it to the end of the list:
					resp_list.append(response)
			#This bit is for any issues with the HTTP request - just a generic error handler
			except Exception, e:
				# OHNOES!!
				print "Error in sending Payload "+i
				print e
				# KTHXCARRYON
				continue
		# WE DUN? Ok, send back what we found...
		return resp_list
		# KTHXBAI
	# Here's another... Fewer comments as it's essentially the same:
	def send_scan_body(self,target):
		resp_list = []
		for i in self.test_strings:
			try:
				print "Sending "+i
				response = urllib2.urlopen(target,i).read()
				if response is not None:
					resp_list.append(response)
			except Exception, e:
				print "Error in sending Payload "+i
				print e
				continue
		return resp_list
	def timed_response(self,target):
		return target

class xss(vuln):
	# So, we've created this class wit hthe argument 'vuln', which tells python that it's a
	# child class of the vuln class. As such, everything we defined above is already here.
	# We can change things before calling methods/variables/etc.
	# 
	# So, we start by defining our test strings:
	test_strings = ["test-string-asdf1234ASDF","<test>","<script>alert(1)</script>"]
	# And here we define our pos responses - which will be the same!
	responses_pos = ["test-string-asdf1234ASDF","<test>","<script>alert(1)</script>"]
	
	def test_xss(self,target):
		print "Scanning for XSS..."
		# First check if the page is live:
		if not self.live_test(target):
			return
		# Now run some tests:
		xss_test=self.send_scan_append(target)
		# So, now xss_test is a list of responses. If that list is empty,
		# it means that we errored out, so we just go to the next scan
		if xss_test is None:
			return
		# However, if we managed to get some responses, then we can now 
		# Go through the reponses...
		for i in xss_test:
			# and in each response, go through our list of positive strings...
			for j in self.responses_pos:
				# ...and if we find one, then we got a response with a positive
				# string in... and you know what that means!! Pwned! :D
				if j in i:
					print "VULN String "+i+" Returned in page"
	
# So, here's a sample vuln class without all the comments so you can read it cleanly.
class xxe(vuln):
	test_strings = ["<test-string>","<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ENTITY file SYSTEM \"file:///proc/1/status\">]><foo>&file;</foo>"]
	responses_pos=["test","boot.ini","root","<test-string>"]
	responses_neg=["error","Error"]
	
	def test_xxe(self,target):
		print "Scanning for XXE..."
		if not self.live_test(target):
			return
		xxe_test=self.send_scan_body(target)
		xxe_test2=self.send_scan_append(target)
		for i in xxe_test2:
			xxe_test.append(i)
		if xxe_test is None:
			return
		for i in xxe_test:
			for j in self.responses_pos:
				if j in i:
					print "VULN!"

