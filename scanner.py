import sys
# So, this is how you import a 'custom' module... you need an empty '__init__.py' file
# in order for this to work...
from classes.vulns import *

# This is just some example code showing how classes work. So, dan is an xxe class of vuln
# and we then iterate through the list of test_strings in dan... eeeaaassyyyy....
dan = xss()
for i in dan.test_strings:
	print "Dan's test string is: ",i

# so, first we get our target from the CLI...
target = sys.argv[1]

# Test for xxe (it's as easy as that, as all the 'hard work' is in the class... 
# We can use scanner.py to organise what vulns run when and how. 
# But we're not doing anything fancy... we'll just scan for XSS first:
test=xss()
test.test_xss(target)
# And now we'll scan for XXE...
test = xxe()
test.test_xxe(target)



