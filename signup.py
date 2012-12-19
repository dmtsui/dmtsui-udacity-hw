import re

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	if USER_RE.match(username):
		return True
	else: 
		return False

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    if(PASS_RE.match(password)):
        return True
    else:
        return False
        

EMAIL_RE  = re.compile(r"^[\S]+@[\S]+\.[\S]+")
def valid_email(email):
    if (EMAIL_RE.match(email) ):
    	return True
    else:
    	return False
