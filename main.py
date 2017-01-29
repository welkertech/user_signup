#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2, cgi, re

def checkUsername(username):
    usernameRE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    if(usernameRE.match(username)):
        return(True)
    else:
        return(False)

def checkPassword(password):
    passwordRE = re.compile(r"^.{3,20}$")
    if(passwordRE.match(password)):
        return(True)
    else:
        return(False)

def checkEmail(email):
    if(email == ""):
        return(True)
    else:
        emailRE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        if(emailRE.match(email)):
            return(True)
        else:
            return(False)

def checkPasswordMatch(Password,password2):
    return(Password == password2)


class MainHandler(webapp2.RequestHandler):
    def get(self):

        userNameError = ""
        passwordError = ""
        passwordMatchError = ""
        emailError = ""

        error = self.request.get("error")

        if error == "username":
            userNameError = "Usernames must be 3-20 letter long, alpha numeric - _"
        elif error == "password":
            passwordError = "password muse be 3-20 letters long"
        elif error == "passwordmatch":
            passwordMatchError = "Password do not match"
        elif error == "email":
            emailError = "not a valid email address"

        content = """<form method="post" action="/SignUp">"""
        content += """<br>Username:<input type="text" name="username"></input></br>""" + userNameError
        content += """<br>Password:<input type="password" name ="password"></input></br>""" + passwordError
        content += """<br>Repeat Password:<input type="password" name="password2"></input></br>""" + passwordMatchError
        content += """<br>Email: <input type="text" name="email"></input></br>""" + emailError
        content += """<input type="submit" value="SignUp"/>"""
        content += """</form>"""
        self.response.write(content)


class SignUpHandler(webapp2.RequestHandler):
    def post(self):
        # look inside the request to figure out what the user typed
        username = cgi.escape(self.request.get("username"))
        password = cgi.escape(self.request.get("password"))
        password2 = cgi.escape(self.request.get("password2"))
        email = cgi.escape(self.request.get("email"))

        if (checkUsername(username) == False):
            self.redirect('/?error=username')
        elif (checkPassword(password) == False):
            self.redirect('/?error=password')
        elif (checkPasswordMatch(password,password2) == False):
            self.redirect('/?error=passwordmatch')
        elif (checkEmail(email) == False):
            self.redirect('/?error=email')
        else:
            content = """<h1>Welcome""" + username + """</h1>"""
            self.response.write(content)
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/SignUp', SignUpHandler)
], debug=True)
