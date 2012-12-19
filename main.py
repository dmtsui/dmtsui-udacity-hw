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
import webapp2
import string
import os
import re       #regular expression lib
import cgi
import jinja2   #html template lib
import hashlib
import hmac
import json

from google.appengine.ext import db
from google.appengine.api import memcache

from caesar_shift import *
from signup import *

secret = "mysecret!!"

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

navigation = [("/","Main"),("/rot13","ROT13"),("/blog/signup","Sign Up Page"),("/blog","Blog"),('/blog/newpost', "Post"), ('/blog/login', "Login")]


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BaseHandler(webapp2.RequestHandler):
    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    def render_json(self,d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')


class MainPage(BaseHandler):
    p = dict(navigation = navigation, current = '/')
    def get(self):
        self.render('main.html', **self.p)

#Blog

class Post(db.Model):
    p_id = db
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def as_dict(self):
        time_fmt = '%c'
        d = {'subject': self.subject,
             'content': self.content,
             'created': self.created.strftime(time_fmt),
             'last_modified': self.last_modified.strftime(time_fmt)}

        return d


class Blog(BaseHandler):

    def get(self):
        p = dict(navigation = navigation, current = '/blog')
        p["posts"] = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10 ")

        if self.request.url.endswith('.json'):
            self.format ='json'
            self.render_json( [post.as_dict() for post in p['posts']])

        else:
            self.format = 'html'      
            self.render('post.html', **p)

class NewPost(BaseHandler):
    def get(self):
        p = dict(navigation = navigation, current = '/newpost')
        self.render('newpost.html', **p)

    def post(self):
        p = dict(navigation = navigation, current = '/blog')
        p["subject"] = self.request.get('subject')
        p["content"] = self.request.get('content')

        if p["subject"] and p["content"]:
            new_post = Post(subject = p["subject"], content = p["content"])
            new_post.put()
            self.redirect('/blog/%s' % str(new_post.key().id()))
        else:
            p["error"] = "subject and content, please!"
            self.render("newpost.html", **p)



class PostPage(BaseHandler):
    
    def get(self, post_id):

        p = dict(navigation = navigation, current = '')
        key = db.Key.from_path('Post', int(post_id))
        p["post"] = db.get(key)

        if not p["post"]:
            self.error(404)
            return

        if self.request.url.endswith('.json'):
            self.format ='json'
            self.render_json(p['post'].as_dict())
        else:
            self.format = 'html'
            self.render("permalink.html", **p)

#Login

class Login(BaseHandler):
    p = dict(navigation = navigation, current = '/login')
    def get(self):
        self.render('login-form.html', **self.p)
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        if User.all().filter("name = ",username).count()>0 and make_secure_val(password) == User.all().filter("name = ",username).get().pw_hash: 
            login_user = User.all().filter("name = ",username).get()
            self.login(login_user)
            self.redirect('/blog/welcome') 
        else:
            self.p['error'] = "Invalid username or password"
            self.render('login-form.html', **self.p)      

class Logout(BaseHandler):
    def get(self):
        p = dict(navigation = navigation, current = '/login')
        self.response.headers.add_header('Set-Cookie','user_id =; Path=/')
        self.redirect('/blog/signup')


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()



#ROT13 

class ROT13(BaseHandler):
    p = dict(navigation = navigation, current = '/rot13', text='')
    def get(self):
        self.render('rot13-form.html', **self.p)

    def post(self):
        user_input = self.request.get('text')
        self.p['text'] = shift(user_input)
        self.render('rot13-form.html', **self.p)

class SignUp(BaseHandler):
    p = dict(navigation = navigation, current = '/signup',
            username = '', email = '',
            error_username = False, error_password = False, 
            error_verify = False , error_email = False)
    def get(self):
        self.p = dict(navigation = navigation, current = '/signup',
            username = '', email = '',
            error_username = False, error_password = False, 
            error_verify = False , error_email = False)
        self.render('signup-form.html', **self.p)

    def post(self):
        self.p['username'] = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        self.p['email'] = self.request.get('email')

        if self.p['username'] == '':
            self.p['error_username'] = True
        else:    
            self.p['error_username'] = not(valid_username(self.p['username']))

        if password == '':
               self.p['error_password'] = True
        else:
            self.p['error_password'] = not(valid_password(password))

        if not self.p['error_password'] and password != '':
            if password != verify:
                self.p['error_verify'] = True
            else:
                self.p['error_verify'] = False
        
        if self.p['email'] != '':
            self.p['error_email'] = not(valid_email(self.p['email']))

        if True in (self.p['error_username'], self.p['error_password'],self.p['error_verify'],self.p['error_email']):
            self.render('signup-form.html', **self.p)
        elif User.all().filter("name = ",self.p['username'] ).count()>0:        
            self.render('signup-form.html', **self.p)
            
        else:
            new_user = User(name = self.p['username'], pw_hash = make_secure_val(password), email = self.p['email'] )
            new_user.put()
            self.login(new_user)
            self.redirect('/blog/welcome')

class Welcome(BaseHandler):
    def get(self):
        user_hash = self.request.cookies.get("user_id", None)

        if user_hash and check_secure_val(user_hash):
            current_user = User.get_by_id(int(check_secure_val(user_hash)))
            p = dict( navigation = navigation, username = current_user.name)


        
        self.render('welcome.html', **p )





app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/rot13',ROT13),
    ('/blog/signup', SignUp),
    ('/blog/welcome', Welcome),
    ('/blog/?(?:\.json)?', Blog),
    ('/blog/([0-9]+)(?:\.json)?', PostPage),
    ('/blog/newpost', NewPost),
    ('/blog/login', Login),
    ('/blog/logout', Logout)
], debug=True)
