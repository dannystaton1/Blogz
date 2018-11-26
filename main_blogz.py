from flask import Flask, request, redirect, render_template,session,flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from random import randrange
import hashlib
import string 
import random

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://BLOGZ:1234asdf@localhost:8889/BLOGZ'
app.config['SQLALCHEMY_ECHO'] = True
app.secret_key = b'\\\xcf)2i\rcf\xe8P\xcc\x0c\x9b 9\x16l\xb4\xa9\x8ft\x0e^\x06'
db = SQLAlchemy(app)

class User(db.Model):
	username = db.Column(db.String(50), primary_key=True) 
	password = db.Column(db.String(50))
	posts = db.relationship('Blog', backref='user') 

	def __init__(self, username, password):
		self.username = username
		self.password = password


class Blog(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120))
    body = db.Column(db.String(1024))
    date = db.Column(db.DateTime)
    username = db.Column(db.String(60), db.ForeignKey('user.username')) 

    def __init__(self, title, body, date):
    	self.title = title
    	self.body = body
    	self.date = date    

def make_salt():
	return ''.join([random.choice(string.ascii_letters) for x in range(5)])


        
def make_pw_hash(password, salt=None):
	if not salt:
		salt = make_salt()
	hash = hashlib.sha256(str.encode(password + salt)).hexdigest()
	return '{0},{1}'.format(hash, salt)



def check_pw_hash(password, hash):
	salt = hash.split(',')[1]
	if make_pw_hash(password, salt) == hash:
		return True
	return False


def loggedin ():
    return 'user' in session

@app.route('/', methods=['GET'])
def index():
	users = User.query.all()
	return render_template('index.html', title="Blogz", loggedin=loggedin(), users=users)




@app.route('/post', methods=['GET'])
def post():

	id = request.args.get('id')
	post = Blog.query.get(int (id))
	return render_template('post.html', title=post.title, post=post, signature=True)

@app.route('/ublog', methods=['GET'])
def ublog():

	uname = request.args.get('uname')
	user = User.query.get(uname)
	page = request.args.get('page')
	if (page == None):
		page = "1"
	page = int(page)
	pagination = Blog.query.filter_by(username=user.username).order_by('date DESC').paginate(page, 3, False)
	posts = pagination.items
	return render_template('blog.html', title="Posts by " + user.username, uname=user.username, loggedin=loggedin(), signature=False, posts=posts, pagination=pagination, link="ublog")

@app.route('/blog', methods=['GET'])
def blog():

	page = request.args.get('page')
	if (page == None):
		page = "1"
	page = int(page)
	pagination = Blog.query.order_by('date DESC').paginate(page, 3, False)
	posts = pagination.items
	return render_template('blog.html', title="All Posts", loggedin=loggedin(), signature=True, posts=posts, pagination=pagination, link="blog")

@app.route('/newpost', methods=['GET', 'POST'])
def newpost():

	if (request.method == 'GET'):
		return render_template('newpost.html',title="Add a Blog Entry", loggedin=loggedin())
	else:
		title = request.form ['title']
		body = request.form ['body']
		titleError = ""
		bodyError = ""
		error = False
		if (title == ""):
			titleError = "Please fill in the title"
			error = True
		if (body == ""):
			bodyError = "Please fill in the body"
			error = True
		if error:
			return render_template('newpost.html',title="Add a Blog Entry", loggedin=loggedin(), terror=titleError, berror=bodyError,
				blogTitle=title, blogBody=body)
		blog = Blog(title=title, body=body, date=datetime.utcnow())
		db.session.add(blog)
		db.session.commit()
		return redirect('/post?id=' + str(blog.id))

@app.route("/login", methods=['GET', 'POST'])
def login():
	if request.method == 'GET':
		return render_template('login.html', title="Login", loggedin=loggedin())
	elif request.method == 'POST':
		uerror = None
		perror = None
		username = request.form['username']
		if username == '':
			uerror = "Please enter a username"
		password = request.form['password']
		if password == '':
			perror = "Please enter a password"
		if uerror != None or perror != None:
			return render_template("/login.html", title="Login", loggedin=loggedin(), username=username, uerror=uerror, perror=perror)
		users = User.query.filter_by(username=username)
		if users.count() == 1:
			user = users.first()
			if check_pw_hash(password, user.password):
				session['user'] = user.username
				flash('welcome back, ' + user.username)
				return redirect("/newpost")
			else:
				perror = "Password does not match" 
		else:
			uerror = "No User with the provided username"
		return render_template("/login.html", title="Login", loggedin=loggedin(), username=username, uerror=uerror, perror=perror)

@app.route("/logout", methods=['GET'])
def logout():
    del session['user']
    return redirect("/blog")

@app.route("/signup", methods=['GET', 'POST'])
def register():
	if request.method == 'POST':
		uerror = None
		perror = None
		verror = None
		username = request.form['username']
		password = request.form['password']
		verify = request.form['verify']
		username = request.form['username']
		if username == '':
			uerror = "Please enter a username"
		else:
			db_count = User.query.filter_by(username=username).count()
			if db_count > 0:
				uerror = 'User "' + username + '" already exists'
		password = request.form['password']
		if password == '':
			perror = "Please enter a password"
		else:
			verify = request.form['verify']
			if verify != password:
				verror = "Password does not match confirmation"	
		if uerror != None or perror != None or verror != None:
			return render_template("/signup.html", title="Sign Up", loggedin=loggedin(), username=username, uerror=uerror, perror=perror, verror=verror)
		user = User(username=username, password=password)
		db.session.add(user)
		db.session.commit()
		session['user'] = user.username
		return redirect("/newpost")
	else:
		return render_template('signup.html', title="Sign Up", loggedin=loggedin())

def logged_in_user():
	owner = User.query.filter_by(username=session['user']).first()
	return owner

endpoints_needing_login = ['newpost']

@app.before_request
def require_login():
	if not ('user' in session) and request.endpoint in endpoints_needing_login:
		return redirect("/login")



if __name__ == '__main__':
	app.run()