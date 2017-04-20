import os
from flask import Flask, render_template, session, redirect, url_for, flash, request
from flask_script import Manager, Shell
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, AnonymousUserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import Form
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import Required, EqualTo, Regexp

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'wow poop'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)
bootstrap = Bootstrap(app)
manager = Manager(app)
db = SQLAlchemy(app)

class LoginForm(Form):
	username = StringField('Username', validators = [Required()])
	password = PasswordField('Password', validators = [Required()])
	remember_me = BooleanField('Keep me logged in')
	submit = SubmitField('Log In')

class RegisterForm(Form):
	username = StringField('Username', validators = [Required()])
	password = PasswordField('Password', validators = [Required()])
	confirm_password = PasswordField('Confirm Password', validators = [Required(), EqualTo('password', message = 'Must match the password field')])
	submit = SubmitField('Submit')
	
	def validate_username(self, field):
		if User.query.filter_by(username=field.data).first():
			raise ValidationError('username already registered')

class GameForm(Form):
	name = StringField('What would you like to name the game?', validators = [Required(), Regexp('^[A-Za-z][A-Za-z0-9_]*$', 0,'Game names must have only letters, numbers, or underscores')])
	submit = SubmitField('Submit')

	def validate_name(self, field):
		if Game.query.filter_by(name=field.data).first():
			raise ValidationError('Game name already registered')

class JoinGame(Form):
	submit = SubmitField('Join Game')

class User(UserMixin, db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key = True)
	username = db.Column(db.String(64), unique = True)
	is_admin = db.Column(db.Boolean, default = False)
	password_hash = db.Column(db.String(128))
	registrations = db.relationship('Registration', backref = 'user')
	games = db.relationship('Game', backref = 'owner')
	
	@property
	def password(self):
		raise AttributeError('Password is not a readable attribute')
	
	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)
	
	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)
	def __repr__(self):
		return '<User %r>' % self.username

class Game(db.Model):
	__tablename__ = 'games'
	id = db.Column(db.Integer, primary_key = True)
	name = db.Column(db.String(64), unique = True)
	has_begun = db.Column(db.Boolean, default = False)
	owner_id = db.Column(db.Integer, db.ForeignKey('users.id')) 
	has_completed = db.Column(db.Boolean, default = False)
	registrations = db.relationship('Registration', backref = 'game')
	def generate_url(self):
		return '/games/' + str(self.name)
	
	def __repr__(self):
		return '<Game %r>' % self.id

class Registration(db.Model):
	__tablename__ = 'registrations'
	id = db.Column(db.Integer, primary_key = True)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
	game_id = db.Column(db.Integer, db.ForeignKey('games.id'))
	score = db.Column(db.Integer, default = 10)
	winner = db.Column(db.Boolean, default = False)
	
	def __repr__(self):
		return '<Registration ID: %r, User: %r, Game ID: %r>, Score: %r' % (self.id, self.user_id, self.game_id, self.score)

@app.route('/', methods = ['GET', 'POST'])
def index():
	return render_template('index.html', User=User)

@app.route('/game/<name>')
@login_required
def game(name, methods = ['GET','POST']):
	exists = False
	game_found = Game.query.filter_by(name=name).first()
	if game_found is not None:
		exists = True
	if exists:
		if game_found.has_completed:
			flash("The winner of this game is " + Registration.query.filter_by(game_id=game_found.id, winner=True).first().user.username)
			return render_template('game.html', name=name, game_found=game_found, Registration=Registration, User=User)
		
		r = Registration.query.filter_by(game_id = game_found.id, user_id = current_user.id).first()
		if game_found.has_begun and r != None and current_user == r.user:
			if r.score == 0:
				flash("You have lost all your points and cannot see the rest of the game until it ends.")
				return redirect(url_for('game_list'))
			num_players_left=0
			potential_winner = current_user
			for reg in Registration.query.filter_by(game_id = game_found.id):
				if reg.score > 0:
					num_players_left += 1
					potential_winner = reg
			if num_players_left == 1:
				potential_winner.winner = True
				game_found.has_completed = True
				flash("Game is complete! " + potential_winner.user.username + " is the winner!")
				
			r = Registration.query.filter_by(user_id = current_user.id, game_id = game_found.id).first()
			r.score -= 1
			db.session.add(r)
			db.session.add(potential_winner)
			db.session.add(game_found)
			db.session.commit()
			if r.score == 9:
				flash('Reminder: refreshing the page will update scores and deduct a point.')
			return render_template('game.html', name=name, game_found=game_found, Registration=Registration, User=User)
		elif not game_found.has_begun:
			return render_template('game.html', name=name, game_found=game_found, Registration=Registration, User=User)
		else:
			flash('That game/lobby does not exist or you are not authorized to view it.')
			return redirect(url_for('game_list'))
	else:
		flash('That game/lobby does not exist or you are not authorized to view it.')
		return redirect(url_for('game_list'))

@app.route('/join/<name>')
@login_required
def join_game(name):
	game_found = Game.query.filter_by(name=name).first()
	if game_found != None and game_found.has_begun == False:
		r = Registration(user_id = current_user.id, game_id = game_found.id)
		db.session.add(r)
		db.session.commit()
		flash("You have joined the game named " + game_found.name)
		return redirect(url_for('game_list'))
	flash("Bad join request. Game has either already started or does not exist.")
	return redirect(url_for('game_list'))

@app.route('/leave/<name>')
@login_required
def leave_game(name):
	game_found = Game.query.filter_by(name=name).first()
	if game_found != None:
		r = Registration.query.filter_by(user_id = current_user.id, game_id = game_found.id).first()
		db.session.delete(r)
		db.session.commit()
		flash('You have left the game named ' + game_found.name)
		return redirect(url_for('game_list'))
	else:
		flash('Game does not exist')
		return redirect(url_for('game_list'))

@app.route('/start/<name>')
@login_required
def start_game(name):
	game_found = Game.query.filter_by(name=name).first()
	if game_found.owner == current_user:
		game_found.has_begun = True
		db.session.add(game_found)
		db.session.commit()
		flash("Your game " + game_found.name + " has now begun.")
		return redirect(url_for('game_list'))
	else:
		flash("Not authorized to do this")
		redirect(url_for('game_list'))

@app.route('/creategame', methods = ['GET','POST'])
def create_game():
	form = GameForm()
	if form.validate_on_submit():
		g = Game(name = form.name.data, owner_id = current_user.id)
		db.session.add(g)
		db.session.commit()
		r = Registration(user_id = current_user.id, game_id = g.id)
		db.session.add(r)
		db.session.commit()
		flash('Game Created')
		return redirect(url_for('game', name = g.name))
	return render_template('creategame.html', form=form)

@app.route('/gamelist')
@login_required
def game_list():
	return render_template('gamelist.html', Game=Game, Registration=Registration, User=User)

@app.route('/login', methods = ['GET','POST'])
def login():
	if current_user in User.query.all():
		flash("You are already logged in!")
		return redirect(url_for('index'))
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username = form.username.data).first()
		if user is not None and user.verify_password(form.password.data):
			login_user(user, form.remember_me.data)
			return redirect(url_for('index'))
		flash('Invalid username or password')
	return render_template('login.html', form = form)

@app.route('/logout')
@login_required
def logout():
	logout_user()
	flash('You have been logged out')
	return redirect(url_for('index'))

@app.route('/register', methods = ['GET','POST'])
def register():
	if current_user in User.query.all():
		flash("You are logged in. Log out before registering a new account.")
		return redirect(url_for('index'))
	form = RegisterForm()
	if form.validate_on_submit():
		user = User(username=form.username.data, password=form.password.data)
		db.session.add(user)
		db.session.commit()
		flash('You can now log in')
		return redirect(url_for('login'))
	return render_template('register.html', form = form)


@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html')

@app.errorhandler(500)
def something_diddled(e):
	return render_template('500.html')

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

def make_shell_context():
	return dict(app=app, db=db, User=User, Game=Game, Registration=Registration)
manager.add_command("shell", Shell(make_context=make_shell_context))

if __name__ == '__main__':
	manager.run()
