import os
from flask import Flask, render_template, session, redirect, url_for, flash, request
from flask_script import Manager, Shell
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, AnonymousUserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import Form
from wtforms import StringField, SubmitField, PasswordField, BooleanField, SelectField, ValidationError, IntegerField
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

#FORMS
class LoginForm(Form):
	username = StringField('Username', validators = [Required()])
	password = PasswordField('Password', validators = [Required()])
	remember_me = BooleanField('Keep me logged in')
	submit = SubmitField('Log In')

class RegisterForm(Form):
	username = StringField('Username', validators = [Required()])
	first_name = StringField('First Name', validators = [Required()])
	last_name = StringField('Last Name', validators = [Required()])
	password = PasswordField('Password', validators = [Required()])
	confirm_password = PasswordField('Confirm Password', validators = [Required(), EqualTo('password', message = 'Must match the password field')])
	card_number = StringField('Credit Card #', validators = [Required(), Regexp('^[0-9]*$', 0, 'Must only be a number')])
	month = SelectField('Expiration Month', coerce = int,  choices = [(1, 'January'), (2, 'February'), (3, 'March'), (4, 'April'), (5, 'May'), (6, 'June'), (7, 'July'), (8, 'August'), (9, 'September'), (10, 'October'), (11, 'November'), (12, 'December')])
	year = SelectField('Expiration Year', choices = [('2017', '2017'), ('2018', '2018'), ('2019', '2019'), ('2020','2020'), ('2021','2021'), ('2022','2022'), ('2023', '2023') ])
	security_code = IntegerField(validators = [Required()])
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

class FlightSearch(Form):
	departing_airport = StringField('Departing Airport', validators = [Required()])
	arriving_airport = StringField('Arriving Airport', validators = [Required()])
	month = SelectField('Month', coerce = int,  choices = [(1, 'January'), (2, 'February'), (3, 'March'), (4, 'April'), (5, 'May'), (6, 'June'), (7, 'July'), (8, 'August'), (9, 'September'), (10, 'October'), (11, 'November'), (12, 'December')])
	day = SelectField('Day', coerce = int, choices = [(1, '01'), (2, '02'), (3, '03'), (4, '04'), (5, '05'), (6, '06'), (7, '07'), (8, '08'), (9, '09'), (10, '10'), (11, '11'), (12, '12'), (13, '13'), (14, '14'), (15, '15'), (16, '16'), (17, '17'), (18, '18'), (19, '19'), (20, '20'), (21, '21'), (22, '22'), (23, '23'), (24, '24'), (25, '25'), (26, '26'), (27, '27'), (28, '28'), (29, '29'), (30, '30'), (31, '31')])
	year = SelectField(u'Year', choices = [('2017', '2017'), ('2018', '2018'), ('2019', '2019')])
	submit = SubmitField('Search')

class AirportSearch(Form):
	airport = StringField('Airport', validators=[Required()])
	submit = SubmitField('Search')

class CreateFlight(Form):
	departing_airport = StringField('Departing Airport', validators = [Required()])
	arriving_airport = StringField('Arriving Airport', validators = [Required()])
	month = SelectField('Month', coerce = int,  choices = [(1, 'January'), (2, 'February'), (3, 'March'), (4, 'April'), (5, 'May'), (6, 'June'), (7, 'July'), (8, 'August'), (9, 'September'), (10, 'October'), (11, 'November'), (12, 'December')])
	day = SelectField('Day', coerce = int, choices = [(1, '01'), (2, '02'), (3, '03'), (4, '04'), (5, '05'), (6, '06'), (7, '07'), (8, '08'), (9, '09'), (10, '10'), (11, '11'), (12, '12'), (13, '13'), (14, '14'), (15, '15'), (16, '16'), (17, '17'), (18, '18'), (19, '19'), (20, '20'), (21, '21'), (22, '22'), (23, '23'), (24, '24'), (25, '25'), (26, '26'), (27, '27'), (28, '28'), (29, '29'), (30, '30'), (31, '31')])
	year = SelectField('Year', choices = [('2017', '2017'), ('2018', '2018'), ('2019', '2019')])
	price = IntegerField('Price', validators = [Required()])
	time = StringField('Time', validators = [Required()])
	submit = SubmitField('Create')

#MODELS

class User(UserMixin, db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key = True)
	username = db.Column(db.String(64), unique = True)
	first_name = db.Column(db.String(64))
	last_name = db.Column(db.String(64))
	payment_info_id = db.Column(db.Integer, db.ForeignKey('paymentinfo.id'))
	is_admin = db.Column(db.Boolean, default = False)
	password_hash = db.Column(db.String(128))
	registrations = db.relationship('Registration', backref = 'user')
	games = db.relationship('Game', backref = 'owner')
	reservations = db.relationship('Reservation', backref = 'flight')
	
	
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
class Airport(db.Model):
	__tablename__ = 'airports'
	id = db.Column(db.Integer, primary_key = True)
	airport_name = db.Column(db.String(64), unique = True)
	airport_code = db.Column(db.String(3), unique = True)

class Flight(db.Model):
	__tablename__ = 'flights'
	id = db.Column(db.Integer, primary_key = True)
	departing_airport = db.Column(db.String(3)) 
	arriving_airport = db.Column(db.String(3)) 
	price = db.Column(db.Integer)
	month = db.Column(db.Integer)
	day = db.Column(db.Integer)
	year = db.Column(db.String(4))
	is_full = db.Column(db.Boolean, default = False)
	time = db.Column(db.String(64)) 
	reservations = db.relationship('Reservation', backref = 'reserved_flight')
	def __repr__(self):
		return '<departing from %r and going to %r>' % (self.departing_airport, self.arriving_airport)
	
	# TODO, TIME AND POTENTIALLY DATE FOR ARRIVING AND DEPARTING

class Reservation(db.Model):
	__tablename__ = 'reservations'
	id = db.Column(db.Integer, primary_key = True)
	flight_id = db.Column(db.Integer, db.ForeignKey('flights.id'))
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
	confirmed = db.Column(db.Boolean, default = False)


class PaymentInfo(db.Model):
	__tablename__ = 'paymentinfo'
	id = db.Column(db.Integer, primary_key = True)
	card_num = db.Column(db.String(16))
	exp_month = db.Column(db.Integer) 
	exp_year = db.Column(db.String(4))
	security_code = db.Column(db.Integer)
	payment_owner = db.relationship('User', backref = 'paymentowner')

#CONTROLLERS

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


@app.route('/reserve/<flightno>')
@login_required
def reserve_flight(flightno):
	if not Reservation.query.filter_by(flight_id = int(flightno), user_id = current_user.id).all():
		r = Reservation(flight_id = int(flightno), user_id = current_user.id)
		db.session.add(r)
		db.session.commit()
		flash('Flight #' + flightno + ' has been reserved for you. Be sure to confirm the reservation by purchasing it.')
		return redirect(url_for('index'))
	else:
		flash('You have already reserved this flight.')
		return redirect(url_for('index'))

@app.route('/deletereservation/<flightno>')
@login_required
def delete_reservation(flightno):
	if not Reservation.query.filter_by(flight_id = int(flightno), user_id = current_user.id).all():
		flash('You cannot cancel this reservation because you do not have it reserved.')
		return redirect(url_for('index'))
	else:
		r = Reservation.query.filter_by(flight_id = int(flightno), user_id = current_user.id).first()
		if r.confirmed:
			flash('Reservation Canceled. Your money has been refunded.')
		else:
			flash('Reservation Canceled.')
		db.session.delete(r)
		db.session.commit()
		
		return redirect(url_for('index'))

@app.route('/confirmreservation/<flightno>')
@login_required
def confirm_reservation(flightno):
	if not Reservation.query.filter_by(flight_id = int(flightno), user_id = current_user.id).all():
		flash('You cannot confirm this reservation because you do not have it reserved.')
		return redirect(url_for('my_reservations'))
	else:
		r = Reservation.query.filter_by(flight_id = int(flightno), user_id = current_user.id).first()
		r.confirmed = True
		db.session.commit()
		flash('Reservation Confirmed. A seat is now guaranteed on your plane.')
		return redirect(url_for('my_reservations'))

@app.route('/myreservations')
@login_required
def my_reservations():
	return render_template('myreservations.html', Reservation=Reservation, Flight=Flight, User=User)

@app.route('/createflight', methods = ['GET','POST'])
@login_required
def create_flight():
	form = CreateFlight()
	if form.validate_on_submit():
		f = Flight(departing_airport = form.departing_airport.data, arriving_airport = form.arriving_airport.data, price = form.price.data, month = form.month.data, day = form.day.data, year = form.year.data, time = form.time.data)
		db.session.add(f)
		db.session.commit()
		flash('Flight Created')
		return redirect(url_for('index'))
	return render_template('createflight.html', form=form, User=User)

@app.route('/searchflights', methods = ['GET','POST'])
def search_flights():
	form1 = FlightSearch()
	form2 = AirportSearch()
	if form1.validate_on_submit():
		return redirect(url_for('flight_list', Flight = Flight, User = User, dep = form1.departing_airport.data, arriv = form1.arriving_airport.data, mon = form1.month.data, d = form1.day.data, yr = form1.year.data))
	if form2.validate_on_submit():
		return render_template('flightlist2.html', airport = form2.airport.data, Flight = Flight)
	return render_template('flightsearch.html', form1=form1, form2 = form2)

@app.route('/flightlist/<dep>/<arriv>/<mon>/<d>/<yr>')
def flight_list(dep, arriv, mon, d, yr):
	return render_template('flightlist.html', Flight=Flight, User=User, departing = dep, arriving = arriv, month = mon, day = d, year = yr)

@app.route('/flight/<flightno>')
@login_required
def flight(flightno, methods = ['GET','POST']):
	if (not Flight.query.filter_by(id = flightno).first()):
		flash('This flight does not exist')
		return redirect(url_for('index'))
	return render_template("flight.html", flightno = int(flightno), flight = Flight.query.filter_by(id = flightno).first(), User = User, Reservation = Reservation, Flight = Flight)

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
		user = None
		payment_inf = None
		payment_inf = PaymentInfo(card_num = form.card_number.data, exp_month = form.month.data, security_code = form.security_code.data, exp_year = form.year.data)
		if form.username.data == 'Admin':
			user = User(username=form.username.data, password=form.password.data, is_admin = True, first_name = form.first_name.data, last_name = form.last_name.data, payment_info_id = payment_inf.id)
		else:
			user = User(username=form.username.data, password=form.password.data, first_name = form.first_name.data, last_name = form.last_name.data, payment_info_id = payment_inf.id)
		db.session.add(payment_inf)
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
