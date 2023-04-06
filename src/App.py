import os
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from flask_login import login_manager
from flask_login import LoginManager

from flask_login import login_required, current_user
from flask_login import login_user, logout_user

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "data.sqlite")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "abc123"

db = SQLAlchemy(app)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(64), unique = True, index = True)
    password_hash = db.Column(db.String(128))
    firstname = db.Column(db.String(64), index = True)
    lastname = db.Column(db.String(64), index = True)
    email = db.Column(db.String(64), index = True)
    job = db.Column(db.String(64), index = True)
    description = db.relationship('Description')
    profile = db.relationship('profile')

    @property
    def password(self):
        raise AttributeError("password is not a readable attribute")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

class Description(db.Model):
    __tablename__ = "description"
    id = db.Column(db.Integer, primary_key = True)
    classyear = db.Column(db.String(64), index = True)
    major = db.Column(db.String(64), index = True)
    minor = db.Column(db.String(64), index = True)
    cluster = db.Column(db.String(64), index = True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

class Profile(db.Model):
    __tablename__ = "profile"
    id = db.Column(db.Integer, primary_key = True)
    industry = db.Column(db.String(64), index = True)
    role = db.Column(db.String(64), index = True)
    subject = db.Column(db.String(64), index = True)
    organizations = db.Column(db.String(64), index = True)
    bio = db.Column(db.String(64), index = True)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

class UserForm(FlaskForm):
    username = StringField("Enter a username: ", validators=[DataRequired()])
    fname = StringField("Enter your first name: ", validators=[DataRequired()])
    lname = StringField("Enter your last name: ", validators=[DataRequired()])
    password = PasswordField("Password: ", validators=[DataRequired()])
    submit = SubmitField("Register")

class DescriptionForm(FlaskForm):
    classyear = StringField("Enter your class year: ", validators=[DataRequired()])
    major = StringField("Enter your major: ", validators=[DataRequired()])
    bio = StringField("Enter a short bio: ", validators=[DataRequired()])
    submit = SubmitField("Add Description")

class LoginForm(FlaskForm):
    username = StringField("Username: ", validators=[DataRequired()])
    password = PasswordField("Password: ", validators=[DataRequired()])
    remember_me = BooleanField("Keep me logged in")
    submit = SubmitField("Log In")

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

class DeleteForm(FlaskForm):
    username = StringField("Enter the username to remove: ", validators=[DataRequired()])
    submit = SubmitField("Delete User")

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

@app.route("/")
def index():
    return render_template("start.html")

@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/register", methods = ["GET", "POST"])
def register():
    form = UserForm()

    if(form.validate_on_submit()):
        username = form.username.data
        fname = form.fname.data
        lname = form.lname.data
        pw = form.password.data
        createUser(username, fname, lname, pw)
        return redirect(url_for("home"))

    return render_template("register.html", form = form)

@app.route("/delete", methods = ["GET", "POST"])
def delete():
    form = DeleteForm()

    if(form.validate_on_submit()):
        username = form.username.data
        deleteUser(username)
        return redirect(url_for("home"))

    return render_template("delete.html", form = form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get("next")
            if next is None or not next.startswith("/"):
                next = url_for("home")
            return redirect(next)
        flash("Invalid username or password.")
    return render_template("login.html", form = form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for("home"))

@app.route("/mentors", methods = ["GET"])
@login_required
def mentors():
    users = User.query.all()
    return render_template("mentors.html", users=users)

@app.errorhandler(404)
def page_not_found(e):
    return render_template("page_not_found.html"), 404
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

def createUser(username, fname, lname, pw):
    user = User(username = username, firstname = fname, lastname = lname, password = pw)
    db.session.add(user)
    db.session.commit()

def deleteUser(username):
    user = User.query.filter_by(username = username).first()
    if(user != None):
        db.session.delete(user)
        db.session.commit()

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

login_manager = LoginManager()
login_manager.login_view = "login"

login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_first_request
def create_tables():
    db.create_all()

@app.before_first_request
def init_app():
    logout_user()

if __name__ == '__main__':
    app.run()
