import os
from flask import Flask, session, render_template, redirect, url_for, flash, request
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
    netid = db.Column(db.String(64), unique = True, index = True)
    password_hash = db.Column(db.String(128))
    firstname = db.Column(db.String(64), index = True)
    lastname = db.Column(db.String(64), index = True)
    email = db.Column(db.String(64), index = True)

    description = db.relationship('Description')
    profile = db.relationship('Profile')

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

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

class UserForm(FlaskForm):
    netid = StringField("NetID: ", validators=[DataRequired()])
    fname = StringField("First name: ", validators=[DataRequired()])
    lname = StringField("Last name: ", validators=[DataRequired()])
    email = StringField("Email: ", validators=[DataRequired()])
    password = PasswordField("Password: ", validators=[DataRequired()])
    submit = SubmitField("Register")

class DescriptionForm(FlaskForm):
    classyear = StringField("Enter your class year: ", validators=[DataRequired()])
    major = StringField("Enter your major: ", validators=[DataRequired()])
    bio = StringField("Enter a short bio: ", validators=[DataRequired()])
    submit = SubmitField("Add description")

class ProfileForm(FlaskForm):
    industry = StringField("What industries are you interested in?", validators=[DataRequired()])
    role = StringField("What roles are you interested in?", validators=[DataRequired()])
    subject = StringField("What do you want your sessions to focus on?", validators=[DataRequired()])
    organizations = StringField("What student organizations are you involved in?", validators=[DataRequired()])
    bio = StringField("Comments:", validators=[DataRequired()])
    submit = SubmitField("Add preferences")

class LoginForm(FlaskForm):
    netid = StringField("NetID: ", validators=[DataRequired()])
    password = PasswordField("Password: ", validators=[DataRequired()])
    remember_me = BooleanField("Keep me logged in")
    submit = SubmitField("Log In")

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

class DeleteForm(FlaskForm):
    netid = StringField("Enter the NetID to remove: ", validators=[DataRequired()])
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
        netid = form.netid.data
        fname = form.fname.data
        lname = form.lname.data
        pw = form.password.data
        email = form.email.data
        session['userdata'] = (netid, fname, lname, email, pw)
        return redirect(url_for("register_2"))

    return render_template("register.html", form = form)

@app.route("/register_2", methods = ["GET", "POST"])
def register_2():
    form = DescriptionForm()

    if(form.validate_on_submit()):
        classyear = form.classyear.data
        major = form.major.data
        bio = form.bio.data
        session['descriptiondata'] = (classyear, major, bio)
        return redirect(url_for("register_3"))

    return render_template("register_2.html", form = form)

@app.route("/register_3", methods = ["GET", "POST"])
def register_3():
    form = ProfileForm()

    if(form.validate_on_submit()):
        industry = form.industry.data
        role = form.role.data
        subject = form.subject.data
        organizations = form.organizations.data
        bio = form.bio.data

        userdata = session.get('userdata', None)
        descriptiondata = session.get('descriptiondata', None)

        createUser(data[0], data[1], data[2], data[3], data[4])
        return redirect(url_for("home"))

    return render_template("register_3.html", form = form)

@app.route("/delete", methods = ["GET", "POST"])
def delete():
    form = DeleteForm()

    if(form.validate_on_submit()):
        netid = form.netid.data
        deleteUser(netid)
        return redirect(url_for("home"))

    return render_template("delete.html", form = form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(netid = form.netid.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get("next")
            if next is None or not next.startswith("/"):
                next = url_for("home")
            return redirect(next)
        flash("Invalid NetID or password.")
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

def createUser(netid, fname, lname, email, pw):
    user = User(netid = netid, firstname = fname, lastname = lname, email = email, password = pw)
    db.session.add(user)
    db.session.commit()

def deleteUser(netid):
    user = User.query.filter_by(netid = netid).first()
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
