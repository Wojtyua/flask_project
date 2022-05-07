from re import template
import bcrypt
from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'Ww9VH.k:XfJr#?%B' #ranodm generated string

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#creating db table
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(30), nullable=False, unique=True)
    name = db.Column(db.String(20), nullable=False)
    last_name = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(80), nullable=False)

#register form
class RegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min = 4, max=30)], render_kw={"placeholder": "Email"})
    name = StringField(validators=[InputRequired(), Length(min = 4, max=20)], render_kw={"placeholder": "Imie"})
    last_name = StringField(validators=[InputRequired(), Length(min = 4, max=20)], render_kw={"placeholder": "Nazwisko"})
    password = PasswordField(validators=[InputRequired(), Length(min = 4, max=20)], render_kw={"placeholder": "Hasło"})

    submit = SubmitField("Register")

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(
            email = email.data).first()
        if existing_user_email:
            raise ValidationError("Email zajety")



class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min = 4, max=30)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min = 4, max=20)], render_kw={"placeholder": "Hasło"})

    submit = SubmitField("Login")


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(name=form.name.data, email=form.email.data, last_name=form.last_name.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
