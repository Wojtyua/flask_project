from enum import unique
from flask import Flask, render_template, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_wtf import wtforms
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Lenght, ValidationError

app = Flask(__name__)
db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'Ww9VH.k:XfJr#?%B' #ranodm generated string

#creating db table
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(30), nullable=False, unique=True)
    name = db.Column(db.String(20), nullable=False)
    last_name = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Lenght(min = 4, max=30)], render_kw={"placeholder": "Email"})
    name = StringField(validators=[InputRequired(), Lenght(min = 4, max=20)], render_kw={"placeholder": "Imie"})
    last_name = StringField(validators=[InputRequired(), Lenght(min = 4, max=20)], render_kw={"placeholder": "Nazwisko"})
    password = StringField(validators=[InputRequired(), Lenght(min = 4, max=20)], render_kw={"placeholder": "Nazwisko"})

    submit = SubmitField("Register")


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')


if __name__ == '__main__':
    app.run(debug=True)
