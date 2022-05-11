from flask import Flask, render_template, url_for, redirect, flash, abort, request
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
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(30), nullable=False, unique=True)
    name = db.Column(db.String(20), nullable=False)
    last_name = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(80), nullable=False)
    login_count = db.Column(db.Integer, nullable=False, default=0)
    isAdmin = db.Column(db.Boolean(), nullable=False, default=False)


class RegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min = 4, max=30)], render_kw={"placeholder": "Email"})
    name = StringField(validators=[InputRequired(), Length(min = 4, max=20)], render_kw={"placeholder": "Imie"})
    last_name = StringField(validators=[InputRequired(), Length(min = 4, max=20)], render_kw={"placeholder": "Nazwisko"})
    password = PasswordField(validators=[InputRequired(), Length(min = 4, max=20)], render_kw={"placeholder": "Hasło"})

    submit = SubmitField("Register")

class UserForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min = 4, max=30)], render_kw={"placeholder": "Email"})
    name = StringField(validators=[InputRequired(), Length(min = 4, max=20)], render_kw={"placeholder": "Imie"})
    last_name = StringField(validators=[InputRequired(), Length(min = 4, max=20)], render_kw={"placeholder": "Nazwisko"})
    password = PasswordField(validators=[Length(min = 4, max=20)], render_kw={"placeholder": "Hasło"})

    submit = SubmitField("Update")

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(
            email = email.data).first()
        if existing_user_email:
            raise ValidationError("Email zajety")

class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min = 4, max=30)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min = 4, max=20)], render_kw={"placeholder": "Hasło"})

    submit = SubmitField("Login")


@app.route('/home', methods=['GET', 'POST'])
def home():
    return render_template('home.html')



@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                #incrementing login count in database
                user.login_count = User.login_count + 1
                db.session.commit()
                              
                login_user(user)
                flash(f"You have been logged in as {current_user.name}")
                return redirect(url_for('home'))

    return render_template('login.html', form=form)



@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You have been logged out")
    return redirect(url_for('home'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user
    return redirect(url_for('home'))
'''
@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    form = UserForm()
    name_to_update = User.query.get_or_404(id)
    if request.method == "POST":
        name_to_update.email = request.form['email']
        name_to_update.name = request.form['name']
        name_to_update.last_name = request.form['last_name']
        name_to_update.password = request.form['password']
        try:
            db.session.commit()
            flash("User updated successfully!")
            return redirect('/admin')
        except:
            flash("Error! Try again.")
            return render_template("update.html", form=form, name_to_update = name_to_update)
    else:
         return render_template("update.html", form=form, name_to_update = name_to_update)
'''

@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(name=form.name.data, email=form.email.data, last_name=form.last_name.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if(current_user.isAdmin == True):
        all_users = User.query.all()
        return render_template('admin.html', users = all_users)
    else:
        return redirect(url_for('home'))

@app.route('/admin/<int:id>/update', methods=['GET', 'POST'])
@login_required
def adminUpdate(id):
    if(current_user.isAdmin == True):
        user = User.query.filter_by(id=id).first()
        form = UserForm()

        if request.method == "POST":
            user.email = request.form['email']
            user.name = request.form['name']
            user.last_name = request.form['last_name']
            if(len(request.form['password']) != 0):
                hashed_password = bcrypt.generate_password_hash(request.form['password'])
                user.password = hashed_password
                
            try:
                db.session.commit()
                return redirect('/admin')
            except:
                return render_template("update.html", form=form, user = user)
        else:
            return render_template("update.html", form=form, user = user)


@app.route('/admin/<int:id>/delete', methods = ['GET','POST'])
@login_required
def delete(id):
    if(current_user.isAdmin == True):
        user = User.query.filter_by(id=id).first()
        if user: 
            db.session.delete(user)
            db.session.commit()
            return redirect('/admin')
        else:
            abort(404)

@app.route('/top_users', methods=['GET', 'POST'])
def topUsers():
    #return all users by login count 
    top_users = db.session.query(User).order_by(User.login_count.desc()).limit(3)
    return render_template('top_users.html', users = top_users)


if __name__ == "__main__":
    app.run(debug=True)