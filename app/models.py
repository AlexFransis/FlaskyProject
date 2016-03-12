from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask.ext.login import UserMixin
from . import login_manager
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app
from . import db

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', backref='role')

    def __repr__(self):
        return '<Role %r>' % self.name

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    confirmed = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return '<User %r>' % self.username

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration) # takes a key and an expiration time
        return s.dumps({'confirm': self.id}) # the data encrypted is the user's id

    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id})

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try: # will verify if token is not expired
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id: # will verify if data matches the id of current_user
            return False
        self.confirmed = True # will confirm user and update database
        db.session.add(self)
        return True

    def reset_password(self, token, new_password):
        ''' This function will take a token and a new password as arguments. It will verify if
        the token is not expired. It will also check the the ID from the token matches the ID of
        the user. If both conditions are met, it will replace the current password of the user with
        the new one that is passed in the function which is usually obtained from a form
        and will add it to the database. '''

        s = Serializer(current_app.config['SECRET_KEY'])
        try: # this will verify if it can load the data from the token and if it is not expired
            data = s.loads(token)
        except:
            return False
        if data.get('reset') != self.id: # if the id from the token does not match the email's id return False
            return False
        self.password = new_password
        db.session.add(self)
        return True
