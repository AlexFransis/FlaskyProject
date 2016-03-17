from datetime import datetime
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask.ext.login import UserMixin, AnonymousUserMixin
from . import login_manager
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app
from . import db

class Permission:
    ''' The following are the permissions available to each type of users:
    FOLLOW: Follow other users
    COMMENT: Comment on articles written by others
    WRITE_ARTICLES: Write original articles
    MODERATE_COMMENTS: Suppress offensive comments made by users
    ADMINISTER: Administrative access to the website '''

    FOLLOW = 0x01
    COMMENT = 0x02
    WRITE_ARTICLES = 0x04
    MODERATE_COMMENTS = 0x08
    ADMINISTER = 0x80

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __repr__(self):
        return '<Role %r>' % self.name

    @staticmethod
    def insert_roles():
        ''' This method allows to add or modify roles in the database easily.
        To add a new role simply add it to the roles dictionary with its permissions. '''

        roles = {
            'User': (Permission.FOLLOW | Permission.COMMENT | Permission.WRITE_ARTICLES, True),
            'Moderator': (Permission.FOLLOW | Permission.COMMENT | Permission.WRITE_ARTICLES |
                          Permission.MODERATE_COMMENTS, False),
            'Administrator': (0xff, False)
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()

class User(UserMixin, db.Model):
    ''' UserMixin provides default implementations for the methods that Flask-Login
    expects user objects to have. '''

    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64)) # real name of user
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)

    def __init__(self, **kwargs):
        ''' The constructor of the base class will set the role for the user. If the email
        is that of the administrator, the user is given administrator permissions. Otherwise
        the user is given default user permissions. '''

        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()

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

    def can(self, permissions):
        ''' The can() method performs a bitwise and operation between the requested permissions
        and the permissions of the assigned role. Returns True if all the requested bits are
        present in the role and will allow the user to perform the task. '''

        return self.role is not None and (self.role.permissions & permissions) == permissions

    def is_administrator(self):
        ''' The is_administrator() method performs the can() method for the ADMINISTER
        permission. '''

        return self.can(Permission.ADMINISTER)

    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)

class AnonymousUser(AnonymousUserMixin):
    ''' This class allows us to check the permissions for the user that is not logged in
    instead of verifying if the user is logged in THEN performing the permissions verifications.
    All permissions are set to False for the user that is anonymous. '''

    def can(self, permissions):
        return False

    def is_administrator(self):
        return False

login_manager.anonymous_user = AnonymousUser
