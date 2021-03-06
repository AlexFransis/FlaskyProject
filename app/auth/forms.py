from flask.ext.wtf import Form
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import Required, Email, Length, EqualTo, Regexp
from wtforms import ValidationError
from ..models import User

class LoginForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class RegistrationForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
    username = StringField('Username', validators=[Required(), Length(1, 64),
                                                   Regexp('^[A-Za-z][A-Za-z0-9_.]*$',
                                                          0, 'Usernames must have only letters, '
                                                          'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[Required(),
                                                     EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Register')

    ''' The two methods will be invoked on the specified field with the other
    validators to ensure that there is no duplicate data in the database.'''
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already register')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use')

class PasswordResetRequestForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
    submit = SubmitField('Reset Password')

    def validate_email(self, field):
        ''' This validator will verify that the email exits in the database before
        sending the instructions to reset email to the user. '''

        if User.query.filter_by(email=field.data).first() is None:
            raise ValidationError('Unknown email address.')

class PasswordResetForm(Form):
    email = StringField('Enter your email:', validators=[Required(), Length(1, 64), Email()])
    password = PasswordField('New password', validators=[Required(), EqualTo('password2',
                                                                             message='Passwords must match.')])
    password2 = PasswordField('Confirm new passowrd', validators=[Required()])
    submit = SubmitField('Change password')

    def validate_email(self, field):
        ''' This validator will verify that the email exits in the database before
        reseting the password. '''

        if User.query.filter_by(email=field.data).first() is None:
            raise ValidationError('Unknown email address.')
