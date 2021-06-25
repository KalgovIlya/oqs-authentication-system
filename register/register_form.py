from wtforms import Form, PasswordField, StringField, validators
from wtforms.fields.html5 import EmailField


class RegistrationForm(Form):
    email = EmailField('Email Address',
                       [validators.DataRequired(message='You need to input email'), validators.Email(),
                        validators.Length(min=8, max=128)])
    first_name = StringField('First name', [
                            validators.DataRequired(message='You need to input first name'),
                            validators.Length(min=2, max=128)])
    last_name = StringField('Last name', [
                            validators.DataRequired(message='You need to input last name'),
                            validators.Length(min=2, max=128)])
    password = PasswordField('Password', [
                            validators.DataRequired(message='You need to input password'),
                            validators.EqualTo('confirm', message='Passwords must match'),
                            validators.Length(min=8, max=128)])
    confirm = PasswordField('Repeat Password')


class ProfileForm(Form):
    first_name = StringField('First name', [
                            validators.DataRequired(message='You need to input first name'),
                            validators.Length(min=2, max=128)])
    last_name = StringField('Last name', [
                            validators.DataRequired(message='You need to input last name'),
                            validators.Length(min=2, max=128)])
