from wtforms import Form, PasswordField, StringField, validators
from wtforms.fields.html5 import EmailField


class LoginForm(Form):
    email = EmailField('Email Address',
                       [validators.DataRequired(message='You need to input email'), validators.Email(),
                        validators.Length(min=8, max=128)])
    password = PasswordField('Password', [
        validators.DataRequired(message='You need to input password'),
        validators.Length(min=8, max=128)])
