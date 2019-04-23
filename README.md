# Flask-AuthOOB

this library is Fask Authentication Out of the Box and make it fast and simple to add an authentication layer to a flask app for apis.

This library is based on [Flask-Security](https://pythonhosted.org/Flask-Security/) that already provides authentication tools in a very opiniated way. Flask-AuthOOB defines as many settings and routes as possible so that you can quickly implement authentication to a newly created flask app.

## Implementation

So the boiler plate for Flask Autentication using this library looks like

```python
from flask import Flask, request

app = Flask(__name__)
db = SQLAlchemy()
authoob = AuthOOB(app, db)
```

And that's all !

## Library options

it is possible to init library at the right time like this

```python
# With other extensions
authoob = AuthOOB()

# Later in code when the context is ready
authoob.init_app(app, db)
```

Then you can reach Authentication objects from authoob instance. for exemple let query users table :

```python
from app import authoob
authoob.User.query.filter_by(email='armin.ronacher@pocoo.org').count()
```

Available variables in the **authoob** instance are:

```python
authoob.User
authoob.Role
authoob.roles_users
```

These models are almost the one given in Flask-Security implementation exemple

## Authentication endpoints

When the extention is properly loaded some default routes are defined as following:

```javascript
{
    method: 'POST',
    route: '/authoob/register',
    payload: {"email": "register@mail.com", "password1": "1Password", "password2": "1Password"},
    success_response: {token: 'AJWT token'},
    fail_response: {code: '4xx', message: 'message'}
}

{
    method: 'POST',
    route: '/authoob/login',
    payload: {"email": "register@mail.com", "password": "1Password"},
    success_response: {token: 'AJWT token'},
    fail_response: {code: '4xx', message: 'message'}
}

{
    method: 'GET'
    route: '/authoob/token'
    headers: {"Authentication-Token": 'AJWT token'}
    success_response: {token: 'AJWT token'},
    fail_response: {code: '4xx', message: 'message'}
}

{
    method: 'GET'
    route: '/authoob/profile'
    headers: {"Authentication-Token": 'AJWT token'}
    success_response: 'serialized user data',
    fail_response: {code: '401', message: 'message'}
}

{
    method: 'GET'
    route: '/authoob/profile/<user_id>'
    success_response: 'serialized user data',
    fail_response: {code: '4xx', message: 'message'}
}

{
    method: 'PUT'
    route: '/authoob/profile'
    payload: {"username": "utopman", "firstname" : "eric", "lastname" : "R"] //default ones, use your own 
    success_response: 'serialized user data',
    fail_response: {code: '4xx', message: 'message'}
}

{
    method: 'PUT'
    route: '/authoob/reset_password'
    payload: {"password1": "newPassword", "password2": "newPassword"}
    success_response: 201,
    fail_response: {code: '4xx', message: 'message'}
}

{
    method: 'POST'
    route: '/authoob/activate/<token>'
    success_response: 201,
    fail_response: {code: '4xx', message: 'message'},
    description: 'The route to call from registration mail url'
}
```

## Add authenticated route to the rest of the application

In the rest of the api, define protected routes using Flask-Security JWT mechanism

```python
from flask_security.decorators import auth_token_required

@app.route('/my_route')
@auth_token_required
def my_route():
    return jsonify({"a": "response"})
```

And from the client that consumes the API, you have to set a header with the tokens in the auth routes responses, the header to use is the one defined by Flask-Security (it is also possible to change the header name defining the key in flask configuration). The header is defined by default in the configuration with the value **SECURITY_TOKEN_AUTHENTICATION_HEADER** to `Authentication-Token`

## Other options

It is possible to change route prefix from authoob to whatever you want (and is a valid url string) by defining a custom route prefix on extention initialization

```python
authoob = AuthOOB(app, db, prefix="another_auth_prefix")
```

It is possible to extend the User model by setting a *CustomUserMixin* property on extention instanciation

```python
class CustomUserMixin:
    test_field = db.Column(db.String)
    extra_updatable_fields = ["test_field"]
    extra_exposed_fields = ["test_field"]

authoob = AuthOOB(app, db, CustomUserMixin=CustomUserMixin)
```

This will add the `test_field` field to the user , allows it's update and serialize it's value on `/authoob/profile` calls
