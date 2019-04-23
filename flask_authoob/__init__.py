import datetime
from hashlib import md5
from validate_email import validate_email
from flask import jsonify, request, abort, make_response
from flask_security import Security, SQLAlchemyUserDatastore
from flask_security.core import current_user
from flask_security.utils import verify_password
from flask_security.decorators import auth_token_required
from flask_security import UserMixin, RoleMixin
from flask_marshmallow import Marshmallow
from password_strength import PasswordPolicy


class AuthOOB:
    def __init__(self, app=None, db=None, prefix="/authoob", CustomUserMixin=None):
        self.prefix = prefix
        self.updatable_fields = ["username", "firstname", "lastname"] + getattr(
            CustomUserMixin, "extra_updatable_fields", []
        )
        self.exposed_fields = [
            "id",
            "email",
            "username",
            "firstname",
            "lastname",
            "create_date",
            "update_date",
            "login_count",
        ] + getattr(CustomUserMixin, "extra_exposed_fields", [])
        self.CustomUserMixin = CustomUserMixin if CustomUserMixin else object

        if app is not None and db is not None:
            self.init_app(app, db)

    def init_app(self, app, db):
        assert app is not None and db is not None
        salt = app.config.get("SECURITY_PASSWORD_SALT", None) or md5(
            app.config["SECRET_KEY"].encode()
        )
        app.config["SECURITY_PASSWORD_SALT"] = salt
        ma = Marshmallow(app)

        def fail(code=401, message="Authentication failed", data={}):
            abort(make_response(jsonify(message=message, data=data), code))

        roles_users = db.Table(
            "roles_users",
            db.Column("user_id", db.Integer(), db.ForeignKey("user.id")),
            db.Column("role_id", db.Integer(), db.ForeignKey("role.id")),
        )

        class UserSchema(ma.Schema):
            class Meta:
                # Fields to expose
                fields = self.exposed_fields

        class Role(db.Model, RoleMixin):
            __tablename__ = "role"
            id = db.Column(db.Integer, primary_key=True)
            name = db.Column(db.String(80), unique=True)
            description = db.Column(db.String(255))

        class User(db.Model, UserMixin, self.CustomUserMixin):
            __tablename__ = "user"
            id = db.Column(db.Integer, primary_key=True)
            email = db.Column(db.String(255), unique=True)
            username = db.Column(db.String(255))
            firstname = db.Column(db.String(255))
            lastname = db.Column(db.String(255))
            password = db.Column(db.String(255))
            create_date = db.Column(db.DateTime(), default=datetime.datetime.now)
            update_date = db.Column(db.DateTime(), onupdate=datetime.datetime.now)
            last_login_at = db.Column(db.DateTime())
            current_login_at = db.Column(db.DateTime())
            last_login_ip = db.Column(db.String(100))
            current_login_ip = db.Column(db.String(100))
            login_count = db.Column(db.Integer, default=0)
            active = db.Column(db.Boolean())
            confirmed_at = db.Column(db.DateTime())
            roles = db.relationship(
                "Role",
                secondary="roles_users",
                backref=db.backref("users", lazy="dynamic"),
            )

        with app.app_context():
            self.user_datastore = SQLAlchemyUserDatastore(db, User, Role)
            self.security = Security(app, self.user_datastore)

        self.roles_users = roles_users
        self.Role = Role
        self.User = User
        self.ma = ma

        @app.route("{}/login".format(self.prefix), methods=["POST"])
        def login():

            try:
                user = User.query.filter_by(email=request.json.get("email", None)).one()
            except Exception:
                fail()

            if verify_password(request.json.get("password", ""), user.password):
                user.login_count += 1
                db.session.add(user)
                db.session.commit()
                return jsonify({"token": user.get_auth_token()})
            else:
                fail()

        @app.route("{}/profile".format(self.prefix))
        @auth_token_required
        def profile():
            return UserSchema().jsonify(current_user)

        @app.route("{}/profile".format(self.prefix), methods=["PUT"])
        @auth_token_required
        def update_profile():
            data, errors = UserSchema(load_only=self.updatable_fields).load(
                request.json
            )
            if errors:
                fail(
                    code=400, message="Invalid parameters for user update", data=errors
                )
            for field in self.updatable_fields:
                setattr(current_user, field, data.get(field, None))
            db.session.add(current_user)
            db.session.commit()
            return UserSchema().jsonify(current_user)

        @app.route("{}/profile/<int:user_id>".format(self.prefix))
        def user_profile(user_id):
            try:
                return UserSchema(only=["username", "id", "created_at"]).jsonify(
                    User.query.get(user_id)
                )
            except Exception:
                fail(code=404, message="User not found")

        @app.route("{}/token".format(self.prefix))
        @auth_token_required
        def token():
            return jsonify({"token": current_user.get_auth_token()})

        @app.route("{}/register".format(self.prefix), methods=["POST"])
        def register():
            if request.json is None:
                fail(code=400, message="Missing data")
            password = request.json.get("password1")
            email = request.json.get("email")
            policy = PasswordPolicy.from_names(
                length=8,  # min length: 8
                uppercase=1,  # need min. 2 uppercase letters
                numbers=1,  # need min. 2 digits
                special=0,  # need min. 2 special characters
                nonletters=0,  # need min. 2 non-letter characters (digits, specials, anything)
            )
            if policy.test(password):
                fail(code=400, message="Passwords strength policy invalid")
            if password is None or password != request.json.get("password2"):
                fail(code=400, message="Mismatching passwords")
            if not validate_email(email):
                fail(code=400, message="Invalid email given")
            if User.query.filter_by(email=email).count():
                fail(code=409, message="User already registered")
            self.user_datastore.create_user(email=email, password=password)
            db.session.commit()
            user = User.query.filter_by(email=email).one()
            return jsonify({"token": user.get_auth_token()})