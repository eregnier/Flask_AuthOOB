import datetime
from hashlib import md5
from uuid import uuid4
from validate_email import validate_email
from flask import jsonify, request, abort, make_response, redirect
from flask_security import Security, SQLAlchemyUserDatastore
from flask_security.core import current_user
from flask_security.utils import verify_password, hash_password
from flask_security.decorators import auth_token_required
from flask_security import UserMixin, RoleMixin
from flask_marshmallow import Marshmallow
from password_strength import PasswordPolicy
from flask_authoob.email_provider import SendGridEmailProvider


class AuthOOB:
    def __init__(
        self,
        app=None,
        db=None,
        prefix="/authoob",
        CustomUserMixin=None,
        CustomUserSchemaMixin=None,
        mail_provider=None,
    ):
        self.prefix = prefix
        if app is not None and db is not None:
            self.init_app(
                app,
                db,
                CustomUserMixin=CustomUserMixin,
                CustomUserSchemaMixin=CustomUserSchemaMixin,
                mail_provider=mail_provider,
            )

    def init_app(
        self,
        app,
        db,
        CustomUserMixin=None,
        CustomUserSchemaMixin=None,
        mail_provider=None,
    ):
        assert (
            app is not None
            and db is not None
            and app.config["APP_URL"]
            and app.config["API_URL"]
            and app.config["SECRET_KEY"]
            and app.config["EMAIL_SENDER"]
        )
        salt = (
            app.config.get("SECURITY_PASSWORD_SALT", None)
            or md5(app.config["SECRET_KEY"].encode()).hexdigest()
        )
        app.config["SECURITY_PASSWORD_SALT"] = salt
        ma = Marshmallow(app)

        self.mail_provider = mail_provider
        if mail_provider is None:
            self.mail_provider = SendGridEmailProvider(app)

        mixin = CustomUserMixin
        self.updatable_fields = ["username", "firstname", "lastname"] + getattr(
            mixin, "extra_updatable_fields", []
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
        ] + getattr(mixin, "extra_exposed_fields", [])
        self.CustomUserMixin = mixin or object

        def fail(code=401, message="Authentication failed", data={}):
            abort(make_response(jsonify(message=message, data=data), code))

        policy = PasswordPolicy.from_names(
            length=8,  # min length: 8
            uppercase=1,  # need min. 2 uppercase letters
            numbers=1,  # need min. 2 digits
            special=0,  # need min. 2 special characters
            nonletters=0,  # need min. 2 non-letter characters (digits, specials, anything)
        )

        roles_users = db.Table(
            "roles_users",
            db.Column("user_id", db.Integer(), db.ForeignKey("user.id")),
            db.Column("role_id", db.Integer(), db.ForeignKey("role.id")),
        )

        class UserSchema(ma.Schema, CustomUserSchemaMixin or object):
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
            active = db.Column(db.Boolean(), default=False)
            activation_token = db.Column(db.String(), default=lambda: str(uuid4()))
            reset_password_token = db.Column(db.String(), default=lambda: str(uuid4()))
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

        @app.route(f"{self.prefix}/login", methods=["POST"])
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

        @app.route(f"{self.prefix}/profile")
        @auth_token_required
        def profile():
            return UserSchema().jsonify(current_user)

        @app.route(f"{self.prefix}/profile", methods=["PUT"])
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

        @app.route(f"{self.prefix}/profile/<int:user_id>")
        def user_profile(user_id):
            try:
                return UserSchema(only=["username", "id", "created_at"]).jsonify(
                    User.query.get(user_id)
                )
            except Exception:
                fail(code=404, message="User not found")

        @app.route(f"{self.prefix}/token")
        @auth_token_required
        def token():
            return jsonify({"token": current_user.get_auth_token()})

        @app.route(f"{self.prefix}/activate/<string:token>")
        def activate(token):
            try:
                user = User.query.filter_by(activation_token=token).one()
            except Exception:
                fail(code=404, message="No token match")
            if not user.active and user.confirmed_at is None:
                user.active = True
                user.confirmed_at = datetime.datetime.now()
                db.session.add(user)
                db.session.commit()
                return redirect(
                    "{}?validated_user={}".format(app.config["APP_URL"], user.id)
                )
            else:
                fail(code=409, message="Unable to activate")

        def do_reset(payload, user):
            password1 = payload.get("password1")
            password2 = payload.get("password2")
            if password1 != password2:
                fail(code=400, message="Password mismatch")
            if policy.test(password1):
                fail(code=400, message="Passwords strength policy invalid")
            user.password = hash_password(password1)
            user.reset_password_token = None
            db.session.add(user)
            db.session.commit()
            return "", 201

        @app.route(f"{self.prefix}/password/ask", methods=["POST"])
        def ask_reset_password():
            if request.json is None:
                fail(code=400, message="Missing data")
            email = request.json.get("email", None)
            if email is None:
                fail(code=400, message="Missing data")
            try:
                user = User.query.filter_by(email=email).one()
            except Exception:
                fail(code=400, message="Missing data")  # This prevents email scans
            user.reset_password_token = str(uuid4())
            db.session.add(user)
            db.session.commit()
            link = (
                f'<a href="{app.config["APP_URL"]}?reset_password_token'
                f'={user.reset_password_token}">this link</a>'
            )
            self.mail_provider.send_mail(
                to_emails=user.email,
                subject="Email reset link",
                html=(f"You can reset your password by following {link}."),
            )
            return "", 201

        @app.route(f"{self.prefix}/password/reset", methods=["PUT"])
        @auth_token_required
        def reset_password_auth():
            if request.json is None:
                fail(code=400, message="Missing data")
            return do_reset(request.json, current_user)

        @app.route(f"{self.prefix}/password/reset/<string:token>", methods=["PUT"])
        def reset_password_token(token):
            if request.json is None:
                fail(code=400, message="Missing data")
            try:
                user = User.query.filter_by(reset_password_token=token).one()
            except Exception:
                fail(code=404, message="No token match")
            return do_reset(request.json, user)

        @app.route(f"{self.prefix}/register", methods=["POST"])
        def register():
            if self.mail_provider is None:
                fail(
                    code=500, message="No email provider defined, cannot register user"
                )
            if request.json is None:
                fail(code=400, message="Missing data")
            password = request.json.get("password1")
            email = request.json.get("email")
            if policy.test(password):
                fail(code=400, message="Passwords strength policy invalid")
            if password is None or password != request.json.get("password2"):
                fail(code=400, message="Mismatching passwords")
            if not validate_email(email):
                fail(code=400, message="Invalid email given")
            if User.query.filter_by(email=email).count():
                fail(code=409, message="User already registered")
            self.user_datastore.create_user(
                email=email, password=password, active=False
            )
            db.session.commit()
            user = User.query.filter_by(email=email).one()
            link = (
                f'<a href="{app.config["API_URL"]}/authoob/'
                f'activate/{user.reset_password_token}">this link</a>'
            )
            self.mail_provider.send_mail(
                to_emails=user.email,
                subject="Email confirmation",
                html=(
                    "Please activate your account by following "
                    f"{link} to confirm your account creation"
                ),
            )
            return jsonify({"token": user.get_auth_token()})
