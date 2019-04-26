import datetime
from hashlib import md5
from uuid import uuid4

from flask_security import Security, SQLAlchemyUserDatastore
from flask_security import UserMixin, RoleMixin
from flask_marshmallow import Marshmallow
from flask_authoob.email_provider import SendGridEmailProvider
from flask_authoob.routes import FlaskOOBRoutes
from flask_authoob.hooks import FlaskOOBHooks


class AuthOOB(FlaskOOBRoutes, FlaskOOBHooks):
    def __init__(
        self,
        app=None,
        db=None,
        prefix="/authoob",
        CustomUserMixin=None,
        CustomUserSchemaMixin=None,
        mail_provider=None,
        custom_hooks=None,
    ):
        self.custom_hooks = custom_hooks or object()
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
        self.UserSchema = UserSchema
        self.ma = ma

        self.register_routes(app, db)
        self.register_hooks()
