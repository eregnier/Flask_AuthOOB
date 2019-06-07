import datetime
from uuid import uuid4

from validate_email import validate_email
from flask import jsonify, request, abort, make_response, redirect
from flask_security.core import current_user
from flask_security.utils import verify_password, hash_password, logout_user
from flask_security.decorators import auth_token_required
from password_strength import PasswordPolicy


class FlaskOOBRoutes:
    def register_routes(self, app, db):

        User = self.User
        UserSchema = self.UserSchema

        policy = PasswordPolicy.from_names(
            length=8,  # min length: 8
            uppercase=1,  # need min. 2 uppercase letters
            numbers=1,  # need min. 2 digits
            special=0,  # need min. 2 special characters
            nonletters=0,  # need min. 2 non-letter characters (digits, specials, anything)
        )

        def fail(code=401, message="Authentication failed", data={}):
            abort(make_response(jsonify(message=message, data=data), code))

        @app.route(f"{self.prefix}/logout", methods=["POST"])
        @auth_token_required
        def logout():
            self.hook("pre_logout", {"user": current_user})
            logout_user()
            self.hook("post_logout", None)
            return "", 204

        @app.route(f"{self.prefix}/login", methods=["POST"])
        def login():

            self.hook("pre_login", {"payload": request.json})

            try:
                user = User.query.filter_by(email=request.json.get("email", None)).one()
            except Exception:
                fail()

            self.hook("before_login", {"payload": request.json, "user": user})

            if verify_password(request.json.get("password", ""), user.password):
                user.login_count += 1
                db.session.add(user)
                db.session.commit()
                self.hook("post_login", {"payload": request.json, "user": user})

                return jsonify({"token": user.get_auth_token()})
            else:
                fail()

        @app.route(f"{self.prefix}/profile")
        @auth_token_required
        def profile():
            self.hook("pre_profile", {"user": current_user})
            response = UserSchema().jsonify(current_user)
            self.hook("post_profile", {"user": current_user, "response": response})
            return response

        @app.route(f"{self.prefix}/profile", methods=["PUT"])
        @auth_token_required
        def update_profile():
            self.hook(
                "pre_update_profile", {"payload": request.json, "user": current_user}
            )
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
            response = UserSchema().jsonify(current_user)
            self.hook(
                "post_update_profile",
                {"payload": request.json, "response": response, "user": current_user},
            )
            return response

        @app.route(f"{self.prefix}/profile/<int:user_id>")
        def user_profile(user_id):
            self.hook("pre_user_profile", {"user_id": user_id})
            try:
                user = User.query.get(user_id)
                response = UserSchema(only=["username", "id", "created_at"]).jsonify(
                    user
                )
                self.hook("post_user_profile", {"user": user, "response": response})
                return response
            except Exception:
                fail(code=404, message="User not found")

        @app.route(f"{self.prefix}/token")
        @auth_token_required
        def token():
            self.hook("pre_token", {"user": current_user})
            response = jsonify({"token": current_user.get_auth_token()})
            self.hook("post_token", {"user": current_user, "response": response})
            return response

        @app.route(f"{self.prefix}/activate/<string:token>")
        def activate(token):
            self.hook("pre_activate", {"token": token})
            try:
                user = User.query.filter_by(activation_token=token).one()
            except Exception:
                fail(code=404, message="No token match")
            if not user.active and user.confirmed_at is None:
                user.active = True
                user.confirmed_at = datetime.datetime.now()
                db.session.add(user)
                db.session.commit()
                self.hook("post_activate", {"user": user})
                default_redirect = "{}?validated_user={}".format(
                    app.config["APP_URL"], user.id
                )
                hook_url = self.hook(
                    "mail_activate_redirect",
                    {"user": user, "app_url": app.config["APP_URL"]},
                )
                return redirect(hook_url if hook_url else default_redirect)
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
            return "", 204

        @app.route(f"{self.prefix}/password/ask", methods=["POST"])
        def ask_reset_password():
            self.hook("pre_ask_reset", {"payload": request.json})
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
            if not self.hook(
                "mail_ask_reset_password",
                {"user": user, "mail_provider": self.mail_provider},
            ):
                link = (
                    f'<a href="{app.config["APP_URL"]}?reset_password_token'
                    f'={user.reset_password_token}">this link</a>'
                )

                self.mail_provider.send_mail(
                    to_emails=user.email,
                    subject="Email reset link",
                    html=(f"You can reset your password by following {link}."),
                )
            self.hook("post_ask_reset", {"payload": request.json, "user": user})

            return "", 204

        @app.route(f"{self.prefix}/password/reset", methods=["PUT"])
        @auth_token_required
        def reset_password_auth():
            self.hook("pre_reset_auth", {"payload": request.json, "user": current_user})
            if request.json is None:
                fail(code=400, message="Missing data")
            response = do_reset(request.json, current_user)
            self.hook(
                "post_reset_auth",
                {"payload": request.json, "user": current_user, "response": response},
            )
            return response

        @app.route(f"{self.prefix}/password/reset/<string:token>", methods=["PUT"])
        def reset_password_token(token):
            self.hook("pre_reset_token", {"token": token})
            if request.json is None:
                fail(code=400, message="Missing data")
            try:
                user = User.query.filter_by(reset_password_token=token).one()
            except Exception:
                fail(code=404, message="No token match")
            response = do_reset(request.json, user)
            self.hook("post_reset_token", {"token": token, "user": user})
            return response

        @app.route(f"{self.prefix}/register", methods=["POST"])
        def register():
            if self.mail_provider is None:
                fail(
                    code=500, message="No email provider defined, cannot register user"
                )
            if request.json is None:
                fail(code=400, message="Missing data")
            self.hook("pre_register", {"payload": request.json})
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
                email=email,
                password=password,
                firstname=request.json.get("firstname", None),
                lastname=request.json.get("lastname", None),
                active=False,
            )
            db.session.commit()
            user = User.query.filter_by(email=email).one()
            if not self.hook(
                "mail_register", {"user": user, "mail_provider": self.mail_provider}
            ):
                # This is default registration text
                link = (
                    f'<a href="{app.config["API_URL"]}/authoob/'
                    f'activate/{user.activation_token}">this link</a>'
                )
                self.mail_provider.send_mail(
                    to_emails=user.email,
                    subject="Email confirmation",
                    html=(
                        "Please activate your account by following "
                        f"{link} to confirm your account creation"
                    ),
                )
            self.hook("post_register", {"user": user, "payload": request.json})
            return jsonify({"token": user.get_auth_token()})
