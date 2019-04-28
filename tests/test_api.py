from flask_authoob import AuthOOB
from flask_sqlalchemy import SQLAlchemy
from flask import Flask

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "SECRET"
app.config["TESTING"] = True
app.config["EMAIL_SENDER"] = "test@mail.com"
app.config["API_URL"] = "http://localhost:5000"
app.config["APP_URL"] = "http://localhost:8080"
app.config["USE_VERIFY_PASSWORD_CACHE"] = True
db = SQLAlchemy(app)


class CustomHooks:
    def __init__(self):
        self.data = {}

    def pre_register(self, context):
        self.data["pre_register"] = context

    def post_register(self, context):
        self.data["post_register"] = context

    def pre_logout(self, context):
        self.data["pre_logout"] = context

    def post_logout(self, context):
        self.data["post_logout"] = context


class CustomUserMixin:
    test_field = db.Column(db.String)
    extra_updatable_fields = ["test_field"]
    extra_exposed_fields = ["test_field"]


class MockEmailProvider:
    def send_mail(self, **kwargs):
        self.args = kwargs


auth = AuthOOB(
    app,
    db,
    CustomUserMixin=CustomUserMixin,
    mail_provider=MockEmailProvider(),
    custom_hooks=CustomHooks(),
)
with app.app_context():
    db.create_all()
client = app.test_client()


class TestApi:
    def login(self):
        return client.post(
            "/authoob/login", json={"email": "test@mail.com", "password": "1Password"}
        ).json["token"]

    def test_register(self):
        res = client.post("/authoob/register")
        assert res.status_code == 400 and res.json["message"] == "Missing data"
        res = client.post("/authoob/register", json={"email": "test@mail.com"})
        assert (
            res.status_code == 400
            and res.json["message"] == "Passwords strength policy invalid"
        )
        res = client.post(
            "/authoob/register", json={"email": "test@mail.com", "password1": "test"}
        )
        assert (
            res.status_code == 400
            and res.json["message"] == "Passwords strength policy invalid"
        )
        res = client.post(
            "/authoob/register",
            json={
                "email": "test@mail.com",
                "password1": "1Password",
                "password2": "2Password",
            },
        )
        assert res.status_code == 400 and res.json["message"] == "Mismatching passwords"
        res = client.post(
            "/authoob/register",
            json={
                "email": "test@mail.com",
                "password1": "1Password",
                "password2": "1Password",
            },
        )
        assert res.status_code == 200 and "token" in res.json
        assert (
            auth.custom_hooks.data["pre_register"]["payload"]["email"]
            == "test@mail.com"
        )
        assert auth.custom_hooks.data["post_register"]["user"].email == "test@mail.com"
        assert "to_emails" in auth.mail_provider.args
        assert "subject" in auth.mail_provider.args
        assert "html" in auth.mail_provider.args

    def test_login(self):
        res = client.post(
            "/authoob/login", json={"email": "test@mail.com", "password": "wrong pass"}
        )
        assert res.status_code == 401 and res.json["message"] == "Authentication failed"
        res = client.post(
            "/authoob/login", json={"email": "wrong email", "password": "1Password"}
        )
        assert res.status_code == 401 and res.json["message"] == "Authentication failed"
        res = client.post(
            "/authoob/login", json={"email": "test@mail.com", "password": "1Password"}
        )
        assert res.status_code == 200 and list(res.json.keys()) == ["token"]

    def test_token(self):
        token = self.login()
        res = client.get("/authoob/token", headers={"Authentication-Token": token})
        assert res.status_code == 200 and list(res.json.keys()) == ["token"]
        res = client.get("/authoob/token", headers={"Authentication-Token": token})
        assert res.status_code == 200 and list(res.json.keys()) == ["token"]

    def test_profile(self):
        token = self.login()
        res = client.get("/authoob/profile", headers={"Authentication-Token": token})
        assert "create_date" in res.json
        assert "update_date" in res.json
        assert "email" in res.json
        assert "id" in res.json
        assert "username" in res.json
        assert "password" not in res.json
        assert res.json["email"] == "test@mail.com"
        res = client.get(f"/authoob/profile/{res.json['id']}")
        assert "email" not in res.json
        assert "username" in res.json
        assert "id" in res.json
        assert "password" not in res.json

    def test_profile_update(self):
        token = self.login()
        res = client.get("/authoob/profile", headers={"Authentication-Token": token})
        user_id = res.json["id"]
        res = client.put(
            "/authoob/profile",
            headers={"Authentication-Token": token},
            json={
                "id": user_id,
                "username": "utopman",
                "random": "notset",
                "test_field": "test_value",
            },
        )
        assert res.status_code == 200
        assert res.json["username"] == "utopman"
        assert res.json["test_field"] == "test_value"
        assert "random" not in res.json

    def test_user_activation(self):
        user = auth.User.query.get(1)
        res = client.get("/authoob/activate/wrong_token")
        assert res.status_code == 404
        res = client.get("/authoob/activate/{}".format(user.activation_token))
        assert res.status_code == 302
        res = client.get("/authoob/activate/{}".format(user.activation_token))
        assert res.status_code == 409

    def test_reset_password(self):
        token = self.login()
        res = client.put(
            "/authoob/password/reset", headers={"Authentication-Token": token}
        )
        assert res.status_code == 400 and res.json["message"] == "Missing data"
        res = client.put(
            "/authoob/password/reset",
            json={"password1": "weakpass", "password2": "anotherpass"},
            headers={"Authentication-Token": token},
        )
        assert res.status_code == 400 and res.json["message"] == "Password mismatch"
        res = client.put(
            "/authoob/password/reset",
            json={"password1": "weakpass", "password2": "weakpass"},
            headers={"Authentication-Token": token},
        )
        assert (
            res.status_code == 400
            and res.json["message"] == "Passwords strength policy invalid"
        )
        res = client.put(
            "/authoob/password/reset",
            json={"password1": "2Password", "password2": "2Password"},
            headers={"Authentication-Token": token},
        )
        assert res.status_code == 204
        res = client.post(
            "/authoob/login", json={"email": "test@mail.com", "password": "2Password"}
        )
        assert res.status_code == 200 and list(res.json.keys()) == ["token"]

        user = auth.User.query.get(1)
        user.reset_password_token = "123"
        email = user.email
        db.session.add(user)
        db.session.commit()
        res = client.put(
            "/authoob/password/reset/123",
            json={"password1": "3Password", "password2": "3Password"},
        )
        assert res.status_code == 204
        res = client.put(
            "/authoob/password/reset/123",
            json={"password1": "3Password", "password2": "3Password"},
        )
        assert res.status_code == 404
        res = client.post(
            "/authoob/login", json={"email": email, "password": "3Password"}
        )
        assert res.status_code == 200 and list(res.json.keys()) == ["token"]
        res = client.post("/authoob/password/ask", json={"email": email})
        assert res.status_code == 204
        user = auth.User.query.filter_by(email=email).one()
        res = client.put(
            "/authoob/password/reset/{}".format(user.reset_password_token),
            json={"password1": "3Password", "password2": "3Password"},
        )
        assert res.status_code == 204

    def test_logout(self):
        res = client.post("/authoob/logout")
        assert res.status_code == 401
        res = client.post(
            "/authoob/login", json={"email": "test@mail.com", "password": "3Password"}
        )
        token = res.json["token"]
        assert res.status_code == 200 and list(res.json.keys()) == ["token"]
        res = client.post("/authoob/logout", headers={"Authentication-Token": token})
        assert res.status_code == 204

