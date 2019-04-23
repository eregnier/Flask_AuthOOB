from flask_authoob import AuthOOB
from flask_sqlalchemy import SQLAlchemy
from flask import Flask

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "SECRET"
app.config["TESTING"] = True

db = SQLAlchemy(app)


class CustomUserMixin:
    test_field = db.Column(db.String)
    extra_updatable_fields = ["test_field"]
    extra_exposed_fields = ["test_field"]


auth = AuthOOB(app, db, CustomUserMixin=CustomUserMixin)
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
        return res.json

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
        res = client.post("/authoob/activate/wrong_token")
        assert res.status_code == 404
        res = client.post("/authoob/activate/{}".format(user.activation_token))
        assert res.status_code == 201
        res = client.post("/authoob/activate/{}".format(user.activation_token))
        assert res.status_code == 409

