from flask_authoob import AuthOOB
from flask_sqlalchemy import SQLAlchemy
from flask import Flask

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "SECRET"
app.config["TESTING"] = True

db = SQLAlchemy(app)
auth = AuthOOB(app, db)
with app.app_context():
    db.create_all()
client = app.test_client()


class TestApi:
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
        token = client.post(
            "/authoob/login", json={"email": "test@mail.com", "password": "1Password"}
        ).json["token"]
        res = client.get("/authoob/token", headers={"Authentication-Token": token})
        assert res.status_code == 200 and list(res.json.keys()) == ["token"]
        res = client.get(
            "/authoob/token", headers={"Authentication-Token": res.json["token"]}
        )
        assert res.status_code == 200 and list(res.json.keys()) == ["token"]
