from setuptools import setup
from os import path

cd = path.abspath(path.dirname(__file__))
with open(path.join(cd, "README.md"), encoding="utf-8") as f:
    long_description = f.read()


setup(
    name="Flask-AuthOOB",
    version="0.0.8",
    description="Implement quiclky authentification in flask using postgres and flask-security",
    packages=["flask_authoob"],
    long_description_content_type="text/markdown",
    long_description=long_description,
    author="Eric Régnier",
    author_email="utopman@gmail.com",
    license="MIT",
    install_requires=[
        "Flask",
        "flask_sqlalchemy",
        "sendgrid",
        "Flask_Security",
        "Flask_Marshmallow",
        "validate_email",
        "password_strength",
        "bcrypt",
        "psycopg2-binary",
    ],
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Programming Language :: Python :: Implementation :: Jython",
        "Intended Audience :: Developers",
    ],
    keywords=["web", "authentification", "jwt", "flask", "api"],
    url="",
)
