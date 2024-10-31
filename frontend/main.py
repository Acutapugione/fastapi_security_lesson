from flask import Flask, render_template, request, redirect, url_for
from requests import post, get

app = Flask(__name__)


@app.get("/items/<token>")
def items(token: str):
    headers = {"Authorization": f"Bearer {token}"}

    response = get(
        "http://localhost:8000/items",
        headers=headers,
    )
    # return f"{response.status_code}"
    if response.ok:
        return response.json()


@app.get("/login")
def login():
    return render_template("login.html")


@app.post("/login")
def login_post():
    form_data = request.form.copy()
    username = form_data.get("username")
    password = form_data.get("password")
    response = post(
        "http://localhost:8000/token",
        data={
            "username": username,
            "password": password,
        },
    )
    if response.ok:
        return redirect(
            url_for(
                items.__name__,
                token=response.json().get("access_token"),
            )
        )
    return response.json().get("detail")


# get("/users/me")
# get("/items/")
# post("/token")
def main():
    app.run()
