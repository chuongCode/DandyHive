from flask import Flask, redirect, url_for, render_template

app = Flask(__name__, static_url_path = "/static")

@app.route("/")
def home():
    return render_template('landing_page.html')

@app.errorhandler(404)
def page_not_found(error):
    return render_template('page_not_found.html'), 404

if __name__ == "__main__":
    app.run()