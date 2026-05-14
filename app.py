from flask import Flask, render_template, request
from scanner import run_all_checks

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    scan_results = []
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            scan_results = run_all_checks(url)
    return render_template("index.html", results=scan_results)

if __name__ == "__main__":
    app.run(debug=True)
