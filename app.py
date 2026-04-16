from flask import Flask, render_template, request, jsonify
from password_manager import PasswordStrengthAnalyzer

app = Flask(__name__)
analyzer = PasswordStrengthAnalyzer()

@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json
    password = data.get("password")

    result = analyzer.analyze(password)
    return jsonify(result)

@app.route("/generate", methods=["GET"])
def generate():
    return analyzer.generate_password()

if __name__ == "__main__":
    app.run(debug=True)