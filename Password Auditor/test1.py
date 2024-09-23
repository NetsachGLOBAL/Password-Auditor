from flask import Flask, request, render_template, jsonify
import requests
import random
import string
import csv
import io
import concurrent.futures

app = Flask(__name__)

def password_strength(password):
    """Evaluates the strength of a password and provides suggestions."""
    score = 0
    suggestions = []

    if len(password) >= 12:
        score += 1
    else:
        suggestions.append("Password should be at least 12 characters long.")

    if any(char.islower() for char in password):
        score += 1
    else:
        suggestions.append("Password should contain at least one lowercase letter.")

    if any(char.isupper() for char in password):
        score += 1
    else:
        suggestions.append("Password should contain at least one uppercase letter.")

    if any(char.isdigit() for char in password):
        score += 1
    else:
        suggestions.append("Password should contain at least one digit.")

    if any(char in string.punctuation for char in password):
        score += 1
    else:
        suggestions.append("Password should contain at least one special character.")

    if score == 5:
        strength = "Strong"
    elif score >= 3:
        strength = "Moderate"
    else:
        strength = "Weak"
        if not suggestions:
            suggestions.append("Consider using a longer and more complex password.")

    return strength, suggestions

def generate_strong_password(length=12):
    """Generates a strong password."""
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def load_credentials_from_csv(file):
    """Loads credentials from a CSV file-like object."""
    credentials = []
    try:
        file.seek(0)
        reader = csv.DictReader(io.StringIO(file.stream.read().decode('utf-8')))
        for row in reader:
            username = row['username']
            password = row['password']
            credentials.append((username, password))
    except KeyError:
        raise ValueError("CSV file is missing 'username' or 'password' columns.")
    except Exception as e:
        raise ValueError(f"An unexpected error occurred: {e}")
    
    return credentials

def test_login(url, username_field, password_field, credentials):
    """Tests the login form with various credentials and evaluates password strength."""
    results = []
    
    def test_single_credential(username, password):
        payload = {
            username_field: username,
            password_field: password
        }
        try:
            response = requests.post(url, data=payload)

            if response.ok and "login" not in response.url.lower():
                status = "SUCCESS"
            else:
                status = "FAIL"

            strength, suggestions = password_strength(password)

            result = {
                "username": username,
                "password": password,
                "status": status,
                "password_strength": strength,
                "suggestions": suggestions,
            }

            if strength == "Weak":
                result["suggested_new_password"] = generate_strong_password()

            return result

        except requests.RequestException as e:
            return {"username": username, "password": password, "status": "ERROR", "error": str(e)}
    
    # Perform concurrent login tests
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_cred = {executor.submit(test_single_credential, username, password): (username, password) for username, password in credentials}
        for future in concurrent.futures.as_completed(future_to_cred):
            results.append(future.result())

    return results

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({"error": "No file part in the request"}), 400

        file = request.files['file']
        url = request.form.get('url')
        username_field = request.form.get('username_field')
        password_field = request.form.get('password_field')

        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400

        if not url or not username_field or not password_field:
            return jsonify({"error": "Missing URL, username field, or password field"}), 400

        try:
            credentials = load_credentials_from_csv(file)
            results = test_login(url, username_field, password_field, credentials)
            return render_template('index.html', results=results)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    return render_template('index.html', results=None)

if __name__ == '__main__':
    app.run(debug=True)
