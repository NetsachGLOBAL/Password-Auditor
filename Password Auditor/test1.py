from flask import Flask, request, jsonify, render_template
import requests
import random
import string
import csv
import io

app = Flask(__name__)

def password_strength(password):
    """
    Evaluates the strength of a password and provides suggestions for improvement.
    """
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

    # Determine strength based on score
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
    """
    Generates a strong password with a given length.
    """
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))


def load_credentials_from_csv(file):
    """
    Loads credentials from a CSV file-like object.
    """
    credentials = []
    try:
        file.seek(0)  # Ensure we read from the start of the file-like object
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
    """
    Tests the login form with various credentials and evaluates password strength.
    """
    results = []
    for username, password in credentials:
        payload = {
            username_field: username,
            password_field: password
        }

        try:
            response = requests.post(url, data=payload)

            if response.ok and "login" not in response.url.lower():
                result = {"username": username, "password": password, "status": "SUCCESS"}
            else:
                result = {"username": username, "password": password, "status": "FAIL"}

            strength, suggestions = password_strength(password)
            result["password_strength"] = strength
            result["suggestions"] = suggestions

            if strength == "Weak":
                result["suggested_new_password"] = generate_strong_password()

            results.append(result)

        except requests.RequestException as e:
            results.append({"username": username, "password": password, "status": "ERROR", "error": str(e)})
        except Exception as e:
            results.append({"username": username, "password": password, "status": "ERROR", "error": str(e)})

    return results


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Uploads a CSV file and starts the login testing process.
    """
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
        return jsonify(results)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


if __name__ == '__main__':
    app.run(debug=True)
