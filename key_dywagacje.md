############### 11111 ########
Oto kompletny kod aplikacji, która umożliwi Ci odebranie tokenu z Keycloak i wysłanie własnego żądania POST do chronionego zasobu. Kod ten łączy w sobie wszystkie poprzednie kroki i demonstruje, jak to działa w praktyce.

Python

from flask import Flask, request, session, redirect
import os
import base64
import requests

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Klucz sesji (ważne dla bezpieczeństwa)

# Konfiguracja Keycloak
KEYCLOAK_URL = "YOUR_KEYCLOAK_URL"  # Adres URL Keycloak
REALM = "YOUR_REALM"  # Nazwa realmu w Keycloak
CLIENT_ID = "YOUR_CLIENT_ID"  # ID klienta aplikacji w Keycloak
REDIRECT_URI = "http://localhost:5000/callback"  # URI przekierowania po autoryzacji
API_ENDPOINT = "YOUR_API_ENDPOINT"  # Adres URL Twojego chronionego zasobu

def generate_state(length):
    return base64.urlsafe_b64encode(os.urandom(length)).decode('utf-8').rstrip('=')

def generate_code_verifier(length):
    return base64.urlsafe_b64encode(os.urandom(length)).decode('utf-8').rstrip('=')

def generate_code_challenge(code_verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode('utf-8')).digest()).decode('utf-8').rstrip('=')


@app.route("/")
def index():
    state = generate_state(32)
    session['state'] = state  # Zapisujemy state w sesji
    code_verifier = generate_code_verifier(43)
    session['code_verifier'] = code_verifier
    code_challenge = generate_code_challenge(code_verifier)

    authorization_url = f"{KEYCLOAK_URL}/auth/realms/{REALM}/protocol/openid-connect/auth"
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }

    redirect_url = requests.Request('GET', authorization_url, params=params).prepare().url

    return f'<a href="{redirect_url}">Zaloguj się przez Keycloak</a>'

@app.route("/callback")
def callback():
    received_state = request.args.get('state')
    saved_state = session.get('state')

    if received_state != saved_state:
        return "Błąd: Nieprawidłowy state. Możliwy atak CSRF.", 400

    code = request.args.get('code')
    code_verifier = session.get('code_verifier')

    token_url = f"{KEYCLOAK_URL}/auth/realms/{REALM}/protocol/openid-connect/token"
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": code_verifier
    }

    response = requests.post(token_url, data=data)

    if response.status_code == 200:
        tokens = response.json()
        access_token = tokens["access_token"]
        refresh_token = tokens["refresh_token"]

        # Wysyłamy żądanie POST do chronionego zasobu
        headers = {"Authorization": f"Bearer {access_token}"}
        post_data = {"klucz": "wartość"}  # Przykładowe dane POST
        api_response = requests.post(API_ENDPOINT, headers=headers, json=post_data)

        if api_response.status_code == 200:
            return f"Odpowiedź z API: {api_response.json()}"
        else:
            return f"Błąd podczas żądania do API: {api_response.status_code} - {api_response.text}"

    else:
        return f"Błąd podczas wymiany kodu na token: {response.status_code} - {response.text}"

if __name__ == "__main__":
    app.run(debug=True)
Kluczowe zmiany i wyjaśnienia:

Flask: Używamy frameworka Flask do stworzenia aplikacji webowej.
Sesja: Używamy sesji Flask do przechowywania state i code_verifier między żądaniami. To jest bardzo ważne dla bezpieczeństwa.
Generowanie state i code_verifier: Funkcje generate_state i generate_code_verifier generują losowe wartości, które są kluczowe dla bezpieczeństwa.
Przekierowanie: Funkcja index generuje URL przekierowania do Keycloak z state, code_challenge i code_challenge_method i wyświetla link do niego.
Callback: Funkcja callback odbiera code i state, porównuje state z wartością w sesji, a następnie wymienia code na tokeny.
Żądanie POST do API: Po otrzymaniu tokenu dostępu, funkcja callback wysyła przykładowe żądanie POST do Twojego chronionego zasobu (API_ENDPOINT).
Obsługa błędów: Dodano podstawową obsługę błędów, aby wyświetlić informacje o problemach podczas autoryzacji lub żądania do API.
Aby uruchomić ten kod:

Zainstaluj Flask i requests: pip install Flask requests
Skonfiguruj Keycloak: Upewnij się, że masz skonfigurowany realm i klienta w Keycloak z poprawnym REDIRECT_URI.
Ustaw zmienne konfiguracyjne: Zastąp wartości KEYCLOAK_URL, REALM, CLIENT_ID, REDIRECT_URI i API_ENDPOINT swoimi.
Uruchom aplikację: python your_app_name.py
Pamiętaj, że to jest tylko przykład demonstracyjny. W prawdziwej aplikacji powinieneś dodać więcej obsługi błędów, logowania i zabezpieczeń.


---------------------------
############### 22222 #########

Aby wykonać autoryzację z Keycloak i odbiór tokena bez użycia frameworka Flask, możesz użyć czystego Pythona z bibliotekami requests i http.server. Poniżej przedstawiam przykład, który demonstruje ten proces.

1. Przygotowanie:

Upewnij się, że masz zainstalowane biblioteki requests i http.server:
Bash

pip install requests
Skonfiguruj klienta w Keycloak z odpowiednim Redirect URI (np. http://localhost:8000/callback).
2. Kod Pythona:

Python

import http.server
import urllib.parse
import requests
import os
import base64
import hashlib

# Konfiguracja
KEYCLOAK_URL = "YOUR_KEYCLOAK_URL"
REALM = "YOUR_REALM"
CLIENT_ID = "YOUR_CLIENT_ID"
REDIRECT_URI = "http://localhost:8000/callback"
API_ENDPOINT = "YOUR_API_ENDPOINT"

def generate_state(length):
    return base64.urlsafe_b64encode(os.urandom(length)).decode('utf-8').rstrip('=')

def generate_code_verifier(length):
    return base64.urlsafe_b64encode(os.urandom(length)).decode('utf-8').rstrip('=')

def generate_code_challenge(code_verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode('utf-8')).digest()).decode('utf-8').rstrip('=')

class MyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        params = urllib.parse.parse_qs(parsed_url.query)

        if path == '/':
            state = generate_state(32)
            code_verifier = generate_code_verifier(43)
            code_challenge = generate_code_challenge(code_verifier)

            authorization_url = f"{KEYCLOAK_URL}/auth/realms/{REALM}/protocol/openid-connect/auth"
            params = {
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "scope": "openid",
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256"
            }

            redirect_url = requests.Request('GET', authorization_url, params=params).prepare().url

            self.send_response(302)
            self.send_header('Location', redirect_url)
            self.end_headers()
        elif path == '/callback':
            received_state = params.get('state', [None])[0]
            code = params.get('code', [None])[0]

            # W tym uproszczonym przykładzie nie zapisujemy state i code_verifier w sesji.
            # W prawdziwej aplikacji jest to NIEZBĘDNE dla bezpieczeństwa.
            # Zamiast tego, przekazujemy je dalej.
            self.handle_callback(code, received_state, code_verifier)
        else:
            self.send_response(404)
            self.end_headers()

    def handle_callback(self, code, received_state, code_verifier):

        token_url = f"{KEYCLOAK_URL}/auth/realms/{REALM}/protocol/openid-connect/token"
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": code_verifier
        }

        response = requests.post(token_url, data=data)

        if response.status_code == 200:
            tokens = response.json()
            access_token = tokens["access_token"]
            refresh_token = tokens["refresh_token"]

            # Wysyłamy żądanie POST do chronionego zasobu
            headers = {"Authorization": f"Bearer {access_token}"}
            post_data = {"klucz": "wartość"}
            api_response = requests.post(API_ENDPOINT, headers=headers, json=post_data)

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f"Token odebrany. Odpowiedź z API: {api_response.json()}".encode())
        else:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f"Błąd: {response.text}".encode())


if __name__ == '__main__':
    server_address = ('localhost', 8000)
    httpd = http.server.HTTPServer(server_address, MyHandler)
    print('Uruchomiono serwer na http://localhost:8000')
    httpd.serve_forever()
3. Uruchomienie:

Zapisz kod jako np. keycloak_auth.py.
Uruchom skrypt: python keycloak_auth.py
Otwórz przeglądarkę i wejdź na http://localhost:8000.
4. Działanie:

Zostaniesz przekierowany do strony logowania Keycloak.
Po zalogowaniu, Keycloak przekieruje Cię z powrotem na http://localhost:8000/callback z kodem autoryzacyjnym.
Skrypt wymieni kod na tokeny i wyśle żądanie POST do Twojego API.
Wynik zostanie wyświetlony w przeglądarce.
Uwagi:

Ten przykład jest uproszczony i nie implementuje przechowywania state i code_verifier w sesji, co jest krytyczne dla bezpieczeństwa. W prawdziwej aplikacji musisz zaimplementować sesję (np. z użyciem baz danych lub plików).
Obsługa błędów jest minimalna. W produkcji powinieneś dodać więcej mechanizmów kontroli i logowania.
Kod zakłada, że masz działający serwer Keycloak i skonfigurowanego klienta.
Ten przykład pokazuje, jak wykonać autoryzację bez frameworka, ale zdecydowanie zalecam użycie frameworka takiego jak Flask lub Django w prawdziwej aplikacji, ze względu na wbudowane mechanizmy bezpieczeństwa i ułatwienia w obsłudze sesji.
