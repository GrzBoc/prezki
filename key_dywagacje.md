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





############################
-------------------------------
Jasne, oto jak możesz zrobić formatkę do wprowadzenia tych danych przez użytkownika, integrując ją z poprzednim kodem.  Użyjemy HTML i JavaScript po stronie klienta, aby zebrać dane i przekierować użytkownika do Keycloak z odpowiednimi parametrami w URL-u.

Python

from flask import Flask, request, session, redirect, render_template
import requests
import os
import base64
import hashlib
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ... (Konfiguracja Keycloak)

@app.route("/", methods=["GET", "POST"])  # Dodajemy obsługę metody POST
def index():
    if request.method == "POST":  # Jeśli formularz został wysłany
        start_date = request.form.get("start_date")
        end_date = request.form.get("end_date")
        place_number = request.form.get("place_number")
        date_of_reservation = request.form.get("date_of_reservation")

        state = generate_state(32)
        session['state'] = state
        code_verifier = generate_code_verifier(43)
        session['code_verifier'] = code_verifier
        code_challenge = generate_code_challenge(code_verifier)

        authorization_url = f"{KEYCLOAK_URL}/auth/realms/{REALM}/protocol/openid-connect/auth"
        params = {
            # ... (inne parametry)
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "start_date": start_date,  # Dodajemy parametry z formularza
            "end_date": end_date,
            "place_number": place_number,
            "date_of_reservation": date_of_reservation
        }
        redirect_url = requests.Request('GET', authorization_url, params=params).prepare().url
        return redirect(redirect_url) # Przekierowanie po zebraniu danych

    return render_template("index.html")  # Wyświetlamy formularz


@app.route("/callback")
def callback():
    # ... (Kod callback bez zmian)

# ... (Reszta kodu bez zmian)
index.html (Szablon HTML):

HTML

<!DOCTYPE html>
<html>
<head>
    <title>Formularz Rezerwacji</title>
</head>
<body>
    <h1>Wprowadź Dane Rezerwacji</h1>
    <form method="POST">  <label for="start_date">Data Początkowa:</label>
        <input type="date" id="start_date" name="start_date" required><br><br>

        <label for="end_date">Data Końcowa:</label>
        <input type="date" id="end_date" name="end_date" required><br><br>

        <label for="place_number">Numer Miejsca:</label>
        <input type="number" id="place_number" name="place_number" required><br><br>

         <label for="date_of_reservation">Data Rezerwacji:</label>
        <input type="date" id="date_of_reservation" name="date_of_reservation" required><br><br>

        <input type="submit" value="Przejdź do Logowania">
    </form>
</body>
</html>
Wyjaśnienie zmian:

render_template: Używamy render_template z Flask, aby wyświetlić formularz HTML.  Musisz utworzyć folder templates w tym samym katalogu, co Twój skrypt Pythona i umieścić w nim plik index.html.

Formularz HTML: Dodajemy formularz HTML z polami input typu date (dla dat) i number (dla numeru miejsca).  Atrybut name w każdym polu jest bardzo ważny, ponieważ te wartości są używane do pobierania danych w Flask.

Obsługa POST: Dodajemy warunek if request.method == "POST" w funkcji index.  Jeśli żądanie jest typu POST (czyli formularz został wysłany), pobieramy dane z formularza za pomocą request.form.get().

Przekierowanie: Po zebraniu danych, tworzymy URL przekierowania do Keycloak z dodanymi parametrami i przekierowujemy użytkownika.

Jak to działa:

Użytkownik wchodzi na stronę główną (/).
Wyświetlany jest formularz HTML.
Użytkownik wypełnia formularz i klika "Przejdź do Logowania".
Przeglądarka wysyła żądanie POST z danymi formularza.
Funkcja index w Flask odbiera dane, generuje state, code_verifier, code_challenge, buduje URL przekierowania do Keycloak i przekierowuje tam użytkownika.
Proces autoryzacji przebiega jak poprzednio.
Po powrocie do /callback, dane z formularza są dostępne w request.args (ponieważ zostały dodane do URL-u przekierowania).
Teraz masz kompletną integrację formularza z procesem autoryzacji Keycloak. Pamiętaj o obsłudze wyjątków i walidacji danych po stronie serwera.


#######################
REDIRECT 302
##################

Tak, istnieje możliwość przechwycenia parametru code poprzez przechwycenie przekierowania z Keycloak w Pythonie i znalezienie go w polu Location nagłówka odpowiedzi. Nie potrzebujesz do tego żadnych zewnętrznych narzędzi ani rozszerzeń przeglądarki. Możesz to zrobić bezpośrednio w Twojej aplikacji.

Oto jak to zaimplementować, wraz z wyjaśnieniami i przykładem kodu:

Python

import requests
import urllib.parse  # Do parsowania URL-i
import os
import base64
import hashlib

# ... (Konfiguracja Keycloak)

def initiate_keycloak_login():
    state = generate_state(32)
    session['state'] = state  # Zapisujemy state w sesji
    code_verifier = generate_code_verifier(43)
    session['code_verifier'] = code_verifier
    code_challenge = generate_code_challenge(code_verifier)

    authorization_url = f"{KEYCLOAK_URL}/auth/realms/{REALM}/protocol/openid-connect/auth"
    params = {
        # ... (inne parametry)
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    redirect_url = requests.Request('GET', authorization_url, params=params).prepare().url

    return redirect_url # Zwracamy URL do przekierowania


def get_authorization_code(redirect_url):

    try:
        response = requests.get(redirect_url, allow_redirects=False) # Kluczowe: allow_redirects=False
        if response.status_code == 302: # Sprawdzamy, czy to jest przekierowanie
            location_header = response.headers.get('Location')
            if location_header:
                parsed_url = urllib.parse.urlparse(location_header)
                query_params = urllib.parse.parse_qs(parsed_url.query)
                code = query_params.get('code', [None])[0]  # Wyodrębniamy code
                state = query_params.get('state', [None])[0] # Wyodrębniamy state
                return code, state
            else:
                return None, None # Nie znaleziono Location
        else:
            return None, None # Nie było przekierowania
    except requests.exceptions.RequestException as e:
        print(f"Błąd podczas pobierania code: {e}")
        return None, None



# Przykład użycia (w Flask lub innym frameworku):

@app.route("/login")
def login():
    redirect_url = initiate_keycloak_login()
    return redirect(redirect_url)

@app.route("/callback") # Ten endpoint teraz nie będzie używany do bezpośredniego odbierania code
def callback():
    # Ten endpoint w ogóle nie powinien być używany, ponieważ przechwytujemy przekierowanie w /get_code
    pass

@app.route("/get_code") # Nowy endpoint do przechwytywania przekierowania
def get_code():
    redirect_url = session.get('redirect_url') # URL zapisany w sesji
    code, state = get_authorization_code(redirect_url)

    if code and state:
        if session.get('state') != state:
            return "Błąd state", 400

        code_verifier = session.get('code_verifier')
        # ... (Dalszy proces autoryzacji z code i code_verifier)
    else:
        return "Nie udało się pobrać code.", 400


# ... (Reszta kodu)
Wyjaśnienie:

allow_redirects=False: To jest kluczowa zmiana.  W żądaniu requests.get() ustawiamy parametr allow_redirects na False. To powoduje, że requests nie będzie automatycznie podążać za przekierowaniem. Zamiast tego, otrzymamy odpowiedź HTTP z kodem 302 (Found) i nagłówkiem Location, który zawiera URL przekierowania.

Odczyt nagłówka Location: Sprawdzamy, czy kod statusu odpowiedzi to 302 (przekierowanie). Jeśli tak, odczytujemy wartość nagłówka Location, która zawiera URL przekierowania z Keycloak.

Parsowanie URL-u: Używamy funkcji urllib.parse.urlparse() i urllib.parse.parse_qs() do rozparsowania URL-u przekierowania i wyodrębnienia parametru code.

Endpoint /get_code: Dodajemy nowy endpoint /get_code, który będzie odpowiedzialny za przechwytywanie przekierowania.  To ten endpoint, a nie /callback, będzie teraz używany.

Zapis URL w sesji: W funkcji index (lub tam, gdzie inicjujesz logowanie), po wygenerowaniu redirect_url, zapisz go w sesji: session['redirect_url'] = redirect_url. Będzie on potrzebny w /get_code.

Przekierowanie do Keycloak: W funkcji login (lub tam, gdzie inicjujesz logowanie), po wygenerowaniu redirect_url, przekieruj użytkownika do /get_code, a nie bezpośrednio do Keycloak.  To /get_code zajmie się resztą.

Przechwytywanie w /get_code: W endpointcie /get_code pobieramy redirect_url z sesji, a następnie używamy get_authorization_code aby przechwycić przekierowanie i wyodrębnić code.

Jak to działa:

Użytkownik wchodzi na stronę logowania w Twojej aplikacji.
Generowany jest URL przekierowania do Keycloak.
Zamiast przekierować użytkownika bezpośrednio do Keycloak, przekierowujemy go do Twojego endpointu /get_code.
Endpoint /get_code wysyła żądanie GET do URL-u Keycloak z allow_redirects=False.
Otrzymujemy odpowiedź 302 z nagłówkiem Location.
Parsujemy URL z Location i wyodrębniamy code.
Kontynuujemy proces autoryzacji z code.
To podejście pozwala na przechwycenie code bez konieczności zmiany redirect_uri w Keycloak. Pamiętaj o obsłudze wyjątków i odpowiednim zabezpieczeniu sesji.

