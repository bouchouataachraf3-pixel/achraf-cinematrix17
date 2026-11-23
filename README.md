# CINEMATRIX — Application Flask (thème cinématique vert & noir)

## Lancer l'application

```bash
cd cinema_app
python -m venv venv
source venv/bin/activate        # Windows : venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Ouvrez http://127.0.0.1:5000 — créez un compte via **Créer un compte**.

## Pages

| URL                       | Description                                   |
|---------------------------|-----------------------------------------------|
| `/login`                  | Connexion (nom d'utilisateur **ou** email)    |
| `/register`               | Inscription (username, email, mot de passe)   |
| `/forgot-password`        | Mot de passe oublié                           |
| `/reset-password/<token>` | Réinitialisation (lien valable 1 h, 1 usage)  |
| `/`                       | Accueil                                       |
| `/contact`                | Contact (messages enregistrés en base)        |
| `/about`                  | À propos                                      |
| `/profile`                | Profil + changement de mot de passe           |

## Mot de passe oublié

Sans SMTP configuré (mode développement), le lien de réinitialisation est
affiché sur la page et dans la console. Pour envoyer de vrais emails :

```bash
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USER=votre@gmail.com
export SMTP_PASSWORD=mot_de_passe_application
python app.py
```

## Sécurité incluse

- Mots de passe hachés (Werkzeug), jamais stockés en clair
- Protection CSRF sur tous les formulaires POST
- Jeton de réinitialisation signé, expirant et à usage unique
- Message identique que l'email existe ou non (pas de fuite d'information)
- Redirections `next` limitées aux URLs internes

En production : définissez `SECRET_KEY`, utilisez HTTPS et un serveur WSGI (gunicorn).

## APK Android autonome

Le projet Android se trouve dans `android`. Pour générer l'APK de test sous
Windows :

```powershell
cd android
.\gradlew.bat assembleDebug
```

Le fichier généré se trouve dans
`android/app/build/outputs/apk/debug/app-debug.apk`. L'application embarque
Flask et sa base SQLite : aucun site hébergé n'est nécessaire. Les comptes et
messages créés dans l'APK sont stockés sur le téléphone et ne sont pas partagés
avec la base de données du site lancé sur ordinateur.

L'APK prend en charge les appareils Android 7 ou plus récents, en 64 bits.
La version préparée pour le transfert sur téléphone est
`achraf_site_flask.apk` à la racine du dossier `cinema_app`.
