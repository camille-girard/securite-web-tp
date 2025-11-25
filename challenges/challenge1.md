# Portswigger Challenge 1 : Path Traversal – Null Byte Bypass

## Nom du challenge & URL

**Nom** : Challenge 1 – Path Traversal – Null Byte Bypass

**URL** : [https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass](https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass)

---

## Étapes de découverte de la vulnérabilité

1. Le site permet d’afficher des images de produits via un paramètre `/image?filename=68.jpg` envoyé dans une requête GET.
2. En interceptant cette requête avec Burp Suite, on constate que le serveur applique une validation de l’extension (ex : `.png`).
3. Les tentatives classiques de path traversal (`../../../etc/passwd`) échouent car l’application exige un fichier image valide.
4. En testant une technique connue, le Null Byte Injection, en mettant `%00`, on remarque que le serveur accepte la requête, car avec `%00.png` à la fin, le serveur s'arrête à `%00` et ignore le reste.
5. Quand on envoie le payload complet `../../../etc/passwd%00.png`, le serveur retourne le contenu du fichier `/etc/passwd`.

---

## Payload utilisé

```
../../../etc/passwd%00.png
```

Ce payload permet :

* De contourner la vérification de l’extension `.png`
* D'accéder au fichier du système `/etc/passwd`

L’application retourne alors le contenu du fichier `/etc/passwd`.

---

## Screenshot

![Capture BurpSuite](../images/challenge1.png)

---

## Recommandations de sécurité

Pour éviter cette vulnérabilité, il est recommandé :

### **1. Interdire toute navigation dans l’arborescence**

Utiliser une liste blanche de noms de fichiers prédéfinis. Ne jamais permettre d’introduire `../` dans un paramètre destiné à charger un fichier.

### **2. Ne jamais utiliser directement l’entrée utilisateur pour construire des chemins

Les chemins d’accès doivent être déterminés côté serveur, pas concaténés avec ce que fournit l’utilisateur.

### **3. Normaliser le chemin avant de l’utiliser

Passer le chemin final à une fonction comme realpath() ou normalize() pour résoudre ../, ./, encodages, etc.
Puis vérifier que le chemin résolu reste dans un répertoire autorisé.

### **4. Bloquer explicitement les caractères dangereux, dont le Null Byte (%00)

Empêcher les caractères susceptibles d’interrompre la comparaison ou détourner la validation.

### **5. Utiliser une référence interne plutôt que le nom réel du fichier**

Ne pas laisser l’utilisateur fournir un nom de fichier. Utiliser une référence interne générée par le serveur (ID, token, handle) qui pointe vers un fichier autorisé.

**Exemple :**
`GET /image?id=42` → serveur → `images/product_42.png`

---

## Références

* PortSwigger Web Security Academy – File Path Traversal
  [https://portswigger.net/web-security/file-path-traversal](https://portswigger.net/web-security/file-path-traversal)

* OWASP Cheat Sheet – Path Traversal
  [https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html)

* NSFOCUS – Path Traversal Attack Protection
  [https://nsfocusglobal.com/path-traversal-attack-protection/](
* 

