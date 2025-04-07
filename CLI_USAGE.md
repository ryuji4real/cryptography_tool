# CLI_USAGE.md

## Utilisation de CryptographyTool en ligne de commande

Ce document explique comment utiliser **CryptographyTool** via l'interface en ligne de commande (CLI). Cet outil permet de chiffrer et déchiffrer des messages avec divers algorithmes de cryptographie directement depuis un terminal.

### Prérequis

- **Système** : Windows (via MinGW/MSYS2) ou Linux.
- **Dépendances** : OpenSSL et zlib doivent être installés.
  - Sous MSYS2 : `pacman -S mingw-w64-x86_64-openssl mingw-w64-x86_64-zlib`.
  - Sous Linux : `sudo apt-get install libssl-dev zlib1g-dev` (pour Debian/Ubuntu).
- Compilation : Exécutez `make` dans le répertoire du projet pour générer l'exécutable `bin/program`.

### Syntaxe générale

```bash
bin/program --encrypt <algo> --key <clé> --input <texte>
```

- `--encrypt` : Indique que vous voulez chiffrer un texte.
- `<algo>` : L'algorithme à utiliser (voir la liste ci-dessous).
- `--key <clé>` : La clé de chiffrement (format dépend de l'algorithme).
- `--input <texte>` : Le texte à chiffrer (entre guillemets si plusieurs mots).

**Note** : Actuellement, seul le chiffrement est pris en charge via CLI. Le déchiffrement nécessite l'interface interactive (voir le menu principal).

### Algorithmes disponibles

#### 1. César (`cesar`)
- **Description** : Décalage simple de chaque lettre.
- **Clé** : Entier positif (ex. `3` pour un décalage de 3).
- **Exemple** :
  ```bash
  bin/program --encrypt cesar --key 3 --input "HELLO"
  ```
  **Sortie** : `Result: KHOOR`

#### 2. AES-GCM (`aes`)
- **Description** : Chiffrement par bloc avec authentification (mode GCM).
- **Clé** : Chaîne de 32 caractères exactement (256 bits).
- **Sortie** : Résultat en hexadécimal + IV (vecteur d'initialisation).
- **Exemple** :
  ```bash
  bin/program --encrypt aes --key "my32charlongkey1234567890abcdef" --input "Secret Message"
  ```
  **Sortie** (exemple fictif) :
  ```
  Result (hex): 4a5b6c7d8e9f0a1b2c3d4e5f6789abcd1234567890abcdef
  IV (hex): 1a2b3c4d5e6f7890abcd1234
  ```
  **Note** : Conservez l'IV pour le déchiffrement (via l'interface interactive).

### Exemples supplémentaires

1. **Chiffrement César avec un message multi-mots** :
   ```bash
   bin/program --encrypt cesar --key 5 --input "BONJOUR LE MONDE"
   ```
   **Sortie** : `Result: GTSOTZW QJ RTSIJ`

2. **Chiffrement AES avec une clé sécurisée** :
   - Générez d'abord une clé de 32 caractères (par exemple via l'option 15 du menu interactif).
   - Puis :
     ```bash
     bin/program --encrypt aes --key "X7kP9mWq2rT5vY8nB3cF6hJ0lQ4tA1dE" --input "Top Secret Data"
     ```

### Remarques

- **Déchiffrement** : Pour déchiffrer, utilisez l'interface interactive (lancez `bin/program` sans arguments et sélectionnez les options 2, 4, 6, 17, etc.).
- **Fichiers** : Le chiffrement/déchiffrement de fichiers n'est pas encore disponible via CLI. Utilisez les options 13/14 du menu interactif.
- **Sortie** : Les résultats sont affichés dans le terminal. Redirigez vers un fichier si nécessaire (ex. `> output.txt`).

### Dépannage

- **Erreur "program not found"** : Assurez-vous d'avoir compilé avec `make` et que vous exécutez la commande depuis le répertoire racine du projet.
- **Erreur "key length"** : Vérifiez que la clé correspond aux exigences de l'algorithme (32 caractères pour AES).
- **Problèmes OpenSSL** : Assurez-vous que les bibliothèques OpenSSL sont installées et liées correctement (`-lssl -lcrypto` dans le `Makefile`).

### Contribution

Pour ajouter des fonctionnalités CLI (ex. déchiffrement, chiffrement de fichiers), modifiez `main.c` dans la section `if (argc > 1)` et soumettez une pull request sur le dépôt GitHub.
