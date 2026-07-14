# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [1.5.0] - 2026-07-14

### Added

- Écran d'accueil retravaillé : logo en dégradé, panneau d'infos avec icônes, et nombre d'entrées affiché
- README : section d'installation Linux pas à pas

## [1.4.2] - 2026-07-14

### Changed

- Les mots de passe (maître et entrées) ne sont plus « trimmés » : les espaces
  en début/fin sont désormais préservés (entropie complète, espaces autorisés).
  Le trim reste appliqué aux autres saisies (alias, utilisateur, chemin…).

### Note

- Compatibilité : un vault existant reste lisible tant que son mot de passe maître
  n'avait pas d'espace en début/fin (cas quasi inexistant).

## [1.4.1] - 2026-07-14

### Changed

- README à jour : mode une-commande (CLI), usage SSH, options -f/$VAULT_FILE, sécurité, installation depuis GitHub

## [1.4.0] - 2026-07-14

### Added

- Mode « une commande » : `vault get github`, `vault list`, etc. exécutent une action puis quittent (idéal SSH/script)
- Option `-f`/`--file <chemin>` et variable d'environnement `VAULT_FILE` pour cibler un vault précis
- Repli clavier pour `open`/`init` quand aucun écran n'est disponible (SSH sans serveur X)
- `delete <alias>` accepte l'alias en argument ; alias `exit` et sortie par Ctrl-D

### Changed

- Le sélecteur de fichier graphique n'est utilisé que si un écran est détecté (DISPLAY/WAYLAND_DISPLAY)

## [1.3.0] - 2026-07-14

### Added

- Choix du fichier vault via un dialogue natif (open/init) — plus de chemin codé en dur
- Support des alias multi-mots (ex. `add mon compte`)

### Fixed

- Fix crash sur commande vide
- Correction de l'écrasement du vault avec un mauvais mot de passe (vérification avant sauvegarde + rollback mémoire)
- Garde contre un fichier vault tronqué/corrompu
- Génération de mot de passe : exclusion du caractère espace

### Security

- Effacement mémoire des secrets (mot de passe maître, clés, tampons en clair) via zeroize
- Effacement mémoire des identifiants du vault au Drop (ZeroizeOnDrop sur Credential)
- Retrait de `Debug` sur les structures sensibles

## [1.2.2] - 2026-02-08

### Fixed

- Fix Version Menu & Delete debug

## [1.2.1] - 2026-02-08

### Fixed

- Fix password init.

## [1.1.0] - 2026-02-08

### Added

- Improve arguments command and colors.

## [1.0.1] - 2026-02-04

### Added

- Add password ramdom generate
