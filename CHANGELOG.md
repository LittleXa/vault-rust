# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


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
