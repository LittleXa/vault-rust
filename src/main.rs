/*
* Vault
* Secret Credentials in Secure Vault
*
* littleXa
* 2026
*
*/

//Global constants
const VERSION: &str = "1.3.0";
const PURPLE: &str = "\x1b[1;35m";
const CYAN: &str   = "\x1b[1;36m";
const GREEN: &str  = "\x1b[1;32m";
const RED: &str    = "\x1b[1;31m";
const RESET: &str  = "\x1b[0m";

//Pour recupere la saisie utilisateur
use std::io;

//Ecriture de fichier Texte
use std::fs::File;
use std::path::{Path, PathBuf};
use std::io::{Read, Write};

//JSON
use serde::{Deserialize, Serialize};

//Utilisation d'un hashmap
use std::collections::HashMap;

//Génération Aléatoire
use rand::{RngCore, Rng};
use rand::rngs::OsRng;

//Crypto
use argon2::Argon2;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};

//Couleurs
use colored::Colorize;

//Effacement mémoire des secrets
use zeroize::{Zeroizing, Zeroize, ZeroizeOnDrop};

/**
* Structure de tableau de type unsigned 8bits
* Le derive permet d'implementer les traits debug et clone
*/
// Pas de derive(Debug) sur les structures sensibles : éviter qu'un {:?}
// accidentel ne divulgue sel, nonce ou identifiants en clair.
#[derive(Clone)]
struct Vault {
    salt: [u8; 16], //tableau de 16 bytes en u8
    nonce_bytes: [u8; 12], //tableau de 12 bytes en u8
    cyphertext: Vec<u8>
}

// Zeroize + ZeroizeOnDrop : le contenu (user + password) est effacé de la RAM
// dès qu'un Credential est libéré (suppression d'entrée ou fermeture du vault).
#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
struct Credential {
    user: String,
    password: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct PasswordVault {
    credentials: HashMap<String, Credential>,
}

fn main() -> io::Result<()> {

    println!("{}", ">> Bienvenue dans Vault ! A Secure Vault in shell".red());

    // Chemin du vault ouvert par défaut au démarrage
    let default_path = PathBuf::from("safe.vault");

    // État : le vault déchiffré en mémoire + le chemin du fichier ouvert
    let mut vault_option: Option<PasswordVault> = None;
    let mut current_path: Option<PathBuf> = None;

    // Au démarrage, on ouvre automatiquement le vault par défaut s'il existe
    if vault_exists(&default_path) {
        match open_vault(&default_path) {
            Ok(vault) => {
                io::stdout().flush()?;
                display_logo(true, &default_path);
                println!("{GREEN}✓ Vault ouvert avec succès !{RESET}\n");
                println!("Tapez {RED}quit{RESET} pour quitter ou {PURPLE}help{RESET} pour l'aide.");
                vault_option = Some(vault);
                current_path = Some(default_path.clone());
            }
            Err(e) => {
                eprintln!("Erreur lors de l'ouverture du vault : {}", e);
                println!("Vous pouvez réessayer avec 'open' ou créer un nouveau vault avec 'init'\n");
            }
        }
    } else {
        println!("{}", "Aucun vault ouvert. 'init' pour en créer un, 'open' pour en choisir un.".blue());
        println!();
    }

    //Boucle principale
    loop {

        //clear
        print!("\x1b[1;36m >> \x1b[0m");
        io::stdout().flush()?;
        // Affiche le prompt
        // Lit l'entrée utilisateur
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        //Collecte des arguments de la commande
        let collect_args: Vec<&str> = input.split_whitespace().collect();
        let command = match collect_args.first() {
            Some(c) => *c,
            None => continue, // ligne vide → on redemande une commande
        };
        // L'argument est tout ce qui suit la commande (autorise les alias multi-mots)
        let args: String = collect_args.get(1..).map(|rest| rest.join(" ")).unwrap_or_default();

        //let alias: String =
        // Traite la commande
        match command {
            "quit" => {
                println!("Au revoir !");
                break;
            },
            "version" => println!("Version {}", VERSION),
            "init" => {
                match pick_new_vault() {
                    Some(path) => {
                        if let Err(e) = init(&path) {
                            eprintln!("Erreur lors de l'initialisation : {}", e);
                        } else {
                            // Charger le nouveau vault
                            match open_vault(&path) {
                                Ok(vault) => {
                                    vault_option = Some(vault);
                                    current_path = Some(path);
                                }
                                Err(e) => {
                                    eprintln!("Erreur lors de l'ouverture du vault : {}", e);
                                }
                            }
                        }
                    }
                    None => println!("Création annulée."),
                }
            },
            "add" => {
                match (vault_option.as_mut(), current_path.as_ref()) {
                    (Some(vault), Some(path)) => {
                        if let Err(e) = add_entry(vault, &args, path) {
                            eprintln!("Erreur lors de l'ajout : {}", e);
                        }
                    }
                    _ => println!("Aucun vault ouvert. Utilisez 'init' pour créer un vault ou 'open' pour en ouvrir un."),
                }
            },
            "list" => {
                if let Some(ref vault) = vault_option {
                    list_entries(vault);
                } else {
                    println!("Aucun vault ouvert. Utilisez 'init' pour créer un vault ou 'open' pour en ouvrir un.");
                }
            },
            "get" => {
                if let Some(ref vault) = vault_option {
                    if let Err(e) = get_entry(vault, &args) {
                        eprintln!("Erreur lors de la récupération : {}", e);
                    }
                } else {
                    println!("Aucun vault ouvert. Utilisez 'init' pour créer un vault ou 'open' pour en ouvrir un.");
                }
            },
            "delete" => {
                match (vault_option.as_mut(), current_path.as_ref()) {
                    (Some(vault), Some(path)) => {
                        if let Err(e) = delete_entry(vault, path) {
                            eprintln!("Erreur lors de la suppression : {}", e);
                        }
                    }
                    _ => println!("Aucun vault ouvert. Utilisez 'init' pour créer un vault ou 'open' pour en ouvrir un."),
                }
            },
            "open" => {
                match pick_existing_vault() {
                    Some(path) => match open_vault(&path) {
                        Ok(vault) => {
                            display_logo(true, &path);
                            println!("{GREEN}✓ Vault ouvert avec succès !{RESET}");
                            vault_option = Some(vault);
                            current_path = Some(path);
                        }
                        Err(e) => {
                            eprintln!("Erreur lors de l'ouverture du vault : {}", e);
                        }
                    },
                    None => println!("Ouverture annulée."),
                }
            },
            "gen"   => { 
                
                loop {
                    //Demande de longueur à generer
                    print!("Longueur (si rien, par défaut 20. Sinon Choisir entre 1 et 255) : ");
                    io::stdout().flush()?;
                    
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;

                    //Converti la chaine en int
                    let length: u8 = if input.trim().is_empty() {
                        20 // valeur par défaut
                    } else {
                        input.trim().parse().unwrap_or(20) // parse ou valeur par défaut si erreur
                    };

                    //*
                    if length > 0 {
                        let generate = generate_password(length);
                        println!("{generate}");
                        break; // Sort de la boucle si les mots de passe correspondent
                    } else {
                        println!("Cette longueur est invalide");
                    }

                }

            },
            "help"  => display_commands(),
            ""      => continue,
            _       => {
                println!("Commande inconnue. Tapez 'help' pour la liste des commandes.");
            }
        }
    }

    Ok(())
}

/**
* Affichage de l'écran d'accueil
*/
fn display_logo(open: bool, path: &Path) {

    let logo = [
        "██╗   ██╗ █████╗ ██╗   ██╗██╗   ████████╗",
        "██║   ██║██╔══██╗██║   ██║██║   ╚══██╔══╝",
        "██║   ██║███████║██║   ██║██║      ██║   ",
        "╚██╗ ██╔╝██╔══██║██║   ██║██║      ██║   ",
        " ╚████╔╝ ██║  ██║╚██████╔╝███████╗ ██║   ",
        "  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═╝   ",
    ];

    let info = [
        format!("{CYAN}vault@secure{RESET}"),
        format!("{GREEN}OS:{RESET}           Windows | Linux"),
        format!("{GREEN}Version:{RESET}      {VERSION}"),
        format!("{GREEN}Shell:{RESET}        vault"),
        format!("{GREEN}Security:{RESET}     AES-256 | Zero-Trust"),
        format!("{GREEN}Storage Path:{RESET} {}", path.display()),
        if !open {
            format!("{GREEN}Status:{RESET}    {RED}Locked 🔒{RESET}")
        } else {
            format!("{GREEN}Status:{RESET}    {CYAN}Open 🔓{RESET}")
        }
    ];

    let width = 55; // espace réservé au logo

    for i in 0..logo.len().max(info.len()) {
        let left = logo.get(i).unwrap_or(&"");
        let right = info.get(i).map(|s| s.as_str()).unwrap_or("");
        println!("{CYAN}{left:<width$}{RESET}  {right}");
    }
}

/**
* Demande du mot de passe 
* Renvoi un type String
*/
fn get_password() -> io::Result<Zeroizing<String>> {

    io::stdout().flush()?;

    let password = rpassword::prompt_password("Mot de passe du coffre : ")
        .map_err(io::Error::other)?;
    let password = Zeroizing::new(password.trim().to_string());

    if password.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Le mot de passe ne peut pas être vide"
        ));
    }

    Ok(password)
}

/**
* Teste si le fichier existe déjà
*/
fn vault_exists(path: &Path) -> bool {
    path.exists()
}

/**
* Dialogue natif pour choisir un fichier vault existant à ouvrir.
* Renvoie None si l'utilisateur annule.
*/
fn pick_existing_vault() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .set_title("Ouvrir un vault")
        .add_filter("Vault", &["vault"])
        .pick_file()
}

/**
* Dialogue natif pour choisir où créer un nouveau vault.
* Renvoie None si l'utilisateur annule.
*/
fn pick_new_vault() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .set_title("Créer un vault")
        .add_filter("Vault", &["vault"])
        .set_file_name("safe.vault")
        .save_file()
}

/*
* Initialisation du coffre
*
*/
fn init(path: &Path) -> io::Result<()> {

    //Test si un fichier existe déjà
    if vault_exists(path) {
        println!("Le vault existe déjà !");
        return Ok(());
    }

    println!("Saisir le mot de passe maître ");
    println!("!! ATTENTION !!");
    println!("NE PERDEZ PAS CE MOT DE PASSE ! SINON VOS DONNEES SERONT PERDUES !!");

    // Boucle jusqu'à ce que les deux saisies correspondent.
    // Les mots de passe sont enveloppés dans Zeroizing → effacés de la RAM au Drop.
    let password: Zeroizing<String> = loop {
        let p = match rpassword::prompt_password("Mot de passe : ") {
            Ok(p) => Zeroizing::new(p),
            Err(error) => {
                eprintln!("Erreur : {}", error);
                continue;
            }
        };

        let confirm = match rpassword::prompt_password("Confirmez le mot de passe : ") {
            Ok(c) => Zeroizing::new(c),
            Err(error) => {
                eprintln!("Erreur : {}", error);
                continue;
            }
        };

        if p.trim() == confirm.trim() {
            break p; // Sort de la boucle si les mots de passe correspondent
        }
        println!("Les mots de passe ne correspondent pas. Veuillez réessayer.");
    };

    // Créer un vault vide
    let empty_vault = PasswordVault {
        credentials: HashMap::new(),
    };

    // Sérialiser en JSON
    let json_data = serde_json::to_string(&empty_vault)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    //Génération d'un sel
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    //Dériver la clé avec Argon2
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password.trim().as_bytes(), &salt, key_bytes.as_mut_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    
    //Clé de chiffrement au format AES 256
    let key = Key::<Aes256Gcm>::from_slice(key_bytes.as_slice());
    let cipher = Aes256Gcm::new(key);

    // Générer un nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Chiffrement du JSON
    let ciphertext = cipher.encrypt(nonce, json_data.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    let mut fichier = File::create(path)?;

    //Ecriture dans le fichier vault
    fichier.write_all(&salt)?;
    fichier.write_all(&nonce_bytes)?;
    fichier.write_all(&ciphertext)?;

    println!("Vault créé avec succès !");

    Ok(())
}

// Dérivation de clé
fn derive_key(password: &str, salt: &[u8; 16]) -> io::Result<Zeroizing<[u8; 32]>> {
    let mut key_bytes = Zeroizing::new([0u8; 32]);

    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, key_bytes.as_mut_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    Ok(key_bytes)
}

/**
* Ajout d'une entrée dans le vault
*/
fn add_entry(vault: &mut PasswordVault, args: &str, path: &Path) -> io::Result<()> {

    println!("{GREEN}==={RESET} Ajout d'une nouvelle entrée {GREEN}==={RESET}");
    let mut alias = String::new();

    if !args.is_empty() {
        alias = args.parse().unwrap();
        println!("Alias : {}", args);
    } else {
        print!("Alias (ex: github, gmail) : ");
        io::stdout().flush()?;
        io::stdin().read_line(&mut alias)?;
        alias = alias.trim().to_string();
    }

    //Test si l'entrée existe déjà sinon le creer
    match vault.credentials.get(&alias) {
        Some(cred) => {
            println!("{RED}=== Entrée déjà existante ==={RESET}");
            println!("Alias      : {}", alias);
            println!("Utilisateur: {}", cred.user);
            println!("(Utilisez '{GREEN}get {alias}{RESET}' pour afficher le mot de passe.)");
            println!();
        }
        None => {
            print!("Nom d'utilisateur : ");
            io::stdout().flush()?;
            let mut username = String::new();
            io::stdin().read_line(&mut username)?;
            let username = username.trim().to_string();

            io::stdout().flush()?;

            let password = rpassword::prompt_password("Mot de passe : ")
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            let password = password.trim().to_string();

            let credential = Credential {
                user: username,
                password,
            };

            vault.credentials.insert(alias.clone(), credential);

            // Sauvegarder le vault ; si la sauvegarde échoue (ex. mauvais mot de
            // passe), on annule l'ajout en mémoire pour rester cohérent avec le disque.
            if let Err(e) = save_vault(vault, path) {
                vault.credentials.remove(&alias);
                return Err(e);
            }

            println!("Entrée '{}' ajoutée avec succès !", alias);
        }
    }



    Ok(())
}

/**
* Generate à partir des codes ascii imprimables 33 -> 126 (l'espace 32 est exclu
* pour éviter un caractère invisible dans le mot de passe).
* ATTENTION avec rand version 0.9 il faut utiliser  rand::rng(); puis random_range()
*/
fn generate_password(length: u8) -> String {

    let mut rng = rand::thread_rng();

    (0..length) //itérateur plage de
        .map(|_| rng.gen_range(33..=126) as u8 as char) //map |_| indique qu'on ne sert pas de la valeur
        .collect() //sans point virgule pour retourner la valeur automatiquement
}

/**
* Liste les entrées du vault
*/
fn list_entries(vault: &PasswordVault) {
    if vault.credentials.is_empty() {
        println!("Le vault est vide.");
        return;
    }
    println!("{GREEN}==={RESET} Entrées du vault {GREEN}==={RESET}");
    for (alias, cred) in &vault.credentials {
        println!("• {} - {}", alias, cred.user);
    }
    println!();
}

/**
* Récupère une entrée du vault par alias
*/
fn get_entry(vault: &PasswordVault, args: &str) -> io::Result<()> {
    if vault.credentials.is_empty() {
        println!("Le vault est vide.");
        return Ok(());
    }

    let mut alias = String::new();

    if !args.is_empty() {
        alias = args.parse().unwrap();
    } else {
        print!("Alias à rechercher : ");
        io::stdout().flush()?;

        io::stdin().read_line(&mut alias)?;
        alias = alias.trim().to_string();
    }

    //Demander le mot de passe
    match vault.credentials.get(&alias) {
        Some(cred) => {
            println!("{GREEN}==={RESET} Entrée trouvée {GREEN}==={RESET}");
            println!("Alias      : {}", alias);
            println!("Utilisateur: {}", cred.user);
            println!("Mot de passe: {}", cred.password);
            println!();
        }
        None => {
            println!("Aucune entrée trouvée pour l'alias '{}'", alias);
            println!("\nEntrées disponibles :");
            for key in vault.credentials.keys() {
                println!("  • {}", key);
            }
        }
    }

    Ok(())
}

/**
* Supprime une entrée du vault par alias
*/
fn delete_entry(vault: &mut PasswordVault, path: &Path) -> io::Result<()> {
    if vault.credentials.is_empty() {
        println!("Le vault est vide.");
        return Ok(());
    }

    list_entries(vault);
    print!("Alias à supprimer : ");
    io::stdout().flush()?;
    let mut alias = String::new();
    io::stdin().read_line(&mut alias)?;
    let alias = alias.trim();

    // Vérifier si l'entrée existe
    if !vault.credentials.contains_key(alias) {
        println!("Aucune entrée trouvée pour l'alias '{}'", alias);
        println!("\nEntrées disponibles :");
        for key in vault.credentials.keys() {
            println!("  • {}", key);
        }
        return Ok(());
    }

    // Afficher l'entrée à supprimer
    if let Some(cred) = vault.credentials.get(alias) {
        println!("\n⚠️  Entrée à supprimer :");
        println!("Alias      : {}", alias);
        println!("Utilisateur: {}", cred.user);
    }

    // Demander confirmation
    print!("\nÊtes-vous sûr de vouloir supprimer cette entrée ? (oui/non) : ");
    io::stdout().flush()?;
    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation)?;
    let confirmation = confirmation.trim().to_lowercase();

    if confirmation == "oui" || confirmation == "o" || confirmation == "yes" || confirmation == "y" {
        // On retire l'entrée puis on sauvegarde ; si la sauvegarde échoue,
        // on la remet en mémoire pour rester cohérent avec le disque.
        if let Some(removed) = vault.credentials.remove(alias)
            && let Err(e) = save_vault(vault, path)
        {
            vault.credentials.insert(alias.to_string(), removed);
            return Err(e);
        }

        println!("{GREEN}✓ Entrée '{}' supprimée avec succès !{RESET}", alias);
    } else {
        println!("Suppression annulée.");
    }

    Ok(())
}

/**
* Sauvegarde le vault
*/
fn save_vault(vault: &PasswordVault, path: &Path) -> io::Result<()> {
    let password = get_password()?;

    // Sérialiser en JSON (contient les secrets en clair → effacé au Drop)
    let json_data = Zeroizing::new(serde_json::to_string(&vault)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?);

    // Lire le contenu existant (sel + nonce + ciphertext)
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    // Garde : fichier corrompu ou incomplet (16 octets de sel + 12 de nonce = 28 minimum)
    if data.len() < 28 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Fichier vault corrompu ou incomplet",
        ));
    }

    let salt: [u8; 16] = data[0..16].try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Salt invalide"))?;
    let old_nonce_bytes: [u8; 12] = data[16..28].try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Nonce invalide"))?;
    let old_ciphertext = &data[28..];

    // Dériver la clé à partir du mot de passe saisi
    let key_bytes = derive_key(&password, &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(key_bytes.as_slice());
    let cipher = Aes256Gcm::new(key);

    // VÉRIFICATION : on déchiffre l'ancien contenu avec cette clé.
    // Si ça échoue, le mot de passe est faux → on refuse d'écraser le vault
    // pour éviter de le rendre définitivement illisible.
    let old_nonce = Nonce::from_slice(&old_nonce_bytes);
    if cipher.decrypt(old_nonce, old_ciphertext).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Mot de passe incorrect — sauvegarde annulée pour ne pas corrompre le vault",
        ));
    }

    // Mot de passe validé : nouveau nonce pour cette sauvegarde
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Chiffrer
    let ciphertext = cipher.encrypt(nonce, json_data.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    // Écrire
    let mut file = File::create(path)?;
    file.write_all(&salt)?;
    file.write_all(&nonce_bytes)?;
    file.write_all(&ciphertext)?;

    Ok(())
}

/**
* Ouverture du vault et init du struct
* 
*/
fn open_vault(path: &Path) -> io::Result<PasswordVault> {

    let password = get_password()?;
    let mut file = File::open(path)?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    // Garde : fichier corrompu ou incomplet (16 octets de sel + 12 de nonce = 28 minimum)
    if data.len() < 28 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Fichier vault corrompu ou incomplet",
        ));
    }

    // Reconstruction
    let salt: [u8; 16] = data[0..16].try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Salt invalid"))?;
    let nonce_bytes: [u8; 12] = data[16..28].try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Nonce invalid"))?;
    let ciphertext = &data[28..];

    //Init vault_secret
    let vault_secret = Vault {
        salt,
        nonce_bytes,
        cyphertext: ciphertext.to_vec()
    };

    //Décryptage du vault et recuperation des entrées
    let vault = decrypt_vault(&vault_secret, &password)?;
    
    Ok(vault)
}

/**
* Decryptage du vault
*
*/
fn decrypt_vault(vault: &Vault, password: &str) -> io::Result<PasswordVault> {

    // Dériver la clé
    let key_bytes = derive_key(password, &vault.salt)?;

    // Génération du chiffrement
    let key = Key::<Aes256Gcm>::from_slice(key_bytes.as_slice());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&vault.nonce_bytes);

    // Déchiffrer (le clair contient tous les secrets → effacé au Drop)
    let plaintext = Zeroizing::new(cipher
        .decrypt(nonce, vault.cyphertext.as_ref())
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "Mot de passe incorrect ou données corrompues"))?);

    // Désérialiser le JSON
    let password_vault: PasswordVault = serde_json::from_slice(plaintext.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(password_vault)
}

/**
* Display Commands Menu
* le r# sert à formater la chaine tel quel
*/
fn display_commands() {
    println!(
        r#"
        Commandes disponibles :
        
        {GREEN}init{RESET}
            Initialiser un nouveau coffre (choix du fichier via un dialogue)

        {GREEN}add [alias]{RESET}
            Ajoute une nouvelle entrée au vault

        {GREEN}list{RESET}
            Liste toutes les entrées

        {GREEN}get [alias]{RESET}
            Récupère et affiche une entrée par alias
            Exemple : get github

        {GREEN}gen{RESET}
            Génère un mot de passe avec longueur

        {GREEN}delete{RESET}
            Supprime une entrée du vault par alias
            Exemple : delete github

        {GREEN}open{RESET}
            Choisit et ouvre un vault via un dialogue de sélection de fichier

        {GREEN}version{RESET}
            Affiche la version

        {GREEN}help{RESET}
            Affiche cette aide

        {GREEN}quit{RESET}
            Sortir

        Note : Les données sont chiffrées avec AES-256-GCM
        "#
    );
}