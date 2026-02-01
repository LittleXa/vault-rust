/*
* Vault
* Secret Credentials in Secure Vault
*
* littleXa
* 2026
*
*
* TODO list :
* - changer les unwrap par un message d'erreur (Result(<T, E>))
* - rpassword pour masquer le mot de passe
* - personnaliser le nom du coffre et le chemin
* - intégrer une fonction de génération
*/

//Global constants
const VERSION: &str = "1.0.0";

//Pour recupere la saisie utilisateur
use std::io;

//Ecriture de fichier Texte
use std::fs::File;
use std::path::Path;
use std::io::{Read, Write};

//JSON
use serde::{Deserialize, Serialize};

//Utilisation d'un hashmap
use std::collections::HashMap;

//Génération Aléatoire et Hex
use rand::RngCore;
use rand::rngs::OsRng;

//Crypto
use argon2::Argon2;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};

//Couleurs
use colored::Colorize;

/**
* Structure de tableau de type unsigned 8bits
* Le derive permet d'implementer les traits debug et clone
*/
#[derive(Debug, Clone)]
struct Vault {
    salt: [u8; 16], //tableau de 16 octets en u8
    nonce_bytes: [u8; 12], //tableau de 12 octets en u8
    cyphertext: Vec<u8> 
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Credential {
    user: String,
    password: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PasswordVault {
    credentials: HashMap<String, Credential>,
}

fn main() -> io::Result<()> {

    println!(r#"                    
                  ▄▄       
                  ██  ██   
██ ██  ▀▀█▄ ██ ██ ██ ▀██▀▀ 
██▄██ ▄█▀██ ██ ██ ██  ██   
 ▀█▀  ▀█▄██ ▀██▀█ ██  ██       
    "#);

    //println!("{} {} !", "it".green(), "works".blue().bold());
    println!("{}", "Bienvenue dans Vault".red().bold());
   
    println!("\n");

    // Vérifier si un vault existe
    if !vault_exists() {
        println!("{}", "Aucun vault trouvé. Utilisez 'init' pour en créer un.".blue());
        println!("\n");
    }

    // Charger le vault en mémoire si il existe
    let mut vault_option: Option<PasswordVault> = None;
    
    if vault_exists() {
        match open_vault() {
            Ok(vault) => {
                println!("{}", "✓ Vault ouvert avec succès !\n".blue());
                 println!("Tapez 'quit' pour quitter ou 'help'.");
                vault_option = Some(vault);
            }
            Err(e) => {
                eprintln!("❌ Erreur lors de l'ouverture du vault : {}", e);
                println!("Vous pouvez réessayer avec la commande 'open' ou créer un nouveau vault avec 'init'\n");
            }
        }
    }

    //Boucle principale
    loop {
        // Affiche le prompt
        //clear
        print!(">> ");
        io::stdout().flush()?;
        // Lit l'entrée utilisateur
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let command = input.trim();

        // Traite la commande
        match command {
            "quit" => {
                println!("Au revoir !");
                break;
            },
            "version" => println!("Version {}", VERSION),
            "init" => {
                if let Err(e) = init() {
                    eprintln!("Erreur lors de l'initialisation : {}", e);
                } else {
                    // Charger le nouveau vault
                    match open_vault() {
                        Ok(vault) => {
                            vault_option = Some(vault);
                        }
                        Err(e) => {
                            eprintln!("Erreur lors de l'ouverture du vault : {}", e);
                        }
                    }
                }
            },
            "add" => {
                if let Some(ref mut vault) = vault_option {
                    if let Err(e) = add_entry(vault) {
                        eprintln!("Erreur lors de l'ajout : {}", e);
                    }
                } else {
                    println!("❌ Aucun vault ouvert. Utilisez 'init' pour créer un vault ou 'open' pour en ouvrir un.");
                }
            },
            "list" => {
                if let Some(ref vault) = vault_option {
                    list_entries(vault);
                } else {
                    println!("❌ Aucun vault ouvert. Utilisez 'init' pour créer un vault ou 'open' pour en ouvrir un.");
                }
            },
            "get" => {
                if let Some(ref vault) = vault_option {
                    if let Err(e) = get_entry(vault) {
                        eprintln!("Erreur lors de la récupération : {}", e);
                    }
                } else {
                    println!("❌ Aucun vault ouvert. Utilisez 'init' pour créer un vault ou 'open' pour en ouvrir un.");
                }
            },
            "delete" => {
                if let Some(ref mut vault) = vault_option {
                    if let Err(e) = delete_entry(vault) {
                        eprintln!("Erreur lors de la suppression : {}", e);
                    }
                } else {
                    println!("❌ Aucun vault ouvert. Utilisez 'init' pour créer un vault ou 'open' pour en ouvrir un.");
                }
            },
            "open" => {
                match open_vault() {
                    Ok(vault) => {
                        println!("✓ Vault ouvert avec succès !");
                        vault_option = Some(vault);
                    }
                    Err(e) => {
                        eprintln!("❌ Erreur lors de l'ouverture du vault : {}", e);
                    }
                }
            },
            //"gen"   => generate_password(10),
              
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
* Demande du mot de passe 
* Renvoi un type String
*/
fn get_password() -> io::Result<String> {

    print!("Mot de passe du coffre : ");
    io::stdout().flush()?;
    
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    
    let password = password.trim().to_string();

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
fn vault_exists() -> bool {
    Path::new("safe.vault").exists()
}

/*
* Initialisation du coffre
*
*/
fn init() -> io::Result<()> {

    //Test si un fichier existe déjà
    if vault_exists() {
        println!("Le vault existe déjà !");
        return Ok(());
    }

    let mut password = String::new();
    let mut confirm = String::new();

    loop {
        password.clear();
        confirm.clear();
        println!("Saisir le mot de passe maître ");
        println!("!! ATTENTION !!");
        println!("NE PERDEZ PAS CE MOT DE PASSE ! SINON VOS DONNEES SERONT PERDUES !!");
        match io::stdin().read_line(&mut password) {
            Ok(_n) => {},
            Err(error) => {
                eprintln!("Erreur : {}", error);
                continue;
            }
        }

        println!("Confirmez le mot de passe");
        match io::stdin().read_line(&mut confirm) {
            Ok(_n) => {},
            Err(error) => {
                eprintln!("Erreur : {}", error);
                continue;
            }
        }

        if password.trim() == confirm.trim() {
            break; // Sort de la boucle si les mots de passe correspondent
        } else {
            println!("Les mots de passe ne correspondent pas. Veuillez réessayer.");
        }
    }

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
    let mut key_bytes = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.trim().as_bytes(), &salt, &mut key_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    
    //Clé de chiffrement au format AES 256
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Générer un nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Chiffrement du JSON
    let ciphertext = cipher.encrypt(nonce, json_data.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    let mut fichier = File::create("safe.vault")?;

    //Ecriture dans le fichier vault 
    fichier.write_all(&salt)?;
    fichier.write_all(&nonce_bytes)?;
    fichier.write_all(&ciphertext)?;

    println!("Vault créé avec succès !");

    Ok(())
}

// Dérivation de clé
fn derive_key(password: &str, salt: &[u8; 16]) -> io::Result<[u8; 32]> {
    let mut key_bytes = [0u8; 32];
    
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    
    Ok(key_bytes)
}

/**
* Ajout d'une entrée dans le vault
*/
fn add_entry(vault: &mut PasswordVault) -> io::Result<()> {

    println!("=== Ajout d'une nouvelle entrée ===");
    
    print!("Alias (ex: github, gmail) : ");
    io::stdout().flush()?;
    let mut alias = String::new();
    io::stdin().read_line(&mut alias)?;
    let alias = alias.trim().to_string();

    print!("Nom d'utilisateur : ");
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim().to_string();

    print!("Mot de passe : ");
    io::stdout().flush()?;
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    let password = password.trim().to_string();

    let credential = Credential {
        user: username,
        password: password,
    };

    vault.credentials.insert(alias.clone(), credential);

    // Sauvegarder le vault
    save_vault(vault)?;

    println!("Entrée '{}' ajoutée avec succès !", alias);

    Ok(())
}

/**
* Liste les entrées du vault
*/
fn list_entries(vault: &PasswordVault) {
    if vault.credentials.is_empty() {
        println!("Le vault est vide.");
        return;
    }

    println!("\n=== Entrées du vault ===");
    for (alias, cred) in &vault.credentials {
        println!("• {} - {}", alias, cred.user);
    }
    println!();
}

/**
* Récupère une entrée du vault par alias
*/
fn get_entry(vault: &PasswordVault) -> io::Result<()> {
    if vault.credentials.is_empty() {
        println!("Le vault est vide.");
        return Ok(());
    }

    print!("Alias à rechercher : ");
    io::stdout().flush()?;
    let mut alias = String::new();
    io::stdin().read_line(&mut alias)?;
    let alias = alias.trim();

    match vault.credentials.get(alias) {
        Some(cred) => {
            println!("\n=== Entrée trouvée ===");
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
fn delete_entry(vault: &mut PasswordVault) -> io::Result<()> {
    if vault.credentials.is_empty() {
        println!("Le vault est vide.");
        return Ok(());
    }

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
        vault.credentials.remove(alias);
        
        // Sauvegarder le vault
        save_vault(vault)?;
        
        println!("✓ Entrée '{}' supprimée avec succès !", alias);
    } else {
        println!("Suppression annulée.");
    }

    Ok(())
}

/**
* Sauvegarde le vault
*/
fn save_vault(vault: &PasswordVault) -> io::Result<()> {
    let password = get_password()?;

    // Sérialiser en JSON
    let json_data = serde_json::to_string(&vault)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Lire le sel et nonce existants
    let mut file = File::open("safe.vault")?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let salt: [u8; 16] = data[0..16].try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Salt invalide"))?;
    
    // Dériver la clé
    let key_bytes = derive_key(&password, &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Nouveau nonce pour chaque sauvegarde
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Chiffrer
    let ciphertext = cipher.encrypt(nonce, json_data.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    // Écrire
    let mut file = File::create("safe.vault")?;
    file.write_all(&salt)?;
    file.write_all(&nonce_bytes)?;
    file.write_all(&ciphertext)?;

    Ok(())
}

/**
* Ouverture du vault et init du struct
* 
*/
fn open_vault() -> io::Result<PasswordVault> {

    let password = get_password()?;

    let file_path = "safe.vault";
    let mut file = File::open(file_path)?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    // Reconstruction
    let salt: [u8; 16] = data[0..16].try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Salt invalide"))?;
    let nonce_bytes: [u8; 12] = data[16..28].try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Nonce invalide"))?;
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
    let key_bytes = derive_key(&password, &vault.salt)?;

    // Génération du chiffrement
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&vault.nonce_bytes);

    // Déchiffrer
    let plaintext = cipher
        .decrypt(nonce, vault.cyphertext.as_ref())
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "Mot de passe incorrect ou données corrompues"))?;
    
    // Désérialiser le JSON
    let password_vault: PasswordVault = serde_json::from_slice(&plaintext)
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
        
        init
            Initialiser un nouveau coffre

        add
            Ajoute une nouvelle entrée au vault

        list
            Liste toutes les entrées

        get
            Récupère et affiche une entrée par alias
            Exemple : get github

        delete
            Supprime une entrée du vault par alias
            Exemple : delete github

        open
            Ouvre et vérifie le vault

        version
            Affiche la version

        help
            Affiche cette aide

        quit
            Sortir

        Note : Les données sont chiffrées avec AES-256-GCM
        "#
    );
}