#[macro_use]
extern crate magic_crypt;
extern crate passwords;
use magic_crypt::MagicCryptTrait;
use passwords::analyzer;
use passwords::scorer;
use passwords::PasswordGenerator;
use std::path::Path;
use std::collections::HashMap;
use std::io::Write;

mod data;

fn main() {
    // Get arguments
    let args: Vec<String> = std::env::args().collect();

    // Setup for later
    let mut password = String::new();
    let mut db: HashMap<String, String>;

    if args.len() == 2 && args[1] != "init" {
        print!("Password: "); 
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_line(&mut password).unwrap();

        db = data::load_data(&args[1]);
        if db.is_empty() {
            println!("!! No database found for passwords!");
            std::process::exit(-1);
        }

        //Create encryptor
        let mcrypt = new_magic_crypt!(password.clone(), 256);

        match db.get(&mcrypt.encrypt_str_to_base64("password")) {
            Some(e) => {
                let check = mcrypt.
                    decrypt_base64_to_string(e)
                    .unwrap_or_else(|_| "".to_string());
                
                if check != "test" {
                    println!("!! Incorrect Password, exiting...");
                    std::process::exit(-1);
                }

                println!("Welcome back!");
                println!("> Supported commands are:\n- add [acccount-name] [password]\n- remove [account-name]\n- add [account-name]\n- get [account-name]\n- get all\n- quit");
            }

            None => {
                println!("!! Incorrect Password, exiting...");
                std::process::exit(-1);
            }
        }
    } else if args.len() == 3 && args[1] == "init" {
        let db_file = ["./", &args[2], ".json"].join("");
        if Path::new(&db_file).exists() {
            return println!("!! This database already exists.")
        }

        print!("Password to use: ");
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_line(&mut password).unwrap();

        let mcrypt = new_magic_crypt!(password, 256);

        // These are control key-val used to verify password in later log-ins
        // If these decrypt correctly then the password is correct
        let key = mcrypt.encrypt_str_to_base64("password");
        let val = mcrypt.encrypt_str_to_base64("test");

        let mut temp = HashMap::<String, String>::new();
        temp.insert(key, val);

        match data::save_data(&db_file, &temp) {
            Err(e) => {
                println!("!! Unable to create file: {}\nexiting...", e);
                std::process::exit(-1);
            }
            _ => std::process::exit(0),
        }
    } else {
        println!("!! Incorrect usage.\nSyntax: {:?} [init] (db_name)", args[0]);
        std::process::exit(-1);
    }

    let mcrypt = new_magic_crypt!(password, 256);
    let pg = PasswordGenerator {
        length: 16,
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: true,
        spaces: true,
        exclude_similar_characters: false,
        strict: true,
    };

    loop {
        let mut line: String = String::new();
        std::io::stdin().read_line(&mut line).unwrap_or(0);
        let tokens: Vec<_> = line.trim().split(' ').collect();

        match tokens[0].trim() {
            "add" => {
                if tokens.len() == 2 { 
                    // add account-name
                    db.insert(
                        mcrypt.encrypt_str_to_base64(tokens[1]),
                        mcrypt.encrypt_str_to_base64(pg.generate_one().unwrap()),
                    );
                } else {
                    // add account-name password
                    let score: f64 = scorer::score(&analyzer::analyze(tokens[2]));

                    if score < 80.0 {
                        println!("> Given password has a weak score ({}), sure you want to add this? y/n", score);

                        let mut line: String = String::new();
                        std::io::stdin().read_line(&mut line).unwrap_or(0);
                        let tok: Vec<_> = line.trim().split(' ').collect();
                        let choice = tok[0].to_lowercase();

                        if choice == "y" || choice == "Y" || choice == "yes" {
                            db.insert(
                                mcrypt.encrypt_str_to_base64(tokens[1]),
                                mcrypt.encrypt_str_to_base64(tokens[2]),
                            );
                        } else {
                            println!("> Password was not saved.");
                            continue;
                        }
                    }
                }

                // save the data to file
                match data::save_data(&args[1], &db) {
                    Err(e) => println!("!! Error in saving data: {}", e),
                    Ok(()) => {
                        println!("> Successfully added.");
                    }
                }
            }

            "remove" => {
                if tokens.len() != 2 {
                    println!("!! Correct usage: remove [account-name]");
                    continue;
                } else {
                    println!("> Are you sure you want to remove the entry for {}? y/n", tokens[1]);

                    let mut line: String = String::new();
                    std::io::stdin().read_line(&mut line).unwrap_or(0);
                    let tok: Vec<_> = line.trim().split(' ').collect();
                    let choice = tok[0].to_lowercase();

                    if choice == "y" || choice == "Y" || choice == "yes" {
                        db.remove(&mcrypt.encrypt_str_to_base64(tokens[1]));

                        // save the data to file
                        match data::save_data(&args[1], &db) {
                            Err(e) => println!("!! Error in saving data: {}", e),
                            Ok(()) => {
                                println!("> Successfully removed.");
                            }
                        }
                    } else {
                        println!("> Password was not deleted.");
                        continue;
                    }
                }
            }

            "get" => {
                if tokens.len() != 2 {
                    println!("!! Correct usage: get [account-name/all]");
                    continue;
                }
                else {
                    match tokens[1] {
                        "all" => {
                            // Get all
                            // For getting all accounts and passwords
                            if db.iter().len() <= 1 {
                                println!("No passwords found.")
                            }

                            for (key, val) in db.iter() {
                                let acc = mcrypt
                                    .decrypt_base64_to_string(key)
                                    .unwrap_or_else(|_| "!! Error in decryption".to_string());

                                // skip the control key-val
                                if acc == "password" {
                                    continue;
                                }

                                let pass = mcrypt
                                    .decrypt_base64_to_string(val)
                                    .unwrap_or_else(|_| "!! Error in decryption".to_string());
                                println!("{}: {}", acc, pass);
                            }
                        }
                        _ => {
                            // Get account-name
                            // For getting specific account-name
                            let key = mcrypt.encrypt_str_to_base64(tokens[1]);
                            match db.get(&key) {
                                Some(val) => {
                                    let pass = mcrypt
                                        .decrypt_base64_to_string(val)
                                        .unwrap_or_else(|_| "!! Error in decryption".to_string());
                                    println!("{}", pass);
                                }
                                None => {
                                    println!("!! No account named {} found", tokens[1]);
                                }
                            }
                        }
                    }
                }
            }

            "quit" => std::process::exit(0),

            _ => println!("> Supported commands are:\n- add [acccount-name] [password]\n- add [account-name]\n- remove [account-name]\n- get [account-name]\n- get all\n- quit"),
        }
    }
}
