# Rust Password Manager

## Description

This is just a simple password manager command line application written in Rust.
This is not particularly good or efficient, in fact it uses a json file in invoking directory to save the encrypted passwords.
This was done as a beginner project, trying to learn Rust.
This uses magic-crypt crated to encrypt and decrypt the passwords,
serde to for serialize-deserialize the maps, and
passwords to score the saving passwords and to generate random password.

## Usage

Compile to file.
Run the file for further instructions.
To open a file, just supply the file name (without the .json) as an argument

Then run the file to enter interactive commandline
Supported operations are:

<ol>
  <li>add [account-name]: To generate and save a random password</li>
  <li>add [account-name] [password]: Save a given password</li>
  <li>remove [account-name]: Remove a given password entry</li>
  <li>get all: Get all account passwords</li>
  <li>get [account-name]: Get password for given account name</li>
  <li>quit: to exit the program</li>
</ol>
