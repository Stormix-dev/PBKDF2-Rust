use std::fs::{self, File}; // Per l'interazione con il file system
use std::io::{BufRead, BufReader, Write}; // Per la lettura e scrittura di file
use std::sync::{Arc, Mutex}; // Per la gestione della concorrenza tra thread
use std::thread; // Per la creazione e gestione dei thread
use pbkdf2::pbkdf2_hmac; // Per il calcolo dell'hash PBKDF2
use sha2::Sha256; // Per l'algoritmo SHA256

// Definiamo i parametri per il PBKDF2
const ITERATIONS: u32 = 4096; // Numero di iterazioni del PBKDF2
const KEY_LENGTH: usize = 32; // Lunghezza della chiave in byte (256 bit per SHA256)

/// Funzione per calcolare l'hash di una password con un "salt" (rete) dato
fn hash_password(password: &str, rete: &str) -> String {
    // Converto la rete in byte (salt per il PBKDF2)
    let salt = rete.as_bytes();
    let mut hash = [0u8; KEY_LENGTH]; // Inizializza un array per l'hash (32 byte per SHA256)

    // Calcola l'hash usando PBKDF2 con SHA256
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, ITERATIONS, &mut hash);
    
    // Converte l'hash in una stringa esadecimale (solo i primi 16 byte)
    hash.iter().take(16).map(|b| format!("{:02x}", b)).collect()
}

/// Funzione per leggere un file e restituire il contenuto come un vettore di stringhe
fn read_file(file_path: &str) -> Vec<String> {
    // Apre il file
    let file = File::open(file_path).expect("Impossibile aprire il file");
    let reader = BufReader::new(file); // Crea un reader per leggere il file in modo efficiente
    reader.lines()
        .map(|line| line.expect("Errore nella lettura della riga")) // Legge ogni riga e la converte in una stringa
        .collect() // Colleziona tutte le righe in un vettore
}

/// Funzione per scrivere un vettore di stringhe in un file
fn write_to_file(file_path: &str, data: &[String]) {
    // Crea un file per la scrittura
    let mut file = File::create(file_path).expect("Impossibile creare il file");

    // Scrive ogni linea nel file
    for line in data {
        writeln!(file, "{}", line).expect("Errore nella scrittura sul file");
    }
}

fn main() {
    // Percorsi dei file di input e output
    let input_file_reti = "src/reti.txt";
    let input_file_passwords = "src/passwords.txt";
    let output_file = "src/PMK.txt";

    // Leggi il contenuto dei file "reti.txt" e "passwords.txt"
    let reti = read_file(input_file_reti);
    let passwords = read_file(input_file_passwords);

    // Condividiamo i risultati tra i thread usando Arc (per la condivisione sicura) e Mutex (per evitare conflitti)
    let results = Arc::new(Mutex::new(Vec::new()));
    
    // Un vettore per raccogliere i handle dei thread
    let mut handles = Vec::new();

    // Iniziamo il timer per misurare il tempo di esecuzione
    let start_time = std::time::Instant::now();

    // Ciclo su ogni rete
    for rete in reti {
        // Creiamo una copia dei dati necessari per ogni thread
        let passwords = passwords.clone();
        let results = Arc::clone(&results); // Cloniamo Arc per usarlo nel thread

        // Creiamo un nuovo thread per elaborare una rete
        let handle = thread::spawn(move || {
            // Per ogni password, calcoliamo l'hash
            for password in passwords {
                let hashed = hash_password(&password, &rete);

                // Blocchiamo l'accesso al vettore `results` per evitare conflitti
                let mut results_lock = results.lock().unwrap();
                // Aggiungiamo l'hash calcolato alla lista dei risultati
                results_lock.push(hashed);
            }
        });

        // Salviamo l'handle del thread per poter aspettare che termini
        handles.push(handle);
    }

    // Attendere che tutti i thread finiscano
    for handle in handles {
        handle.join().expect("Errore nel thread");
    }

    // Dopo che tutti i thread sono finiti, scriviamo i risultati nel file di output
    let results = results.lock().unwrap();
    write_to_file(output_file, &results);

    // Misuriamo il tempo impiegato per l'esecuzione
    let duration = start_time.elapsed();
    println!("Hashing completato in: {:?} ms", duration.as_millis());
}
