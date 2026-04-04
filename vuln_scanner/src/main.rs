use clap::Parser;
use serde::Serialize;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

// Argumentos de línea de comandos
#[derive(Parser, Debug)]
#[command(name = "vuln_scanner")]
#[command(about = "NetGuard — Escáner de puertos en Rust")]
struct Args {
    /// Host a escanear (IP o dominio)
    #[arg(short = 'H', long)]
    host: String,

    /// Puerto inicial
    #[arg(short = 's', long, default_value = "1")]
    start: u16,

    /// Puerto final
    #[arg(short = 'e', long, default_value = "1024")]
    end: u16,

    /// Timeout por puerto en milisegundos
    #[arg(short, long, default_value = "1000")]
    timeout: u64,

    /// Máximo de puertos concurrentes
    #[arg(short, long, default_value = "100")]
    concurrencia: usize,
}

// Resultado de cada puerto escaneado
#[derive(Serialize, Debug)]
struct ResultadoPuerto {
    puerto: u16,
    estado: String,
    servicio: String,
    latencia_ms: u64,
}

// Mapeo de puertos conocidos a servicios
fn identificar_servicio(puerto: u16) -> &'static str {
    match puerto {
        21   => "FTP",
        22   => "SSH",
        23   => "Telnet",
        25   => "SMTP",
        53   => "DNS",
        80   => "HTTP",
        110  => "POP3",
        143  => "IMAP",
        443  => "HTTPS",
        445  => "SMB",
        853 => "DNS-over-TLS",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        6379 => "Redis",
        8000 => "HTTP-dev",
        8080 => "HTTP-alt",
        8443 => "HTTPS-alt",
        _    => "desconocido",
    }
}

// Escanea un puerto individual y retorna el resultado
async fn escanear_puerto(host: &str, puerto: u16, timeout_ms: u64) -> ResultadoPuerto {
    let addr = format!("{}:{}", host, puerto);
    let servicio = identificar_servicio(puerto).to_string();
    let inicio = std::time::Instant::now();

    let resultado = timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(&addr)
    ).await;

    let latencia_ms = inicio.elapsed().as_millis() as u64;

    let estado = match resultado {
        Ok(Ok(_))  => "abierto".to_string(),   // conexión exitosa
        Ok(Err(_)) => "cerrado".to_string(),   // RST recibido
        Err(_)     => "filtrado".to_string(),  // timeout — firewall
    };

    ResultadoPuerto { puerto, estado, servicio, latencia_ms }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    println!("NetGuard Scanner — escaneando {}:{}-{}",
        args.host, args.start, args.end);
    println!("Timeout: {}ms | Concurrencia: {} puertos simultáneos\n",
        args.timeout, args.concurrencia);

    let total = (args.end - args.start + 1) as usize;
    let puertos: Vec<u16> = (args.start..=args.end).collect();

    // Procesamos en chunks — cada chunk corre concurrentemente
    let mut abiertos = Vec::new();
    let mut procesados = 0;

    for chunk in puertos.chunks(args.concurrencia) {
        // Creamos una tarea async por cada puerto del chunk
        let tareas: Vec<_> = chunk.iter().map(|&puerto| {
            let host = args.host.clone();
            tokio::spawn(async move {
                escanear_puerto(&host, puerto, args.timeout).await
            })
        }).collect();

        // Esperamos que terminen todas las tareas del chunk
        for tarea in tareas {
            if let Ok(resultado) = tarea.await {
                if resultado.estado == "abierto" {
                    abiertos.push(resultado);
                }
            }
        }

        procesados += chunk.len();
        eprint!("\rProgreso: {}/{} puertos escaneados...", procesados, total);
    }

    eprintln!(); // nueva línea después del progreso

    // Mostramos resultados
    println!("\n{} puertos abiertos encontrados:\n", abiertos.len());
    println!("{:<8} {:<12} {:<15} {}", "PUERTO", "ESTADO", "SERVICIO", "LATENCIA");
    println!("{}", "-".repeat(50));

    for r in &abiertos {
        println!("{:<8} {:<12} {:<15} {}ms",
            r.puerto, r.estado, r.servicio, r.latencia_ms);
    }

    // Output JSON para integración con NetGuard
    println!("\n--- JSON ---");
    println!("{}", serde_json::to_string_pretty(&abiertos).unwrap());
}