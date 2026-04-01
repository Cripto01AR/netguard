use pcap::Capture;
use serde::{Deserialize, Serialize};
use std::io::{self, BufWriter, Write};

// Estructura que representa un paquete procesado
// derive hace que Rust genere automáticamente la serialización a JSON
#[derive(Serialize, Deserialize, Debug)]
struct Paquete {
    timestamp: String,
    src: String,
    dst: String,
    protocolo: String,
    puerto_dst: String,
    longitud: u32,
}

fn parsear_ip(datos: &[u8], offset: usize) -> String {
    if datos.len() < offset + 4 {
        return "?.?.?.?".to_string();
    }
    format!(
        "{}.{}.{}.{}",
        datos[offset],
        datos[offset + 1],
        datos[offset + 2],
        datos[offset + 3]
    )
}

fn procesar_paquete(datos: &[u8], timestamp: &str) -> Option<Paquete> {
    // Ethernet header son 14 bytes — después empieza IP
    if datos.len() < 14 {
        return None;
    }

    // Verificamos que sea IPv4 (0x0800 en bytes 12-13 del header Ethernet)
    let ethertype = ((datos[12] as u16) << 8) | datos[13] as u16;
    if ethertype != 0x0800 {
        return None; // No es IPv4, ignoramos
    }

    // IP header empieza en byte 14
    let ip_start = 14;
    if datos.len() < ip_start + 20 {
        return None;
    }

    let protocolo_num = datos[ip_start + 9]; // byte 9 del header IP = protocolo
    let src = parsear_ip(datos, ip_start + 12);
    let dst = parsear_ip(datos, ip_start + 16);

    // Longitud del header IP (primeros 4 bits del primer byte × 4)
    let ip_header_len = ((datos[ip_start] & 0x0F) as usize) * 4;
    let transport_start = ip_start + ip_header_len;

    let (protocolo, puerto_dst) = match protocolo_num {
        6 => {
            // TCP — puerto destino en bytes 2-3 del header TCP
            if datos.len() >= transport_start + 4 {
                let puerto = ((datos[transport_start + 2] as u16) << 8)
                    | datos[transport_start + 3] as u16;
                ("TCP".to_string(), puerto.to_string())
            } else {
                ("TCP".to_string(), "-".to_string())
            }
        }
        17 => {
            // UDP — puerto destino en bytes 2-3 del header UDP
            if datos.len() >= transport_start + 4 {
                let puerto = ((datos[transport_start + 2] as u16) << 8)
                    | datos[transport_start + 3] as u16;
                ("UDP".to_string(), puerto.to_string())
            } else {
                ("UDP".to_string(), "-".to_string())
            }
        }
        1 => ("ICMP".to_string(), "-".to_string()),
        _ => ("OTRO".to_string(), "-".to_string()),
    }; 

    Some(Paquete {
        timestamp: timestamp.to_string(),
        src,
        dst,
        protocolo,
        puerto_dst,
        longitud: datos.len() as u32,
    })
}

fn main() {
    // Usamos stdout con buffer para máximo rendimiento
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    // Abrimos la interfaz eth0 para captura
    let mut cap = Capture::from_device("eth0")
        .expect("No se pudo abrir eth0")
        .promisc(true)        // modo promiscuo — captura todo el tráfico
        .snaplen(65535)       // tamaño máximo de paquete
        .open()
        .expect("No se pudo iniciar la captura");

    eprintln!("NetGuard capture_rs iniciado en eth0...");

    // Loop principal — procesa paquetes indefinidamente
    while let Ok(paquete) = cap.next_packet() {
        let datos = paquete.data;
        let timestamp = chrono::Utc::now().format("%H:%M:%S").to_string();

        if let Some(pkt) = procesar_paquete(datos, &timestamp) {
            // Serializamos a JSON y mandamos por stdout — una línea por paquete
            if let Ok(json) = serde_json::to_string(&pkt) {
                writeln!(out, "{}", json).ok();
                out.flush().ok();
            }
        }
    }
}