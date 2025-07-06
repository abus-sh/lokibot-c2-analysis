use packets::Packet;

#[macro_use] extern crate rocket;

mod encoding;
mod packets;

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[post("/controllers/user/fre.php", data = "<input>")]
async fn handle_fre_packet(input: Vec<u8>) -> &'static str {
    let packet = if let Ok(packet) = Packet::try_from(input.as_slice()) {
        packet
    } else {
        println!("Unknown packet:\n{:?}", input);
        return "UNKNOWN PACKET";
    };

    match packet {
        Packet::Beacon(packet) => {
            println!("Received a beacon packet:\n{}", packet);
        },
        Packet::Information(packet) => {
            println!("Receivied an information packet:\n{}", packet);
        },
        #[allow(unreachable_patterns)]
        other => {
            println!("Received a packet:\n{:?}", other);
        },
    }

    // First 4 bytes as a LE u32 must be greater than 8

    // Before loop
    //       v
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index, handle_fre_packet])
}
