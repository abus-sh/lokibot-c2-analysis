use encoding::Response;
use packets::Packet;

#[macro_use] extern crate rocket;

mod encoding;
mod packets;

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[post("/controllers/user/fre.php", data = "<input>")]
async fn handle_fre_packet(input: Vec<u8>) -> Vec<u8> {
    let packet = if let Ok(packet) = Packet::try_from(input.as_slice()) {
        packet
    } else {
        println!("Unknown packet:\n{:?}", input);
        return vec![0, 1, 2];
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
    
    //  Header |num commands   |?              |opcode       |ignored        |string               |?              |opcode         |ignored        |string
    //"\x11\"3D\x02\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00hi\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00hi!\x00"
    Response::default().into()
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index, handle_fre_packet])
}
