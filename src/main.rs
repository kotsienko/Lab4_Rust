use std::thread;
use std::net::{TcpListener, TcpStream, Shutdown};
use std::net::SocketAddr;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::io::{Read, Write};
use std::io;
use std::str;
use rand;



fn get_session_key() -> String 
{
    // generate 10 char random string
	let mut result: String = "".to_string();
	for _ in 0..10 
    { 
        result += &(((rand::random::<f64>()*9.0 + 1.0) as i64).to_string()); 
    }
	return result;
}


fn get_hash_str() -> String 
{
    // calculate initial hash string
	let mut li : String = "".to_string();
	for _ in 0..5 
    { 
        li += &(((rand::random::<f64>()*6.0 + 1.0) as i64).to_string()); 
    }
	return li;
}



fn next_session_key(skey: &String, hashstr: &String) -> String 
{
    let leng = hashstr.len();
    let mut result : i64 = 0;
    for idx in 0..leng 
    {
        let i = &hashstr[idx..idx+1];
        let j = &i.parse::<i64>().unwrap();
        let fres = calc_hash(skey, j);



        //println!("{}", i);
        result += fres.parse::<i64>().unwrap();
        //println!("{}", result);
    }
    let res = "0000000000".to_string() + &result.to_string()[0..];
    let fres = &res[res.len()-10..];
    return fres.to_string()
}


fn calc_hash(session_key: &String, val :&i64) -> String 
{
    let session_key : &String = &*session_key;
    // calculate hash
    let mut result : String = "".to_string();
    if *val == 1 
    {
        let res1 = (&session_key[0..5].parse::<i64>().unwrap() % 97).to_string();
        let res2 = "00".to_string() + &res1;
        return res2[res2.len()-2..].to_string();
    }

    else if *val == 2 
    {
        for i in 1..session_key.len() 
        {
            result = result + &session_key[session_key.len()-i..session_key.len()-i+1];
        }

        return (result + &session_key[0..1]).to_string()
    }
    else if *val == 3 
    {
        return session_key[session_key.len()-5..].to_string() + &session_key[0..5]
    }
    else if *val == 4 
    {
        let mut num  = 0;
        for i in 1..9 
        { 
            num += (&session_key[i..i+1]).parse::<i32>().unwrap() + 41; 
        }
        return num.to_string()
    }

    else if *val == 5 
    {
        let mut num  = 0;
        for i in 0..session_key.len() 
        {
            let char_vec: Vec<char> = session_key[i..i+1].chars().collect();
            let cha_ord = char_vec[0] as u32;
            let cha =  std::char::from_u32(cha_ord ^ 43).unwrap();
            if !cha.is_digit(10) 
            {
                num += cha as u32;
            } 
            else 
            { 
                num += cha.to_digit(10).unwrap(); 
            }

        }

        return num.to_string()
    }
    else 
    { 
        return (session_key.parse::<i64>().unwrap() + val).to_string(); 
    }
}





fn handle_client(mut stream: TcpStream) 
{
    let mut count_serv = 0;
    let max_count_serv = 10;

    let mut hash = [0 as u8; 5];
    let mut key = [0 as u8; 10];
    let mut msg = [0 as u8; 50];

    match stream.read(&mut hash) 
    {
        Ok(_) => 
        {

            match stream.read(&mut key) 
            {
                Ok(_) => 
                {

                    let hash_ = str::from_utf8(&hash).unwrap().to_string();
                    let  mut key_ = str::from_utf8(&key).unwrap().to_string();


                    while count_serv < max_count_serv 
                    {
                        key_ = next_session_key(&key_,&hash_);
                        match stream.read(&mut msg) 
                        {
                            Ok(_) => 
                            {
                                let unwmsg = str::from_utf8(&msg).unwrap().to_string();
                                let split_msg : Vec<&str> = unwmsg.split('\n').collect();
                                println!();
                                println!("received msg: {}", split_msg[count_serv]);
                                stream.write(key_.as_bytes()).unwrap();
                                println!("key {} sent", key_);

                            },
                            Err(_) => 
                            {
                                println!("An error occurred, terminating connection with {}",
                                         stream.peer_addr().unwrap());
                                stream.shutdown(Shutdown::Both).unwrap();
                                break;
                            }
                        }
                        count_serv+=1;
                    }
                    println!("Connection closed");
                    stream.shutdown(Shutdown::Both).unwrap();

                },
                Err(_) => 
                {
                    println!( "Key error {}", stream.peer_addr().unwrap() );
                    stream.shutdown(Shutdown::Both).unwrap();
                }
            }

        },
        Err(_) => 
        {
            println!( "Hash error {}", stream.peer_addr().unwrap() );
            stream.shutdown(Shutdown::Both).unwrap();
        }
    }



}



fn run_server(port: String) 
{
    println!("Server mode");
    println!("Read max count of connections:");
    let mut n = 0;

    let mut n_max = String::new();
    io::stdin()
        .read_line(&mut n_max)
        .expect("Failed to read line");


    let port_u16 : u16 = port[0..port.len()-1].parse().unwrap();
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port_u16);

    let listener = TcpListener::bind(socket).unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port {}", port_u16);

    for stream in listener.incoming() 
    {
        n += 1;
        match stream 
        {
            Ok(stream) => 
            {
                if n < n_max[0..n_max.len()-1].parse::<i32>().unwrap() 
                {
                    println!("New connection: {}. {}/{}", stream.peer_addr().unwrap(), n, n_max);
                    thread::spawn(move || 
                    {
                        // connection succeeded
                        handle_client(stream)
                    });
                } 
                else 
                {
                    println!("max count of connections");
                }
            }
            Err(e) => 
            {
            // connection failed 
            println!("Error: {}", e);
            }
        }
        n-=1;
    }
    // close the socket server
    drop(listener);
}




fn run_client(ip_port: String) 
{
    println!("Client mode");

    let split_ip_port : Vec<&str> = ip_port.split(':').collect();
    let split_ip : Vec<&str> = split_ip_port[0].split('.').collect();
    let port = split_ip_port[1];

    let ip1  : u8 = split_ip[0][0..split_ip[0].len()].parse().unwrap();
    let ip2  : u8 = split_ip[1][0..split_ip[1].len()].parse().unwrap();
    let ip3  : u8 = split_ip[2][0..split_ip[2].len()].parse().unwrap();
    let ip4  : u8 = split_ip[3][0..split_ip[3].len()].parse().unwrap();
    let port : u16 = port[0..port.len()-1].parse().unwrap();

    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip1, ip2, ip3, ip4)), port);

    match TcpStream::connect(socket) 
    {
        Ok(mut stream) => 
        {
            println!("Successfully connected to server in port 3333");

            //  127.0.0.1:3333

            let mut key = get_session_key();
            let hash = get_hash_str();

            println!("Read your msg:");
            let mut msg = String::new();
            io::stdin()
                .read_line(&mut msg)
                .expect("Failed to read line");

            stream.write(hash.as_bytes()).unwrap();
            stream.write(key.as_bytes()).unwrap();
            stream.write(msg.as_bytes()).unwrap();
            println!("first msg sent");

            let mut new_key = next_session_key(&key, &hash);

            let mut count = 1;
            let max_count = 10;

            while count < max_count 
            {
                let mut res_key = [0 as u8; 10]; // using 10 byte buffer
                match stream.read(&mut res_key) 
                {
                    Ok(_) => 
                    {
                        let inpkey = str::from_utf8(&res_key).unwrap();
                        println!();
                        println!("received key: {}", inpkey);
                        println!("client key: {}", new_key);

                        if inpkey.to_string()[0..10] == new_key.to_string()[0..10] 
                        {
                            println!("Correct reply");

                            key = new_key.to_string();

                            println!("Read your msg:");
                            io::stdin()
                                .read_line(&mut msg)
                                .expect("Failed to read line");

                            stream.write(msg.as_bytes()).unwrap();
                            println!("msg sent");
                        }
                        else 
                        { 
                            println!("Incorrect key: {}", inpkey); break; 
                        }
                    },
                    Err(e) => 
                    { 
                        println!("Failed to receive data: {}", e); break; 
                    }
                }
                count+=1;
                new_key = next_session_key(&key, &hash);
            }
        },
        Err(e) => 
        {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
}



fn main() 
{
    println!("Read [port] or [ip:port]");
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    if input.find(':') == None 
    { 
        run_server(input) 
    }
    else 
    { 
        run_client(input) 
    };
}