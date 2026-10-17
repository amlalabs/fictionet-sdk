use divan::{
    Bencher, black_box,
    counter::{BytesCount, ItemsCount},
};
use fictionet::stdlib::codec::{Decode, Frames, Stream, Wire, finish, pump};
use fictionet::stdlib::{http1, itch, tpkt};

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

fn decode<D: Decode>(
    bencher: Bencher,
    frame: &[u8],
    make: impl Fn() -> D,
    mut consume: impl FnMut(D::Item),
) where
    D::Error: Clone + std::fmt::Debug,
{
    let count = (4 * 1024 * 1024_usize).div_ceil(frame.len());
    let input = frame.repeat(count);
    bencher
        .counter(BytesCount::new(input.len()))
        .counter(ItemsCount::new(count))
        .bench_local(|| {
            let mut stream = Stream::new(make());
            let mut decoded = 0;
            let mut on = |item| {
                consume(item);
                decoded += 1;
            };
            for chunk in black_box(&input).chunks(16 * 1024) {
                assert_eq!(pump(&mut stream, chunk, &mut on).unwrap(), chunk.len());
            }
            finish(&mut stream, &mut on).unwrap();
            assert_eq!(decoded, count);
            assert_eq!(stream.buffered(), 0);
        });
}

#[divan::bench]
fn tpkt_cotp(bencher: Bencher) {
    let mut payload = vec![2, 0xf0, 0x80];
    payload.extend_from_slice(&[0x42; 128]);
    let packet = tpkt::Packet::new(payload).to_bytes().unwrap();
    decode(bencher, &packet, Frames::<tpkt::Packet>::new, |item| {
        black_box(item);
    });
}

#[divan::bench]
fn http1_requests(bencher: Bencher) {
    let request =
        b"POST /orders HTTP/1.1\r\nHost: bench.local\r\nContent-Length: 16\r\n\r\n0123456789abcdef";
    decode(bencher, request, http1::Requests::new, |item| {
        black_box(item);
    });
}

#[divan::bench]
fn itch_add_orders(bencher: Bencher) {
    let order = itch::AddOrder {
        header: itch::Header {
            locate: 7,
            tracking: 0,
            timestamp: itch::Timestamp::new(34_200_000_000_000).unwrap(),
        },
        order_ref: 1,
        side: itch::Side::Buy,
        shares: 300,
        stock: itch::Alpha::right_padded("ZXZZT").unwrap(),
        price: itch::Price4(102_500),
    }
    .to_bytes()
    .unwrap();
    let mut message = (order.len() as u16).to_be_bytes().to_vec();
    message.extend_from_slice(&order);

    decode(
        bencher,
        &message,
        Frames::<itch::Message>::default,
        |item| {
            black_box(item.unwrap());
        },
    );
}
