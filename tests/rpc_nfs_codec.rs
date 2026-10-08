//! TCP record marking through RPC, NFS, and portmap, in both directions.

use fictionet::stdlib::codec::{
    self, Assembled, Decode, Stream, Wire, finish, pump,
};
use fictionet::stdlib::test_support::contract;

use fictionet::stdlib::test_support::chunks;
use fictionet::stdlib::{nfs, onc_rpc, portmap};
use onc_rpc::{Accept, Body, Message, Reply};

const RECORD_LIMIT: usize = 4096;

#[test]
fn authentication_composes_with_xdr_and_refuses_changed_values() {
    for auth in [
        onc_rpc::Auth::None,
        onc_rpc::Auth::Other {
            flavor: 9,
            body: vec![1, 2, 3],
        },
    ] {
        let mut writer = onc_rpc::Writer::new();
        writer.uint(42);
        auth.write(&mut writer);
        writer.uint(7);
        let bytes = writer.finish().unwrap();
        let mut reader = onc_rpc::Reader::new(&bytes);
        assert_eq!(reader.uint(), Ok(42));
        assert_eq!(onc_rpc::Auth::read(&mut reader), Ok(auth));
        assert_eq!(reader.uint(), Ok(7));
        assert_eq!(reader.finish(), Ok(()));
    }
    let mut writer = onc_rpc::Writer::new();
    writer.uint(42);
    let prefix = writer.as_bytes().to_vec();
    onc_rpc::Auth::Other {
        flavor: onc_rpc::flavor::NONE,
        body: Vec::new(),
    }
    .write(&mut writer);
    assert_eq!(writer.as_bytes(), prefix);
    assert_eq!(writer.finish(), Err(onc_rpc::Error::Unwritable));
}

#[derive(Debug, PartialEq, Eq)]
enum Request {
    Nfs(nfs::Request),
    Portmap(portmap::Request),
}

fn request_stream() -> impl Decode<
    Item = Result<(Message, Request), onc_rpc::Error>,
    Error = codec::AssembleError<onc_rpc::Error>,
> {
    onc_rpc::messages(RECORD_LIMIT).map(|message| {
        let message = message?;
        let Body::Call(call) = &message.body else {
            return Err(onc_rpc::Error::Discriminant(1));
        };
        assert_eq!(call.rpc_version, onc_rpc::RPC_VERSION);
        let request = match (call.program, call.version) {
            (nfs::NFS_PROGRAM, nfs::NFS_VERSION) => {
                Request::Nfs(nfs::Request::read(call.procedure, &call.args)?)
            }
            (onc_rpc::PMAP_PROGRAM, version) => {
                let request = portmap::Request::read(version, call.procedure, &call.args).unwrap();
                assert_eq!(portmap::Request::from_call(call), Ok(request.clone()));
                Request::Portmap(request)
            }
            _ => return Err(onc_rpc::Error::Discriminant(call.program)),
        };
        Ok((message, request))
    })
}

#[test]
fn tcp_requests_and_replies() -> Result<(), Box<dyn core::error::Error>> {
    let lookup = nfs::Request::Lookup(nfs::DirOp {
        dir: nfs::FileHandle(vec![1, 2, 3]),
        name: b"notes.txt".to_vec(),
    });
    let pmap = portmap::Request::Pmap(portmap::PmapRequest::GetPort(portmap::Mapping {
        program: nfs::NFS_PROGRAM,
        version: nfs::NFS_VERSION,
        protocol: portmap::IPPROTO_TCP,
        port: 0,
    }));
    let rpcb = portmap::Request::Rpcb {
        version: 4,
        request: portmap::RpcbRequest::GetAddr(portmap::Rpcb {
            program: nfs::NFS_PROGRAM,
            version: nfs::NFS_VERSION,
            netid: "tcp".into(),
            addr: String::new(),
            owner: String::new(),
        }),
    };
    let calls = [lookup.call(101)?, pmap.call(102)?, rpcb.call(103)?];
    let mut tcp = Vec::new();
    for (call, fragment_len) in calls.iter().zip([1, 7, 13]) {
        let payload = <Message as Wire>::to_bytes(call)?;
        // Empty nonfinal fragments are legal even before nonempty data.
        tcp.extend_from_slice(&0u32.to_be_bytes());
        tcp.extend(onc_rpc::encode_fragments(&payload, fragment_len)?);
    }
    contract::check_decode(request_stream, &tcp);
    contract::check_decode_with_held_limit(|| onc_rpc::records(RECORD_LIMIT), &tcp, RECORD_LIMIT);

    // Run the layers separately as an oracle for the composed decoder.
    let mut fragments = Stream::new(onc_rpc::Fragments::with_limit(RECORD_LIMIT));
    let mut joined = Vec::new();
    let mut separate = Vec::new();
    for part in chunks(&tcp, &[1]) {
        pump(&mut fragments, part, |fragment| {
            assert!(joined.len() + fragment.data.len() <= RECORD_LIMIT);
            joined.extend_from_slice(&fragment.data);
            if fragment.last {
                separate.push(Message::parse(&joined).unwrap());
                joined.clear();
            }
        })?;
    }
    finish(&mut fragments, |_| panic!("all fragments drained"))?;
    assert!(joined.is_empty());
    assert_eq!(separate, calls);

    for pattern in [&[][..], &[1][..], &[3, 1, 37][..], &[64][..]] {
        let mut stream = Stream::new(request_stream());
        let mut requests = Vec::new();
        for part in chunks(&tcp, pattern) {
            assert_eq!(pump(&mut stream, part, |r| requests.push(r))?, part.len());
            assert!(stream.buffered() <= RECORD_LIMIT + onc_rpc::RECORD_MARK_LEN);
            assert!(stream.held() <= RECORD_LIMIT);
        }
        finish(&mut stream, |r| requests.push(r))?;
        let requests = requests.into_iter().collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            requests.iter().map(|(m, _)| m).collect::<Vec<_>>(),
            calls.iter().collect::<Vec<_>>()
        );
        assert_eq!(
            requests.iter().map(|(_, r)| r).collect::<Vec<_>>(),
            [
                &Request::Nfs(lookup.clone()),
                &Request::Portmap(pmap.clone()),
                &Request::Portmap(rpcb.clone())
            ]
        );

        let lookup_result = nfs::Response::Lookup(Ok(nfs::LookupOk {
            object: nfs::FileHandle(vec![4, 5, 6]),
            object_attributes: None,
            dir_attributes: None,
        }));
        let mut replies = Vec::new();
        for (message, request) in requests {
            let reply = match request {
                Request::Nfs(_) => lookup_result.reply()?,
                Request::Portmap(portmap::Request::Pmap(_)) => {
                    Reply::success(portmap::PmapResult::Port(u32::from(nfs::PORT)).to_bytes()?)
                }
                Request::Portmap(portmap::Request::Rpcb { .. }) => {
                    Reply::success(portmap::RpcbResult::Addr("10.0.0.5.8.1".into()).to_bytes()?)
                }
            };
            let reply = message.reply(reply);
            let mut payload = Vec::new();
            Wire::write(&reply, &mut payload)?;
            contract::check_wire::<Message>(&payload);
            onc_rpc::Record(payload).write(&mut replies)?;
        }

        let mut incoming = Stream::new(onc_rpc::messages(RECORD_LIMIT));
        let mut parsed_replies = Vec::new();
        for part in chunks(&replies, &[1]) {
            pump(&mut incoming, part, |m| parsed_replies.push(m))?;
        }
        finish(&mut incoming, |m| parsed_replies.push(m))?;
        assert_eq!(parsed_replies.len(), calls.len());
        for reply in parsed_replies {
            let Message { xid, body } = reply?;
            let Body::Reply(Reply::Accepted {
                status: Accept::Success(results),
                ..
            }) = body
            else {
                panic!("expected a successful RPC reply");
            };
            // A client's outstanding calls supply the response procedure.
            let call = calls.iter().find(|call| call.xid == xid).unwrap();
            let Body::Call(call) = &call.body else {
                panic!("expected a call")
            };
            match call.program {
                nfs::NFS_PROGRAM => {
                    assert_eq!(
                        nfs::Response::parse(call.procedure, &results),
                        Ok(lookup_result.clone())
                    )
                }
                _ if call.version == 2 => assert_eq!(
                    portmap::PmapResult::parse(call.procedure, &results),
                    Ok(portmap::PmapResult::Port(2049))
                ),
                _ => assert_eq!(
                    portmap::RpcbResult::parse(call.procedure, &results),
                    Ok(portmap::RpcbResult::Addr("10.0.0.5.8.1".into()))
                ),
            }
        }
    }
    Ok(())
}

#[test]
fn bad_rpc_record_does_not_hide_the_next_request() -> Result<(), Box<dyn core::error::Error>> {
    let good = nfs::Request::Null.call(7)?;
    let mut tcp = onc_rpc::Record(vec![0, 1, 2]).to_bytes()?;
    tcp.extend(onc_rpc::encode_fragments(
        &<Message as Wire>::to_bytes(&good)?,
        1,
    )?);
    let mut stream = Stream::new(request_stream());
    let mut items = Vec::new();
    for byte in &tcp {
        pump(&mut stream, core::slice::from_ref(byte), |item| {
            items.push(item)
        })?;
    }
    finish(&mut stream, |item| items.push(item))?;
    assert_eq!(
        items,
        [
            Err(onc_rpc::Error::Short),
            Ok((good, Request::Nfs(nfs::Request::Null)))
        ]
    );
    assert!(stream.failed().is_none());

    // The assembler itself accepts an empty record; RPC parsing refuses it.
    let mut records = Stream::new(onc_rpc::records(0));
    assert_eq!(records.push(&onc_rpc::LAST_FRAGMENT.to_be_bytes()), 4);
    assert_eq!(records.next(), Some(Ok(Assembled::Message(Vec::new()))));
    Ok(())
}
