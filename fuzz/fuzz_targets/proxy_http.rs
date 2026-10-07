//! The HTTP proxy door (`fictionet attach --type http_proxy`), where the
//! agent is the client: the request head (`CONNECT host:port` or an
//! absolute URI), the token in `Proxy-Authorization`, and the head the
//! site's answer gets on its way back.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| fictionet_fuzz::doors::http(data));
