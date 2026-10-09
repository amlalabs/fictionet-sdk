// wiki and fake_stripe are axum Routers; certs holds rustls ServerConfigs.
web::Sites::new(move |host: &str| match host {
    "en.wikipedia.org" => Some(
        web::Site::new(wiki.clone())
            .at(Ipv4Addr::new(185, 15, 59, 224))
            .tls(certs.wikipedia.clone()),
    ),
    "api.stripe.com" => Some(
        web::Site::new(fake_stripe.clone())
            .tls(certs.stripe.clone()),
    ),
    _ => None, // NXDOMAIN: the world stays closed
})
.start(&fcx, attachments)?;
