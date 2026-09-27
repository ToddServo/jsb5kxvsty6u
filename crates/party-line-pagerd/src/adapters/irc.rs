//! IRC.
//!
//! Only a `PRIVMSG` addressed to the bot's own nickname counts. Anything said
//! in a channel is ignored even when the bot is sitting in it, so `signal` in
//! `#lobby` does nothing.
//!
//! IRC has no offline delivery: a broadcast to somebody who is not connected is
//! lost. That is a property of the protocol, not a bug here, and it is why the
//! README tells IRC-only users to add a second endpoint.
//!
//! Logging in to services happens over SASL PLAIN, before the nickname is
//! claimed. The alternative, a `NICKSERV IDENTIFY` sent after the MOTD, is too
//! late on any network that reserves nicknames: the server has already refused
//! the nick or renamed us by then. SASL PLAIN sends the password base64-encoded
//! but not encrypted, so it belongs on a TLS connection, which is the default.

use std::sync::Mutex;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use party_line_pager_core::{EndpointId, Style};
use data_encoding::BASE64;
use futures_util::StreamExt;
use irc::client::prelude::{Capability, Client, Command, Config, Response};
use irc::client::ClientStream;
use irc::proto::CapSubCommand;
use tokio::sync::mpsc;

use crate::config;
use crate::transport::{Incoming, OutMessage, Transport};

/// IRC lines are capped around 512 bytes including protocol overhead. Leave
/// generous headroom for the prefix the server prepends.
const MAX_LINE: usize = 400;

/// An `AUTHENTICATE` payload is capped at 400 base64 characters per line.
/// Longer credentials have to be split across several lines, which no account
/// password should ever need.
const MAX_SASL_PAYLOAD: usize = 400;

/// Services credentials, already resolved from the config.
struct Sasl {
    account: String,
    password: String,
}

pub struct Irc {
    config: Config,
    sasl: Option<Sasl>,
    sender: Mutex<Option<irc::client::Sender>>,
}

impl Irc {
    pub fn new(cfg: &config::Irc) -> Result<Self> {
        Ok(Self {
            config: Config {
                nickname: Some(cfg.nick.clone()),
                server: Some(cfg.server.clone()),
                port: Some(cfg.port),
                use_tls: Some(cfg.tls),
                channels: cfg.channels.clone(),
                ..Config::default()
            },
            sasl: cfg.password.as_ref().map(|password| Sasl {
                account: cfg.account().to_string(),
                password: password.clone(),
            }),
            sender: Mutex::new(None),
        })
    }
}

#[async_trait]
impl Transport for Irc {
    fn name(&self) -> &str {
        "irc"
    }

    async fn run(&self, tx: mpsc::Sender<Incoming>) -> Result<()> {
        let mut client = Client::from_config(self.config.clone())
            .await
            .context("could not connect to IRC")?;
        // Taking the stream first is not optional: it owns the outbound half,
        // so nothing we send is flushed until something polls it.
        let mut stream = client.stream()?;

        if let Some(sasl) = &self.sasl {
            authenticate(&client, &mut stream, sasl)
                .await
                .context("IRC SASL login failed")?;
        }
        client.identify().context("IRC identify failed")?;

        *self.sender.lock().unwrap() = Some(client.sender());
        // The nick we asked for and the nick we hold are not always the same:
        // services can rename us, and the server has the last word on what we
        // are called. Only messages to the nick we actually hold are ours, so
        // track it rather than trusting the config.
        let mut nick = self.config.nickname.clone().unwrap_or_default();

        while let Some(message) = stream.next().await.transpose()? {
            match &message.command {
                // The welcome line is addressed to whatever the server decided
                // to call us.
                Command::Response(Response::RPL_WELCOME, args) => {
                    if let Some(assigned) = args.first() {
                        nick = assigned.clone();
                    }
                }
                Command::NICK(new_nick)
                    if message
                        .source_nickname()
                        .is_some_and(|from| from.eq_ignore_ascii_case(&nick)) =>
                {
                    nick = new_nick.clone();
                }
                Command::PRIVMSG(target, text) => {
                    if !is_direct(target, &nick) {
                        continue;
                    }
                    let Some(from) = message.source_nickname() else {
                        continue;
                    };
                    let Ok(endpoint) = EndpointId::new("irc", from) else {
                        continue;
                    };
                    if tx
                        .send(Incoming {
                            endpoint,
                            text: text.clone(),
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                _ => {}
            }
        }

        *self.sender.lock().unwrap() = None;
        Err(anyhow!("IRC connection closed"))
    }

    async fn send(&self, address: &str, msg: &OutMessage) -> Result<()> {
        let sender = self
            .sender
            .lock()
            .unwrap()
            .clone()
            .context("IRC is not connected right now")?;

        for line in split_lines(&msg.render(Style::Plain)) {
            sender
                .send_privmsg(address, &line)
                .with_context(|| format!("IRC PRIVMSG to {address} failed"))?;
        }
        Ok(())
    }
}

/// Runs a SASL PLAIN exchange to completion, before `CAP END` lets the server
/// assign us a nickname.
///
/// Returns an error rather than carrying on unauthenticated: on a network where
/// the nick is reserved, connecting anonymously means either being refused or
/// being renamed, and both are worse than a supervised reconnect.
async fn authenticate(client: &Client, stream: &mut ClientStream, sasl: &Sasl) -> Result<()> {
    let payload = plain_credential(&sasl.account, &sasl.password)?;
    client.send_cap_req(&[Capability::Sasl])?;

    while let Some(message) = stream.next().await.transpose()? {
        match &message.command {
            Command::CAP(_, CapSubCommand::ACK, _, _) => client.send_sasl_plain()?,
            Command::CAP(_, CapSubCommand::NAK, _, _) => {
                bail!("server does not offer the SASL capability")
            }
            // The server's "go ahead, send the credential" prompt.
            Command::AUTHENTICATE(_) => client.send_sasl(&payload)?,
            Command::Response(Response::RPL_SASLSUCCESS, _) => return Ok(()),
            Command::Response(
                code @ (Response::ERR_SASLFAIL
                | Response::ERR_SASLTOOLONG
                | Response::ERR_SASLABORT
                | Response::ERR_SASLALREADY
                | Response::ERR_NICKLOCKED),
                args,
            ) => bail!("{:?}: {}", code, args.last().map_or("rejected", String::as_str)),
            _ => {}
        }
    }
    bail!("connection closed during SASL")
}

/// The SASL PLAIN credential: an empty authorization identity, the account, and
/// the password, NUL-separated and base64-encoded.
fn plain_credential(account: &str, password: &str) -> Result<String> {
    let encoded = BASE64.encode(format!("\0{account}\0{password}").as_bytes());
    if encoded.len() > MAX_SASL_PAYLOAD {
        bail!("SASL credential is too long to send on one line");
    }
    Ok(encoded)
}

/// True when a PRIVMSG target is the bot itself rather than a channel.
fn is_direct(target: &str, nick: &str) -> bool {
    !target.starts_with(['#', '&', '!', '+']) && target.eq_ignore_ascii_case(nick)
}

/// Splits a message into IRC-sized single lines.
///
/// Blank lines are dropped, because an empty PRIVMSG is a protocol error, and
/// long lines are hard-wrapped rather than silently truncated so nobody loses
/// half an onion address.
fn split_lines(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let mut rest = line;
        while !rest.is_empty() {
            let mut cut = MAX_LINE.min(rest.len());
            // Never split inside a UTF-8 character.
            while !rest.is_char_boundary(cut) {
                cut -= 1;
            }
            out.push(rest[..cut].to_string());
            rest = &rest[cut..];
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> config::Irc {
        config::Irc {
            enabled: true,
            server: "irc.example.org".into(),
            port: 6697,
            tls: true,
            nick: "party-line-pager".into(),
            account: None,
            password: None,
            channels: vec![],
        }
    }

    #[test]
    fn channel_traffic_is_not_a_direct_message() {
        assert!(!is_direct("#lobby", "party-line-pager"));
        assert!(!is_direct("&local", "party-line-pager"));
        assert!(!is_direct("+modeless", "party-line-pager"));
        assert!(!is_direct("!12345chan", "party-line-pager"));
        assert!(is_direct("party-line-pager", "party-line-pager"));
        assert!(is_direct("PARTY-LINE-PAGER", "party-line-pager"), "nicks are case insensitive");
        assert!(
            !is_direct("someone-else", "party-line-pager"),
            "a PRIVMSG aimed elsewhere is not ours"
        );
    }

    #[test]
    fn bodies_are_split_into_sendable_lines() {
        let lines = split_lines("first\n\nsecond\n");
        assert_eq!(lines, vec!["first", "second"]);
    }

    #[test]
    fn long_lines_are_wrapped_not_truncated() {
        let long = "x".repeat(1000);
        let lines = split_lines(&long);
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(|l| l.len() <= MAX_LINE));
        assert_eq!(lines.concat(), long, "nothing may be lost");
    }

    #[test]
    fn wrapping_respects_character_boundaries() {
        let body = "é".repeat(300); // two bytes each
        let lines = split_lines(&body);
        assert_eq!(lines.concat(), body);
        assert!(lines.iter().all(|l| l.len() <= MAX_LINE));
    }

    #[tokio::test]
    async fn sending_while_disconnected_is_an_error_not_a_panic() {
        let irc = Irc::new(&cfg()).unwrap();

        let err = irc
            .send("someone", &OutMessage::plain("hi"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not connected"), "{err}");
    }

    #[test]
    fn no_password_means_no_sasl_exchange() {
        assert!(Irc::new(&cfg()).unwrap().sasl.is_none());
    }

    #[test]
    fn the_account_defaults_to_the_nick() {
        let sasl = Irc::new(&config::Irc {
            password: Some("hunter2".into()),
            ..cfg()
        })
        .unwrap()
        .sasl
        .unwrap();
        assert_eq!(sasl.account, "party-line-pager");

        let sasl = Irc::new(&config::Irc {
            account: Some("bs-services".into()),
            password: Some("hunter2".into()),
            ..cfg()
        })
        .unwrap()
        .sasl
        .unwrap();
        assert_eq!(sasl.account, "bs-services");
    }

    #[test]
    fn the_password_never_reaches_the_server_password_field() {
        // Config::password is the PASS line, which is a different thing and
        // would leak the account password to networks that log it.
        let irc = Irc::new(&config::Irc {
            password: Some("hunter2".into()),
            ..cfg()
        })
        .unwrap();
        assert_eq!(irc.config.password, None);
    }

    #[test]
    fn a_plain_credential_is_nul_separated_and_base64() {
        let encoded = plain_credential("party-line-pager", "hunter2").unwrap();
        assert_eq!(
            BASE64.decode(encoded.as_bytes()).unwrap(),
            b"\0party-line-pager\0hunter2"
        );
    }

    #[test]
    fn an_oversized_credential_is_refused_rather_than_truncated() {
        let err = plain_credential("party-line-pager", &"x".repeat(400))
            .unwrap_err()
            .to_string();
        assert!(err.contains("too long"), "{err}");
    }
}
