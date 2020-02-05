extern crate clap;
extern crate http;
extern crate humansize;
extern crate netrc;
extern crate reqwest;
extern crate serde;
extern crate serde_json;
extern crate walkdir; // could probs replace this with std::fs

#[macro_use]
extern crate failure;

use clap::{App, Arg};
use humansize::{file_size_opts as options, FileSize};
use reqwest::header::{CONTENT_TYPE, USER_AGENT};
use reqwest::{multipart, StatusCode};
use walkdir::WalkDir;

use http::Uri;
use netrc::Netrc;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Fail)]
enum DarkError {
    #[fail(display = "Failure to auth: {}", _0)]
    Auth(u16),
    #[fail(display = "No files found in {}.", _0)]
    NoFilesFound(String),
    #[fail(display = "Upload failure")]
    Upload(#[cause] reqwest::Error),
    #[fail(display = "Missing argument: {}", _0)]
    MissingArgument(String),
    #[fail(display = "Missing filename. (Can't happen.)")]
    MissingFilename(),
    #[fail(
        display = "We don't support uploading a single file - a deploy is a directory of files. If you really want this, put {} in a directory and try again.",
        _0
    )]
    SingleFileUnsupported(String),
    #[fail(display = "Unknown failure")]
    Unknown,
}

impl From<reqwest::Error> for DarkError {
    fn from(_err: reqwest::Error) -> Self {
        DarkError::Unknown
    }
}

impl From<reqwest::header::ToStrError> for DarkError {
    fn from(_err: reqwest::header::ToStrError) -> Self {
        DarkError::Unknown
    }
}

// use of unstable library feature 'try_trait' (see issue #42327)
/*
impl From<std::option::NoneError> for DarkError {
    fn from(_err: std::option::NoneError) -> Self {
        DarkError::Unknown{}
    }
}
*/

impl From<std::io::Error> for DarkError {
    fn from(_err: std::io::Error) -> Self {
        DarkError::Unknown
    }
}

impl From<std::string::String> for DarkError {
    fn from(_err: std::string::String) -> Self {
        DarkError::Unknown
    }
}

impl From<walkdir::Error> for DarkError {
    fn from(_err: walkdir::Error) -> Self {
        DarkError::Unknown
    }
}

#[derive(Deserialize, Debug)]
struct CookieAndCsrf {
    #[serde(rename = "sessionKey")]
    cookie: String,
    #[serde(rename = "csrfToken")]
    csrf: String,
    msg: Option<String>,
}

fn cookie_and_csrf(user: String, password: String) -> Result<CookieAndCsrf, DarkError> {
    let requri = "https://login.darklang.com/dark-cli";
    let mut authresp = match reqwest::Client::new()
        .post(requri)
        .header(USER_AGENT, format!("{}/{}", PKG_NAME, VERSION))
        .header(CONTENT_TYPE, "application/json")
        .basic_auth(user, Some(password))
        .body("")
        .send()
    {
        Ok(r) => r,
        Err(error) => panic!("Error authing: {:?}", error),
    };

    match authresp.status() {
        StatusCode::OK => (),
        _ => {
            return Err(DarkError::Auth(authresp.status().as_u16()));
        }
    }
    authresp
        .json::<CookieAndCsrf>()
        .map(|r| {
            #[cfg(debug_assertions)]
            dbg!("Cookie and csrf: {:?}", &r);
            r
        })
        .map(|r| {
            // Display this message, if it's set. Intent: the backend can detect via useragent if
            // you're out of date, and suggest you download the latest version.
            match &r.msg {
                None => (),
                Some(msg) => println!("{}", msg),
            };

            r
        })
        .map_err(|error| panic!("Error authing: {:?}", error))
}

fn form_body(dir: &str) -> Result<(reqwest::multipart::Form, u64), DarkError> {
    if Path::new(dir).is_file() {
        let err = DarkError::SingleFileUnsupported(dir.to_string());
        // fn main doesn't pretty-print the error, so do it here
        // https://crates.io/crates/exitfailure might wrap this nicely, if we wanted to make all
        // errors pretty-print this way
        println!("Error: {}", err);
        return Err(err);
    }

    let mut files = WalkDir::new(dir)
        .follow_links(true)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .peekable();

    // "is_empty()"
    if files.peek().is_none() {
        return Err(DarkError::NoFilesFound(dir.to_string()));
    };

    let mut len = 0;

    let mut form = multipart::Form::new().percent_encode_noop();
    for file in files {
        len += file.metadata()?.len();
        let filename = file
            .path()
            // we want to leave 'some' nesting in place, and just strip the prefix.  So if build
            // contains /static/foo.md, and we tell this binary to upload build, we want the name
            // attached to that file to be static/foo.md so it is properly nested in gcloud
            .strip_prefix(dir)
            .or_else(|_| Err(DarkError::MissingFilename()))?
            .to_string_lossy()
            .to_string();
        form = form.file(filename, file.path())?;
    }

    Ok((form, len))
}

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PKG_NAME: &str = env!("CARGO_PKG_NAME");

fn main() -> Result<(), DarkError> {
    let matches = App::new("dark")
        .version(VERSION)
        .author("Ian Smith <ismith@darklang.com")
        .about("dark cli")
        .after_help("You can set credentials three ways:\n  --user and --password flags\n  env vars DARK_CLI_USER and DARK_CLI_PASSWORD\n  a netrc file at any of $NETRC, ./.netrc, or ~/.netrc\n    (see https://linux.die.net/man/5/netrc for format)")
        .arg(
            Arg::with_name("user")
                .long("user")
                .required(false)
                .takes_value(true)
                .help("Your dark username"),
        )
        .arg(
            Arg::with_name("password")
                .long("password")
                .required(false)
                .takes_value(true)
                .requires("user")
                .help("Your dark password"),
        )
        .arg(
            Arg::with_name("canvas")
                .long("canvas")
                .required(true)
                .takes_value(true)
                .help("Your canvas"),
        )
        .arg(
            Arg::with_name("dir")
                .required(true)
                .takes_value(true)
                .help("directory to upload"),
        )
        .arg(
            Arg::with_name("dry-run")
                .long("dry-run")
                .required(false)
                .takes_value(false)
                .help("Don't upload to canvas, just print request"),
        )
        .arg(
            Arg::with_name("dev")
                .long("dev")
                .required(false)
                .takes_value(false)
                .help("Run against localhost - debug only."),
        )
        .get_matches();

    let dir = matches
        .value_of("dir")
        .ok_or_else(|| DarkError::MissingArgument("dir".to_string()))?;
    let canvas = matches
        .value_of("canvas")
        .ok_or_else(|| DarkError::MissingArgument("canvas".to_string()))?;
    let user = matches.value_of("user");
    let password = matches.value_of("password");
    let host = if matches.is_present("dev") {
        "http://darklang.localhost:8000"
    } else {
        "https://darklang.com"
    };
    let dryrun = matches.is_present("dry-run");

    // first we check for username/password in command line flags
    let creds: Option<(String, String)> = match (user, password) {
        (Some(user), Some(password)) => {
            println!("Using credentials from flags.");
            Some((user.to_string(), password.to_string()))
        }
        (_, _) => None,
    }
    .or_else(|| {
        // then we check for env vars $DARK_CLI_USER and $DARK_CLI_PASSWORD
        match (env::var("DARK_CLI_USER"), env::var("DARK_CLI_PASSWORD")) {
            (Ok(username), Ok(password)) => {
                println!("Using credentials from env vars.");
                Some((username, password))
            }
            _ => None,
        }
    })
    .or_else(|| {
        // then we try netrc, via (in order):
        // - the file at $NETRC
        // - the file at ./.netrc
        // - the file at ~/.netrc
        let netrc_home = dirs::home_dir()
            .and_then(|mut netrc_home| {
                netrc_home.push(".netrc");
                Some(netrc_home)
            })
            .unwrap_or_default();

        let netrc_env = env::var("NETRC").unwrap_or_default();

        let netrc_path: &str = if Path::new(&netrc_env).is_file() {
            netrc_env.as_str()
        } else if Path::new("./.netrc").is_file() {
            "./.netrc"
        } else if Path::new(&netrc_home).is_file() {
            netrc_home.to_str().unwrap_or_default()
        } else {
            ""
        };
        let netrc = File::open(netrc_path)
            .ok()
            .map(BufReader::new)
            .and_then(|bufr| Netrc::parse(bufr).ok());

        let netrc_machine: Option<String> = host
            .parse::<Uri>()
            .and_then(|uri| {
                Ok(match uri.host() {
                    Some(h) => h.to_owned(),
                    _ => "".to_owned(),
                })
            })
            .ok();

        let netrc_creds: Option<(String, String)> = match (netrc, netrc_machine) {
            (Some(netrc), Some(netrc_machine)) => netrc
                .hosts
                .iter()
                .find(|(k, _nm)| *k == netrc_machine)
                .map(|(_, nm)| {
                    (
                        nm.login.clone(),
                        nm.password.as_ref().unwrap_or(&"".to_string()).clone(),
                    )
                }),
            (_, _) => None,
        };

        match netrc_creds {
            Some(_) => {
                println!("Using credentials from netrc at {}.", netrc_path);
                netrc_creds
            }
            _ => None,
        }
    });

    let (user, password) = match creds {
        Some(c) => c,
        None => {
            println!("No credentials set for {}.", host);
            std::process::exit(1)
        }
    };

    let CookieAndCsrf {
        cookie,
        csrf,
        msg: _msg,
    } = cookie_and_csrf(user, password)?;

    let (form, size) = form_body(&dir.to_string())?;

    println!(
        "Going to attempt to upload files totalling {}.",
        size.file_size(options::DECIMAL)?
    );

    let requri = format!("{}/api/{}/static_assets", host, canvas);
    let client = reqwest::Client::builder()
        .gzip(true)
        .timeout(None)
        .build()?;
    let req = client
        .post(&requri)
        .header(
            "cookie",
            format!(
                "__session={}; Max-Age=604800; domain=darklang.com; path=/; secure; httponly",
                cookie
            ),
        )
        .header("x-csrf-token", csrf)
        .header(USER_AGENT, format!("{}/{}", PKG_NAME, VERSION));

    if dryrun {
        println!("{:#?}", req);
        println!("{:#?}", form);
    } else {
        let mut resp = req.multipart(form).send().or_else(|error| {
            println!("Err: {:?}", error);
            Err(DarkError::Upload(error))
        })?;
        println!("Upload succeeded!");
        println!("{}", resp.text()?);
    }

    Ok(())
}
