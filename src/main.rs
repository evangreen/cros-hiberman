// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Coordinates suspend-to-disk activities

use hiberman::{self, error};
use hiberman::{HibernateOptions, ResumeOptions};
use sys_util::syslog;

fn print_usage(message: &str, error: bool) {
    if error {
        eprintln!("{}", message)
    } else {
        println!("{}", message);
    }
}

fn init_logging() -> std::result::Result<(), ()> {
    if let Err(e) = syslog::init() {
        eprintln!("failed to initialize syslog: {}", e);
        return Err(());
    }

    if let Err(e) = hiberman::hiberlog::init() {
        eprintln!("failed to initialize hiberlog: {}", e);
        return Err(());
    }

    Ok(())
}

fn cookie_usage(error: bool) {
    let usage_msg = r#"Usage: hiberman cookie <path> [options]
Get or set the hibernate cookie info. With no options, gets the
current status of the hibernate cookie. Returns 0 if the cookie
indicates a valid hibernate image, or 1 if no image.

Option are:
    --set -- Set the cookie to indicate a valid hibernate image.
    --clear -- Clear the cookie to indicate no valid hibernate image.
    --verbose -- Print more, including for "get" operations the status
      of the cookie.
    --help -- Print this help text.
"#;

    print_usage(usage_msg, error);
}

fn hiberman_cookie(args: &mut std::env::Args) -> std::result::Result<(), ()> {
    // Note: Don't fire up logging immediately in this command as it's called
    // during very early init, before syslog is ready.
    let mut clear_cookie = false;
    let mut set_cookie = false;
    let mut path = None;
    let mut verbose = false;
    for arg in args {
        match arg.as_ref() {
            "--verbose" => verbose = true,
            "--set" => set_cookie = true,
            "--clear" => clear_cookie = true,
            "--help" => cookie_usage(false),
            _ => {
                path = Some(arg);
            }
        }
    }

    // In verbose mode, or for anything other than "get", fire up logging.
    if verbose || set_cookie || clear_cookie {
        init_logging()?;
    }

    if set_cookie || clear_cookie {
        match hiberman::cookie::set_hibernate_cookie(path.as_ref(), set_cookie) {
            Err(e) => {
                error!("Failed to write hibernate cookie: {}", e);
                Err(())
            }
            Ok(()) => Ok(()),
        }
    } else {
        match hiberman::cookie::get_hibernate_cookie(path.as_ref()) {
            Err(e) => {
                error!("Failed to get hibernate cookie: {}", e);
                Err(())
            }
            Ok(is_set) => {
                if verbose {
                    match is_set {
                        true => println!("Hibernate cookie is set"),
                        false => println!("Hibernate cookie is not set"),
                    }
                }

                match is_set {
                    true => Ok(()),
                    false => Err(()),
                }
            }
        }
    }
}

fn cat_usage(error: bool) {
    let usage_msg = r#"Usage: hiberman cat <file> [file...]
Print a disk file to stdout. Since disk files write to blocks
underneath the file system, they cannot be read reliably by normal
file system accesses.

Option are:
    --log -- This file is a log file (stop on first nul byte).
    --help -- Print this help text.
"#;

    print_usage(usage_msg, error);
}

fn hiberman_cat(args: &mut std::env::Args) -> std::result::Result<(), ()> {
    init_logging()?;
    let mut log = false;
    let mut result = Ok(());
    for arg in args {
        match arg.as_ref() {
            "--log" => log = true,
            "--help" => cat_usage(false),
            _ => {
                if let Err(e) = hiberman::cat_disk_file(&arg, log) {
                    error!("Failed to cat {}: {}", &arg, e);
                    result = Err(())
                }
            }
        }
    }

    result
}

fn hibernate_usage(error: bool) {
    let usage_msg = r#"Usage: hiberman hibernate [options]
Hibernate the system now.

Options are:
    --dry-run -- Create the hibernate image, but then exit rather than
        shutting down. Note that it's not safe to resume to this image
        as the file systems will likely be modified after the process
        exits. Use this only for testing the hibernate sequence, in
        tandem with resume --dry-run.
    --unencrypted -- Do not encrypt the hibernate image. Useful
        only in measurement and debug scenarios.
    --help -- Print this help text.
"#;

    print_usage(usage_msg, error);
}

fn hiberman_hibernate(args: &mut std::env::Args) -> std::result::Result<(), ()> {
    init_logging()?;
    let mut options = HibernateOptions::new();
    for arg in args {
        match arg.as_ref() {
            "--help" | "-h" => {
                hibernate_usage(false);
                return Ok(());
            }

            "--dry-run" | "-n" => {
                options.dry_run = true;
            }

            "--unencrypted" => {
                options.unencrypted = true;
            }

            _ => {
                error!("invalid argument: {}", arg);
                return Err(());
            }
        }
    }

    if let Err(e) = hiberman::hibernate(&options) {
        error!("Failed to hibernate: {}", e);
        return Err(());
    }

    Ok(())
}

fn resume_usage(error: bool) {
    let usage_msg = r#"Usage: hiberman resume [options]
Resume the system now. On success, does not return, but jumps back into the
resumed image.

Options are:
    -n, --dry-run -- Load the resume image, but don't actually jump into it.
    --unencrypted -- Allow unencrypted resume images. Useful only for
        measurement and debug scenarios.
    --help -- Print this help text.
"#;

    print_usage(usage_msg, error);
}

fn hiberman_resume(args: &mut std::env::Args) -> std::result::Result<(), ()> {
    init_logging()?;
    let mut options = ResumeOptions::new();
    for arg in args {
        match arg.as_ref() {
            "--help" | "-h" => {
                resume_usage(false);
                return Ok(());
            }

            "-n" | "--dry-run" => {
                options.dry_run = true;
            }

            "--unencrypted" => {
                options.unencrypted = true;
            }

            _ => {
                error!("invalid argument: {}", arg);
                return Err(());
            }
        }
    }

    if let Err(e) = hiberman::resume(&options) {
        error!("Failed to resume: {}", e);
        return Err(());
    }

    Ok(())
}

fn app_usage(error: bool) {
    let usage_msg = r#"Usage: hiberman subcommand [options]
This application coordinates suspend-to-disk activities. Try
hiberman <subcommand> --help for details on specific subcommands.

Valid subcommands are:
    help -- Print this help text.
    hibernate -- Suspend the machine to disk now.
    resume -- Resume the system now.
    cat -- Write a disk file contents to stdout.
    cookie -- Read or write the hibernate cookie.
"#;
    print_usage(usage_msg, error);
}

fn hiberman_main() -> std::result::Result<(), ()> {
    let mut args = std::env::args();
    if args.next().is_none() {
        eprintln!("expected executable name.");
        return Err(());
    }

    let subcommand = match args.next() {
        Some(subcommand) => subcommand,
        None => {
            eprintln!("expected a subcommand");
            return Err(());
        }
    };

    let mut args = std::env::args();
    args.next();
    args.next();
    match subcommand.as_ref() {
        "--help" | "-h" | "help" => {
            app_usage(false);
            return Ok(());
        }
        "cat" => hiberman_cat(&mut args),
        "cookie" => hiberman_cookie(&mut args),
        "hibernate" => hiberman_hibernate(&mut args),
        "resume" => hiberman_resume(&mut args),
        _ => {
            error!("unknown subcommand: {}", subcommand);
            return Err(());
        }
    }
}

fn main() {
    std::process::exit(if hiberman_main().is_ok() { 0 } else { 1 });
}

#[cfg(test)]
mod tests {
    use super::*;
}
