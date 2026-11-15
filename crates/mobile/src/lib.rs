//! `snitchhiker-mobile`: the Rust core of the Android app (decision 0011). It holds the app's connections to its
//! nodes (iroh, as the desktop app's remote ones) and pairs with nodes; requests and notices cross as the protocol's
//! own messages, encoded. This file is only the JNI glue of `core`: the static methods of the app's
//! `dev.nikarh.snitchhiker.app.Native`. Errors and panics become Java `RuntimeException`s.

#![expect(
    clippy::must_use_candidate,
    reason = "JNI entry points: the JVM calls them, and uses what they return"
)]

pub mod core;

use jni::EnvUnowned;
use jni::errors::ThrowRuntimeExAndDefault;
use jni::objects::{JByteArray, JClass, JObjectArray, JString};
use jni::sys::{jint, jlong};
use jni::{Env, jni_mangle};

/// An application error, for Java.
fn fail(env: &mut Env<'_>, message: &str) -> jni::errors::Error {
    let _ = env.throw_new(
        jni::jni_str!("java/lang/RuntimeException"),
        jni::strings::JNIString::new(message),
    );
    jni::errors::Error::JavaException
}

fn bytes(env: &Env<'_>, array: &JByteArray<'_>) -> jni::errors::Result<Vec<u8>> {
    env.convert_byte_array(array)
}

fn handle(value: jlong) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn jlong_of(value: u64) -> jlong {
    jlong::try_from(value).unwrap_or(jlong::MAX)
}

#[jni_mangle("dev.nikarh.snitchhiker.app.Native")]
pub extern "system" fn generate_key<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> JByteArray<'local> {
    unowned
        .with_env(|env| env.byte_array_from_slice(&core::generate_key()))
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[jni_mangle("dev.nikarh.snitchhiker.app.Native")]
pub extern "system" fn key_id<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    key: JByteArray<'local>,
) -> JString<'local> {
    unowned
        .with_env(|env| {
            let key = bytes(env, &key)?;
            match core::key_id(&key) {
                Ok(id) => JString::from_str(env, id),
                Err(e) => Err(fail(env, &e)),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[jni_mangle("dev.nikarh.snitchhiker.app.Native")]
pub extern "system" fn pair<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    key: JByteArray<'local>,
    link_or_code: JString<'local>,
    name: JString<'local>,
    relays: JObjectArray<'local>,
) -> JString<'local> {
    unowned
        .with_env(|env| {
            let key = bytes(env, &key)?;
            let link_or_code = link_or_code.try_to_string(env)?;
            let name = name.try_to_string(env)?;
            let mut list = Vec::new();
            for index in 0..relays.len(env)? {
                let element = relays.get_element(env, index)?;
                let item = JString::cast_local(env, element)?;
                list.push(item.try_to_string(env)?);
            }
            match core::pair(&key, &link_or_code, &name, &list) {
                Ok(node) => JString::from_str(env, node),
                Err(e) => Err(fail(env, &e)),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[jni_mangle("dev.nikarh.snitchhiker.app.Native")]
pub extern "system" fn connect<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    key: JByteArray<'local>,
    node: JString<'local>,
) -> jlong {
    unowned
        .with_env(|env| {
            let key = bytes(env, &key)?;
            let node = node.try_to_string(env)?;
            core::connect(&key, &node)
                .map(jlong_of)
                .map_err(|e| fail(env, &e))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[jni_mangle("dev.nikarh.snitchhiker.app.Native")]
pub extern "system" fn welcome<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    connection: jlong,
) -> JByteArray<'local> {
    unowned
        .with_env(|env| match core::welcome(handle(connection)) {
            Ok(welcome) => env.byte_array_from_slice(&welcome),
            Err(e) => Err(fail(env, &e)),
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[jni_mangle("dev.nikarh.snitchhiker.app.Native")]
pub extern "system" fn call<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    connection: jlong,
    request: JByteArray<'local>,
) -> JByteArray<'local> {
    unowned
        .with_env(|env| {
            let request = bytes(env, &request)?;
            match core::call(handle(connection), &request) {
                Ok(response) => env.byte_array_from_slice(&response),
                Err(e) => Err(fail(env, &e)),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[jni_mangle("dev.nikarh.snitchhiker.app.Native")]
pub extern "system" fn subscribe<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    connection: jlong,
    topic: jint,
) -> jlong {
    unowned
        .with_env(|env| {
            core::subscribe(handle(connection), topic)
                .map(jlong_of)
                .map_err(|e| fail(env, &e))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// The next notice, or null when none came within the time.
#[jni_mangle("dev.nikarh.snitchhiker.app.Native")]
pub extern "system" fn next_notice<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    connection: jlong,
    timeout_ms: jlong,
) -> JByteArray<'local> {
    unowned
        .with_env(|env| {
            match core::next_notice(handle(connection), u64::try_from(timeout_ms).unwrap_or(0)) {
                Ok(Some(notice)) => env.byte_array_from_slice(&notice),
                Ok(None) => Ok(JByteArray::null()),
                Err(e) => Err(fail(env, &e)),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[jni_mangle("dev.nikarh.snitchhiker.app.Native")]
pub extern "system" fn close<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    connection: jlong,
) {
    unowned
        .with_env(|_| {
            core::close(handle(connection));
            Ok::<_, jni::errors::Error>(())
        })
        .resolve::<ThrowRuntimeExAndDefault>();
}
