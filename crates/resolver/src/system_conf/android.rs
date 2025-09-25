use jni::objects::{AutoLocal, JObject, JPrimitiveArray, JValue};
use jni::sys::jbyte;
use std::net::IpAddr;
use tracing::{trace, warn};

use crate::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use crate::proto::ProtoError;

pub fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), ProtoError> {
    let ctx = ndk_context::android_context();
    let activity = unsafe { JObject::from_raw(ctx.context().cast()) };
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }?;
    let mut env = vm.attach_current_thread()?;

    // https://developer.android.com/reference/android/content/Context#getSystemService(java.lang.String)
    let connectivity_service = env.new_string("connectivity")?;
    let connectivity_manager = env
        .call_method(
            activity,
            "getSystemService",
            "(Ljava/lang/String;)Ljava/lang/Object;",
            &[JValue::Object(&connectivity_service)],
        )?
        .l()?;

    // https://developer.android.com/reference/android/net/ConnectivityManager#getActiveNetwork()
    let network = env
        .call_method(
            &connectivity_manager,
            "getActiveNetwork",
            "()Landroid/net/Network;",
            &[],
        )?
        .l()?;

    // https://developer.android.com/reference/android/net/ConnectivityManager#getLinkProperties(android.net.Network)
    let link_properties = env
        .call_method(
            &connectivity_manager,
            "getLinkProperties",
            "(Landroid/net/Network;)Landroid/net/LinkProperties;",
            &[JValue::Object(&network)],
        )?
        .l()?;

    // https://developer.android.com/reference/android/net/LinkProperties#getDnsServers()
    let dns_servers = env
        .call_method(&link_properties, "getDnsServers", "()Ljava/util/List;", &[])?
        .l()?;
    let dns_servers = env.get_list(&dns_servers)?;
    let mut dns_servers = dns_servers.iter(&mut env)?;

    let mut nameservers = Vec::<NameServerConfig>::new();
    while let Some(server) = dns_servers.next(&mut env)? {
        let server: AutoLocal<'_, JObject<'_>> = env.auto_local(server);

        // https://developer.android.com/reference/java/net/InetAddress#getAddress()
        let ip_bytes_obj = env.call_method(&server, "getAddress", "()[B", &[])?.l()?;
        let ip_bytes = env.convert_byte_array(JPrimitiveArray::<'_, jbyte>::from(ip_bytes_obj))?;

        let ip = match ip_bytes.len() {
            4 => {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&ip_bytes);
                IpAddr::from(arr)
            }
            16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&ip_bytes);
                IpAddr::from(arr)
            }
            _ => {
                warn!("Got invalid ip length: {}. Skipping.", ip_bytes.len());
                continue;
            }
        };
        nameservers.push(NameServerConfig::udp_and_tcp(ip.into()));
    }

    trace!("Got DNS servers: {:?}", nameservers);

    Ok((
        ResolverConfig::from_parts(None, vec![], nameservers),
        Default::default(),
    ))
}
