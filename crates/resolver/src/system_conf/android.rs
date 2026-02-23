use jni::objects::{IntoAuto as _, JByteArray, JList, JObject, JValue};
use jni::{jni_sig, jni_str};
use std::net::IpAddr;
use tracing::{trace, warn};

use crate::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use crate::proto::ProtoError;

pub fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), ProtoError> {
    let ctx = ndk_context::android_context();
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) };
    vm.attach_current_thread(|env| {
        let activity = unsafe { JObject::from_raw(env, ctx.context().cast()) };

        // https://developer.android.com/reference/android/content/Context#getSystemService(java.lang.String)
        let connectivity_service = env.new_string("connectivity")?;
        let connectivity_manager = env
            .call_method(
                activity,
                jni_str!("getSystemService"),
                jni_sig!("(Ljava/lang/String;)Ljava/lang/Object;"),
                &[JValue::Object(&connectivity_service)],
            )?
            .l()?;

        // https://developer.android.com/reference/android/net/ConnectivityManager#getActiveNetwork()
        let network = env
            .call_method(
                &connectivity_manager,
                jni_str!("getActiveNetwork"),
                jni_sig!("()Landroid/net/Network;"),
                &[],
            )?
            .l()?;

        // https://developer.android.com/reference/android/net/ConnectivityManager#getLinkProperties(android.net.Network)
        let link_properties = env
            .call_method(
                &connectivity_manager,
                jni_str!("getLinkProperties"),
                jni_sig!("(Landroid/net/Network;)Landroid/net/LinkProperties;"),
                &[JValue::Object(&network)],
            )?
            .l()?;

        // https://developer.android.com/reference/android/net/LinkProperties#getDnsServers()
        let dns_servers = env
            .call_method(
                &link_properties,
                jni_str!("getDnsServers"),
                jni_sig!("()Ljava/util/List;"),
                &[],
            )?
            .l()?;
        let dns_servers = env.cast_local::<JList<'_>>(dns_servers)?;
        let dns_servers = dns_servers.iter(env)?;

        let mut nameservers = Vec::<NameServerConfig>::new();
        while let Some(server) = dns_servers.next(env)? {
            let server = server.auto();

            // https://developer.android.com/reference/java/net/InetAddress#getAddress()
            let ip_bytes_obj = env
                .call_method(&server, jni_str!("getAddress"), jni_sig!("()[B"), &[])?
                .l()?;
            let ip_bytes_arr = env.cast_local::<JByteArray<'_>>(ip_bytes_obj)?;
            let ip_bytes = env.convert_byte_array(ip_bytes_arr)?;

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
    })
}
