use forti_client::auth::xml::Route;
use forti_client::tun::routes::{mask_to_prefix, route_add_cmd, route_delete_cmd};
use std::net::Ipv4Addr;

#[test]
fn test_route_add_subnet() {
    let route = Route {
        ip: Ipv4Addr::new(10, 60, 0, 0),
        mask: Ipv4Addr::new(255, 255, 240, 0),
    };
    let args = route_add_cmd(&route, "utun3");
    assert_eq!(
        args,
        vec!["add", "-net", "10.60.0.0/20", "-interface", "utun3"]
    );
}

#[test]
fn test_route_add_host() {
    let route = Route {
        ip: Ipv4Addr::new(18, 169, 33, 210),
        mask: Ipv4Addr::new(255, 255, 255, 255),
    };
    let args = route_add_cmd(&route, "utun3");
    assert_eq!(
        args,
        vec!["add", "-host", "18.169.33.210", "-interface", "utun3"]
    );
}

#[test]
fn test_route_delete_subnet() {
    let route = Route {
        ip: Ipv4Addr::new(10, 60, 0, 0),
        mask: Ipv4Addr::new(255, 255, 240, 0),
    };
    let args = route_delete_cmd(&route, "utun3");
    assert_eq!(
        args,
        vec!["delete", "-net", "10.60.0.0/20", "-interface", "utun3"]
    );
}

#[test]
fn test_mask_to_prefix_len() {
    assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 255)), 32);
    assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), 24);
    assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 240, 0)), 20);
    assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 0, 0)), 16);
    assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 0, 0, 0)), 8);
    assert_eq!(mask_to_prefix(Ipv4Addr::new(0, 0, 0, 0)), 0);
}
