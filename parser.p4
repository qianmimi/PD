/**
 *
 * parser.p4
 *
 */
 
#define ETHER_TYPE_IPV4 0x0800
#define ETHERTYPE_DROP_NF 0x0801
parser start {
    return parse_ethernet;
}
parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_DROP_NF: parse_drop_nf; // notification packet，This should report event???
        ETHERTYPE_IPV4 : parse_ipv4; 
        default : ingress;
    }
}

// IP.
parser parse_ipv4 {
    extract(ipv4);
    return select(ipv4.ihl) {
        5: parse_l4; //no options
        default : parse_ipv4_option;  //have options
    }
}
parser parse_ipv4_option {
    extract(ipv4_option);
    return parse_l4;
}

// TCP / UDP ports.
parser parse_l4 {
    extract(l4_ports);
    return ingress;
}


// looks up its ring buffer for the packets whose sequence
//numbers fall into the missing interval and reports them as dropped
//packets.
parser parse_drop_no {

}
