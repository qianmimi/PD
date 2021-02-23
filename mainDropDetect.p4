/**
 *
 * mainDropDetect.p4
 * 
 */
#include <tofino/intrinsic_metadata.p4>
#include <tofino/constants.p4>
#include <tofino/stateful_alu_blackbox.p4>
#include <tofino/primitives.p4>

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_DROP_NF 0x081A
#include "parser.p4"

control ingress {
    if (valid(ipv4)) {
	    ciDropDetectDrop();
	}

}

control egress {  
	ceStarFlow();  
}

control ciDropDetectDrop {
    if (sfMeta.inProcessing == 1) {
        apply(tiSetMatch);
    }
}
blackbox stateful_alu sUpdatePacketId{
    reg : rPacketId;
    condition_lo : ipv4.srcAddr == register_lo;

    update_lo_1_predicate : not condition_lo;
    update_lo_1_value : ipv4.srcAddr;

    output_predicate : not condition_lo;
    output_dst : sfExportKey.srcAddr;
    output_value : register_lo;
}

register rPacketId {
    width : 32;
    instance_count : SF_SHORT_SIZE;
}
