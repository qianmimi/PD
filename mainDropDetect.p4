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
#define SF_SHORT_BIT_WIDTH 15
#include "parser.p4"

field_list flPortFields {
    ig_intr_md.ingress_port;
}
field_list_calculation PortHashCalc {
    input { flPortFields; }
    algorithm : crc16;
    output_width : SF_SHORT_BIT_WIDTH;
}
control ingress {
    apply(tiVerifyfarward);
}

control egress {  
	ce();  
}

@pragma stage 0
table tiVerifyfarward{
    reads {ethernet.etherType : exact;}
    actions {aiUpdatePacketId; aiNoOp; aiforward;}
    default_action : aiNoOp();
    size : 128;
}
action aiUpdatePacketId() {  
    modify_field(sfInfoKey.endPId, ipv4_option.packetID);
    modify_field_with_hash_based_offset(sfInfoKey.PortHashVal, 0, PortHashCalc, 65536);
    sUpdatePacketId.execute_stateful_alu(sfInfoKey.PortHashVal);

}

//if packetId==register+1,forward packet
//else  
/* inconsecutive sequence numbers as a sign of packet drops;
   constructs a packet which contains the starting and ending of
   missing sequence numbers and sends it to Switch-1.*/

blackbox stateful_alu sUpdatePacketId{
    reg : rPacketId;
    condition_lo : ipv4_option.packetID== register_lo+1;

    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo+1;

    output_predicate : not condition_lo;
    output_dst : sfInfoKey.startPId;
    output_value : register_lo;
}

register rPacketId {
    width : 32;
    instance_count : SF_SHORT_SIZE;
}
