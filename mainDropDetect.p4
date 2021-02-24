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
    apply(tiVerifyfarward);//verify whether packet drop,TO DO：need to modify
    //TO DO
    /*1, forward packet always,
      2, if sfInfoKey.dflag==1 constructs a packet which contains the starting and ending of missing sequence numbers and sends it to upstreamswitch
    produce three copies of it in order to avoid drop again */
    apply(tiNotice);
}

control egress {  
	  
}

@pragma stage 0
table tiVerifyfarward{
    reads {ethernet.etherType : exact;}//verify normal packet or notice packet
    actions {aiUpdatePacketId; aiNoOp;}
    default_action : aiNoOp();
    size : 128;
}
//if normal packet
action aiUpdatePacketId() {  
    modify_field(sfInfoKey.endPId, ipv4_option.packetID);
    modify_field_with_hash_based_offset(sfInfoKey.PortHashVal, 0, PortHashCalc, 65536);
    sUpdatePacketId.execute_stateful_alu(sfInfoKey.PortHashVal);
}

//if packetId==register+1,no drop
/* else inconsecutive sequence numbers as a sign of packet drops;*/
/*dflag==0 no drop ; dflag==1 drop yes*/
blackbox stateful_alu sUpdatePacketId{
    reg : rPacketId;
    condition_lo : ipv4_option.packetID== register_lo+1;

    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo+1;

    output_predicate : not condition_lo;
    output_dst : sfInfoKey.dflag;
    output_value : 1;
    
    output_dst : sfInfoKey.startPId;//能不能这样用?两个output_dst和output_value
    output_value : register_lo;//保存开始seqnumber
}

register rPacketId {
    width : 32;
    instance_count : SF_SHORT_SIZE;
}

//if sfInfoKey.dflag==1,constructs a packet
@pragma stage 0
@pragma ignore_table_dependency tiVerifyfarward
table tiNotice {
    reads {sfInfoKey.dflag : exact;}
    actions {ainotice; aiNoOp;}
    default_action : aiNoOp();
    size : 128;
}
action ainotice() {
   //TODO: constructs a packet
   add_header(sfNotice);
   modify_field(sfNotice.realEtherType, ethernet.etherType);
   modify_field(sfNotice.startPId, sfInfoKey.startPId);
   modify_field(sfNotice.endPId, sfInfoKey.endPId);
   modify_field(ethernet.etherType, ETHERTYPE_DROP_NF);
   

}

action aiforward(egress_spec) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_spec);
}
