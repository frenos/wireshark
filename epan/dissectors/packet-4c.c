/* packet-4c.c
 * Copyright by Michael Tuexen <tuexen [AT] fh-muenster.de>
 *
 * $Id: packet-m2pa.c,v 1.21 2003/05/04 09:43:49 tuexen Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-m3ua.c
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>
#include <tvbuff-int.h>
#include <epan/conversation.h>
#include <stdio.h>
#include <epan/to_str.h>

#include "packet-tcp.h"
#include "packet-udp.h"
#include "packet-sctp.h"

#define NETWORK_BYTE_ORDER FALSE
#define SCTP_PORT_4C       55555
#define TCP_PORT_4C        55555
#define UDP_PORT_4C        55555

static int proto_4c        = -1;

//static conversation_t *conversation;
static guint32 new_4c_ppid = 58;

static int hf_type         = -1;
static int hf_length       = -1;
static int hf_value        = -1;
static int hf_value_seq    = -1;
static int hf_value_col    = -1;
static int hf_peer_address = -1;
static int hf_peer_port    = -1;
static int hf_peer_start   = -1; 

static int hf_name_length  = -1;
static int hf_pw_length    = -1;
static int hf_name         = -1;
static int hf_pw           = -1;
static int hf_start        = -1;
static int hf_error	   = -1;
static int hf_other        = -1;

static gint ett_4c         = -1;

static gboolean four_c_desegment = TRUE;
static gint error_type     = -1;

static expert_field ei_4c_type_unknown = EI_INIT;
static expert_field ei_4c_invalid_padding = EI_INIT;

static dissector_handle_t sub_handle_4c;

#define TYPE_LENGTH         2
#define LENGTH_LENGTH       2
#define HEADER_LENGTH       (TYPE_LENGTH + LENGTH_LENGTH)
#define SEQNO_LENGTH	    4
#define COLUMN_LENGTH	    4
#define IPV4_ADDRESS_LENGTH 4
#define NAMELENGTH_LENGTH	2
#define PWLENGTH_LENGTH	    2
#define START_LENGTH        4
#define ERROR_LENGTH        4
#define ERROR_CAUSE_LENGTH  4
#define RESERVED_LENGTH     2
#define PORT_LENGTH	    2
#define PSTART_LENGTH       2
#define PNAMELENGTH_LENGTH  2

#define NAME_LENGTH        20
#define PW_LENGTH          20

#define HEADER_OFFSET      0
#define TYPE_OFFSET        HEADER_OFFSET
#define LENGTH_OFFSET      (TYPE_OFFSET + TYPE_LENGTH)
#define VALUE_OFFSET       (LENGTH_OFFSET + LENGTH_LENGTH)
#define SEQNO_OFFSET	   VALUE_OFFSET
#define COLUMN_OFFSET	   (VALUE_OFFSET + SEQNO_LENGTH)
#define NAMELENGTH_OFFSET  VALUE_OFFSET + PORT_LENGTH
#define	PWLENGTH_OFFSET	   (NAMELENGTH_OFFSET + NAMELENGTH_LENGTH)
#define NAME_OFFSET	   (PWLENGTH_OFFSET + PWLENGTH_LENGTH + RESERVED_LENGTH)
#define ERROR_OFFSET	   (LENGTH_OFFSET + LENGTH_LENGTH)

#define ADDRESS_OFFSET     (LENGTH_OFFSET + LENGTH_LENGTH)
#define PORT_OFFSET	   (ADDRESS_OFFSET + IPV4_ADDRESS_LENGTH)
#define PSTART_OFFSET      (PORT_OFFSET + PORT_LENGTH)
#define PNAMELENGTH_OFFSET (PSTART_OFFSET+PSTART_LENGTH)
#define PNAME_OFFSET       (PNAMELENGTH_OFFSET+PNAMELENGTH_LENGTH +RESERVED_LENGTH)

#define REGISTRATION_REQUEST_TYPE 0x1
#define REGISTRATION_ACK_TYPE     0x2
#define REGISTRATION_NACK_TYPE    0x3
#define PEER_INFO_TYPE            0x4
#define SET_COLUMN_TYPE           0x400
#define SET_COLUMN_ACK_TYPE       0x401
#define HEARTBEAT_REQUEST_TYPE    0x800
#define HEARTBEAT_ACK_TYPE        0x801
#define ERROR_CAUSE_TYPE          0xC00
#define SERVER_ANNOUNCE_TYPE      0x1000

#define ERROR_COLUMN_OUT_OF_RANGE 1
#define ERROR_COLUMN_FULL         2
#define ERROR_UNKNOWN_TYPE        3
#define ERROR_OTHER               4294967295 //0xffffffff 

static const value_string type_values[] = {
  { REGISTRATION_REQUEST_TYPE, "Registration Request"                  },
  { REGISTRATION_ACK_TYPE,     "Registration Acknowledgement"          },
  { REGISTRATION_NACK_TYPE,    "Negative Registration Acknowledgement" },
  { HEARTBEAT_REQUEST_TYPE,    "Heartbeat Request"                     },
  { HEARTBEAT_ACK_TYPE,        "Heartbeat Acklowledgement"             },
  { PEER_INFO_TYPE,            "Peer Info"                             },
  { ERROR_CAUSE_TYPE,          "Error Cause"                           },
  { SET_COLUMN_TYPE,           "Set Column"                            },
  { SET_COLUMN_ACK_TYPE,       "Set Column Acknowledgement"            },
  { SERVER_ANNOUNCE_TYPE,      "Server Announcement"                   },
  { 0,                         NULL                                    }}; 

static const value_string error_values[] = {
  {ERROR_COLUMN_OUT_OF_RANGE, "Column Out Of Range"},
  {ERROR_COLUMN_FULL, "Column Is Full"},
  {ERROR_UNKNOWN_TYPE, "Unknown Error"},
  {ERROR_OTHER, "Other Error, see details"}
};  

#define ADD_PADDING(x) ((((x) + 3) >> 2) << 2)
/*
typedef struct {
	guint32	dst_addr;
	guint32	clnt_port;
	guint16	dst_port;
	guint32	server_int_port;
	int	proto;
}conv_entry_t;

typedef struct {
	guint32	remote_addr;
	guint32	clnt_port;
	guint16	remote_port;
	guint32	server_int_port;
	int	proto;
}redirect_entry_t;
*/
static void
dissect_4c_error(tvbuff_t *message_tvb, packet_info *pinfo  _U_, proto_tree *four_c_tree)
{
  proto_item *error_item = NULL;
  proto_tree *error_tree = NULL;
  int message_length = -1;
  
  error_type = tvb_get_guint32(message_tvb,ERROR_OFFSET, NETWORK_BYTE_ORDER);
  
  error_item = proto_tree_add_item(four_c_tree,hf_error, message_tvb, ERROR_OFFSET, ERROR_LENGTH, NETWORK_BYTE_ORDER );
  error_tree = proto_item_add_subtree(error_item, hf_error);
  switch(error_type){
    case ERROR_COLUMN_OUT_OF_RANGE:
      col_add_fstr(pinfo->cinfo, COL_INFO, "- %s","Column out of range");
      proto_tree_add_item(error_tree,hf_value_col, message_tvb, ERROR_OFFSET+ERROR_LENGTH, ERROR_CAUSE_LENGTH, NETWORK_BYTE_ORDER );
      break;
    case ERROR_COLUMN_FULL:
      col_add_fstr(pinfo->cinfo, COL_INFO, "- %s","Column is full");
      proto_tree_add_item(error_tree,hf_value_col, message_tvb, ERROR_OFFSET+ERROR_LENGTH, ERROR_CAUSE_LENGTH, NETWORK_BYTE_ORDER );
      break;
    case ERROR_UNKNOWN_TYPE:
      col_add_fstr(pinfo->cinfo, COL_INFO, "- %s","Unknown Error");
      break;
    case ERROR_OTHER:
      
      message_length = tvb_get_guint16(message_tvb,LENGTH_OFFSET, NETWORK_BYTE_ORDER);
      message_length = message_length -(ERROR_OFFSET+ERROR_LENGTH);
      proto_tree_add_item(error_tree, hf_other, message_tvb, ERROR_OFFSET+ERROR_LENGTH, message_length, NETWORK_BYTE_ORDER);
      col_add_fstr(pinfo->cinfo, COL_INFO, "- %s","Other Error");
      break;
    default:
      col_add_fstr(pinfo->cinfo, COL_INFO, "- %s","default");
  }
  
}
  
static void
dissect_4c_registration(tvbuff_t *message_tvb, packet_info *pinfo _U_, proto_tree *four_c_tree)
{
      int namelen, pwlen, offset;
      
      proto_tree_add_item(four_c_tree, hf_name_length, message_tvb, NAMELENGTH_OFFSET, NAMELENGTH_LENGTH, NETWORK_BYTE_ORDER);
      proto_tree_add_item(four_c_tree, hf_pw_length,   message_tvb, PWLENGTH_OFFSET,   PWLENGTH_LENGTH,   NETWORK_BYTE_ORDER);
      namelen=tvb_get_guint16(message_tvb, NAMELENGTH_OFFSET, NETWORK_BYTE_ORDER);
      proto_tree_add_item(four_c_tree, hf_name, message_tvb, NAME_OFFSET, namelen,FALSE);
      pwlen=tvb_get_ntohs(message_tvb, PWLENGTH_OFFSET);
      offset=ADD_PADDING(namelen);
      proto_tree_add_item(four_c_tree, hf_pw, message_tvb, NAME_OFFSET+offset, pwlen,FALSE);
}
/*
static void
add_new4c_conversation(packet_info *pinfo, conv_entry_t *conv_info)
{
  	conversation_t *conv;
	redirect_entry_t *new_conv_info;

	if (pinfo->fd->flags.visited) {
		return;
	}

	conv = find_conversation( pinfo->fd->num, &pinfo->src,
		&pinfo->dst, (port_type)conv_info->proto, conv_info->server_int_port,
		conv_info->clnt_port, 0);

	if ( !conv) {
		conv = conversation_new( pinfo->fd->num, &pinfo->src, &pinfo->dst,
			(port_type)conv_info->proto, conv_info->server_int_port,
			conv_info->clnt_port, 0);
	}
	conversation_set_dissector(conv, sub_handle_4c);

	new_conv_info = wmem_new(wmem_file_scope(), redirect_entry_t);

	new_conv_info->remote_addr = conv_info->dst_addr;
	new_conv_info->clnt_port = conv_info->clnt_port;
	new_conv_info->remote_port = conv_info->dst_port;
	new_conv_info->server_int_port = conv_info->server_int_port;
	new_conv_info->proto = conv_info->proto;

	conversation_add_proto_data(conv, proto_4c,new_conv_info);
}
*/



static void
dissect_4c_peerinfo(tvbuff_t *message_tvb, packet_info *pinfo , proto_tree *four_c_tree)
{
      int namelen;

      gchar *addrbuf;
      int len = sizeof(gchar)*32;
      addrbuf = (gchar *)malloc(len);
 
   /*   
      conv_info->dst_addr = tvb_get_guint32(message_tvb, ADDRESS_OFFSET, NETWORK_BYTE_ORDER);
      conv_info->dst_port = tvb_get_guint16(message_tvb, PORT_OFFSET, NETWORK_BYTE_ORDER);
      conv_info->server_int_port = pinfo->destport;
      conv_info->clnt_port = pinfo->srcport;
      conv_info->proto = PT_UDP;
      */  

      printf("PRINT STRUCT -------------\n");
      printf("addr in packet       : %i\n",tvb_get_guint32(message_tvb, ADDRESS_OFFSET, NETWORK_BYTE_ORDER));
      printf("port in packet       : %i\n",tvb_get_guint16(message_tvb, PORT_OFFSET, NETWORK_BYTE_ORDER)); // 44444
      
      address_to_str_buf(&(pinfo->dst),addrbuf,len);
      printf("pinfo->destaddr      : %s\n",addrbuf); // ADDR
      
      printf("pinfo->destport      : %i\n",pinfo->destport); // UDP PORT 55555
      printf("pinfo->srcport       : %i\n",pinfo->srcport); // UDP PORT 12345
      fflush(stdout);
    
      proto_tree_add_item(four_c_tree, hf_peer_address, message_tvb, ADDRESS_OFFSET, IPV4_ADDRESS_LENGTH,NETWORK_BYTE_ORDER);
      proto_tree_add_item(four_c_tree, hf_peer_port, message_tvb, PORT_OFFSET, PORT_LENGTH,NETWORK_BYTE_ORDER);
      proto_tree_add_item(four_c_tree, hf_peer_start, message_tvb, PSTART_OFFSET, PSTART_LENGTH,NETWORK_BYTE_ORDER);
      proto_tree_add_item(four_c_tree, hf_name_length, message_tvb, PNAMELENGTH_OFFSET, PNAMELENGTH_LENGTH, NETWORK_BYTE_ORDER);
      namelen=tvb_get_guint16(message_tvb, PNAMELENGTH_OFFSET, NETWORK_BYTE_ORDER);
      proto_tree_add_item(four_c_tree, hf_name, message_tvb, PNAME_OFFSET, namelen, NETWORK_BYTE_ORDER);
      
      //add_new4c_conversation(pinfo,conv_info);
}

static gboolean testpadding(packet_info *pinfo, proto_item *msg_type_item, guint16 type, guint16 padding_length){
	switch (type) {
		case REGISTRATION_REQUEST_TYPE:		
		case HEARTBEAT_REQUEST_TYPE:
		case HEARTBEAT_ACK_TYPE:
		case PEER_INFO_TYPE:
		case ERROR_CAUSE_TYPE:
			break;
		case SET_COLUMN_TYPE:
		case SET_COLUMN_ACK_TYPE:
		case REGISTRATION_ACK_TYPE:
		case REGISTRATION_NACK_TYPE:
		case SERVER_ANNOUNCE_TYPE:
			if(padding_length>0){
			  expert_add_info(pinfo, msg_type_item, &ei_4c_invalid_padding);
			  return FALSE;
			}
			break;
	}
	return TRUE;
}

static void
dissect_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *four_c_tree)
{
	guint16 type, length, padding_length , reported_length, value_length;
	proto_item *msg_type_item;
	gboolean padding_ok;
	
	type            = tvb_get_ntohs(message_tvb, TYPE_OFFSET);
	length          = tvb_get_ntohs(message_tvb, LENGTH_OFFSET);
	reported_length = tvb_reported_length(message_tvb);
	padding_length  = reported_length - length;
	
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(type, type_values, "Unknown Type"));
	col_set_fence(pinfo->cinfo, COL_INFO);
	
	if (four_c_tree) 
	{
		value_length = length - HEADER_LENGTH;
		//always show MESSAGE_TYPE and MESSAGE_LENGTH, no matter the TYPE
		msg_type_item = proto_tree_add_item(four_c_tree, hf_type,   message_tvb, TYPE_OFFSET,   TYPE_LENGTH,   NETWORK_BYTE_ORDER);
		proto_tree_add_item(four_c_tree, hf_length, message_tvb, LENGTH_OFFSET, LENGTH_LENGTH, NETWORK_BYTE_ORDER);

		padding_ok = testpadding(pinfo,msg_type_item,type,padding_length);
		
		if (value_length > 0 && padding_ok) {
			switch (type) {
			case REGISTRATION_REQUEST_TYPE:
				dissect_4c_registration(message_tvb, pinfo, four_c_tree);
				break;	
			case HEARTBEAT_REQUEST_TYPE:
			case HEARTBEAT_ACK_TYPE:
				//HB_Request and HB_ACK both only have INFO as data (=value here)
				proto_tree_add_item(four_c_tree, hf_value, message_tvb, VALUE_OFFSET, value_length, NETWORK_BYTE_ORDER);
				break;
			case SET_COLUMN_TYPE:
				proto_tree_add_item(four_c_tree, hf_value_seq, message_tvb, SEQNO_OFFSET, SEQNO_LENGTH,NETWORK_BYTE_ORDER);
				proto_tree_add_item(four_c_tree, hf_value_col, message_tvb, COLUMN_OFFSET, COLUMN_LENGTH,NETWORK_BYTE_ORDER);
				break;
			case SET_COLUMN_ACK_TYPE:
				proto_tree_add_item(four_c_tree, hf_value_seq, message_tvb, SEQNO_OFFSET, SEQNO_LENGTH, NETWORK_BYTE_ORDER);
				break;
			case PEER_INFO_TYPE:
				dissect_4c_peerinfo(message_tvb,pinfo,four_c_tree);
				break;
			case ERROR_CAUSE_TYPE:
				dissect_4c_error(message_tvb,pinfo,four_c_tree);
				break;
			default:
				//msg_item = proto_tree_add_item(four_c_tree, hf_type, message_tvb, TYPE_OFFSET, TYPE_LENGTH, NETWORK_BYTE_ORDER);
				expert_add_info(pinfo, msg_type_item, &ei_4c_type_unknown);
			}
		}
	}
}

static void
dissect_4c_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  /*
        conv_entry_t *conv_info;
	conversation_t *conv;
  */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "4C");

	col_clear(pinfo->cinfo, COL_INFO);
	
/*	
	conv = find_or_create_conversation(pinfo);

	conv_info = (conv_entry_t *)conversation_get_proto_data(conv, proto_4c);
	if (!conv_info) {
		conv_info = wmem_new(wmem_file_scope(), conv_entry_t);
		conversation_add_proto_data(conv, proto_4c,
			conv_info);
	}
	
	printf("PRINT STRUCT -------------\n");
	printf("conv_info->dst_addr       : %i\n",conv_info->dst_addr);
	printf("conv_info->dst_port       : %i\n",conv_info->dst_port);
	printf("conv_info->server_int_port: %i\n",conv_info->server_int_port);
	printf("conv_info->clnt_port      : %i\n",conv_info->clnt_port);
	printf("conv_info->proto          : %i\n",conv_info->proto);
	fflush(stdout);
*/	
	if (tree) {
		proto_item *four_c_item = NULL;
		proto_tree *four_c_tree = NULL;
		four_c_item = proto_tree_add_item(tree, proto_4c, tvb, 0, -1, ENC_NA);
		four_c_tree = proto_item_add_subtree(four_c_item, ett_4c);
		dissect_message(tvb, pinfo, four_c_tree);		
	}
}
static guint
get_4c_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	return ADD_PADDING(tvb_get_ntohs(tvb, offset + TYPE_LENGTH));
}

static int
dissect_4c_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	dissect_4c_common(tvb, pinfo, tree);
	return tvb_reported_length(tvb);
}

static int
dissect_4c_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	tcp_dissect_pdus(tvb, pinfo, tree, four_c_desegment, HEADER_LENGTH, get_4c_pdu_len, dissect_4c_tcp_pdu, data);
	return tvb_reported_length(tvb);
}

static void
dissect_4c_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_4c_common(tvb, pinfo, tree);
}

static void
dissect_4c_sctp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_4c_common(tvb, pinfo, tree);
}
/*
static void dissect_4c_sub( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  


	guint32 *ptr;
	redirect_entry_t *redirect_info;
	conversation_t *conv;
	proto_tree      *tree_4c;
	proto_item      *ti;

	
	printf("4C SUB DISSECT\n");
	fflush(stdout);
	
	conv = find_conversation( pinfo->fd->num, &pinfo->src, &pinfo->dst,
		pinfo->ptype, pinfo->srcport, pinfo->destport, 0);



	redirect_info = (redirect_entry_t *)conversation_get_proto_data(conv,
		proto_4c);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "4C");

	col_set_str(pinfo->cinfo, COL_INFO,
			(( redirect_info->proto == PT_TCP) ? "TCP stream" :
			 "UDP packets"));

	if ( tree) {
		ti = proto_tree_add_item( tree, proto_4c, tvb, 0, 0,
					  ENC_NA );

		tree_4c = proto_item_add_subtree(ti, ett_4c);

		proto_tree_add_uint( tree_4c, hf_peer_port, tvb, 0, 0,
			redirect_info->remote_port);

		proto_tree_add_ipv4( tree_4c, hf_peer_address, tvb, 0, 0,
			redirect_info->remote_addr);

	}

 //set pinfo->{src/dst port} and call the TCP or UDP sub-dissector lookup 

	if ( pinfo->srcport == redirect_info->clnt_port)
		ptr = &pinfo->destport;
	else
		ptr = &pinfo->srcport;

	*ptr = redirect_info->remote_port;

	printf("REMOTE PORT: %i\n",*ptr);
	fflush(stdout);
	
	if ( redirect_info->proto == PT_TCP)
		decode_tcp_ports( tvb, 0, pinfo, tree, pinfo->srcport,
			pinfo->destport, NULL, NULL);
	if(redirect_info->proto == PT_SCTP)
		decode_sctp_ports( tvb, 0, pinfo, tree, pinfo->srcport,
			pinfo->destport, -1);
	if(redirect_info->proto == PT_UDP)
		decode_udp_ports( tvb, 0, pinfo, tree, pinfo->srcport,
			pinfo->destport, -1);

	*ptr = redirect_info->server_int_port;
}
*/
void
proto_register_4c(void)
{
        module_t *four_c_module;
	expert_module_t *expert_4c;
	
	static hf_register_info hf[] = 
	{ { &hf_type,         { "Message type",    "4c.type",        FT_UINT16, BASE_HEX,  VALS(type_values),  0x0, "", HFILL} },
	  { &hf_length,       { "Message length",  "4c.length",      FT_UINT16, BASE_DEC,  NULL,               0x0, "", HFILL} },
	  { &hf_value,        { "Message value",   "4c.value",       FT_BYTES,  BASE_NONE, NULL,               0x0, "", HFILL} },
	  { &hf_value_seq,    { "Sequence number", "4c.seqno",       FT_UINT32, BASE_DEC,  NULL,               0x0, "", HFILL} },
	  { &hf_value_col,    { "Column number",   "4c.col",         FT_UINT32, BASE_DEC,  NULL,               0x0, "", HFILL} },
	  { &hf_name_length,  { "Username length", "4c.namelength",  FT_UINT32, BASE_DEC,  NULL,               0x0, "", HFILL} },
	  { &hf_pw_length,    { "Password length", "4c.pwlength",    FT_UINT32, BASE_DEC,  NULL,               0x0, "", HFILL} },
	  { &hf_start,        { "Player",          "4c.start",       FT_UINT32, BASE_DEC,  NULL,               0x0, "", HFILL} },
	  { &hf_peer_address, { "Peer Address",    "4c.peeraddress", FT_IPv4,   BASE_NONE, NULL,               0x0, "", HFILL} },
	  { &hf_peer_port,    { "Peer Port",       "4c.peerport",    FT_UINT16, BASE_DEC,  NULL,               0x0, "", HFILL} },
	  { &hf_peer_start,   { "Peer Start",      "4c.peerstart",   FT_UINT16, BASE_DEC,  NULL,               0x0, "", HFILL} },
	  { &hf_name,         { "User Name",       "4c.username",    FT_STRING, BASE_NONE, NULL,               0x0, "", HFILL} },
	  { &hf_pw,           { "User Password",   "4c.password",    FT_STRING, BASE_NONE, NULL,               0x0, "", HFILL} },
	  { &hf_error,        { "Error",           "4c.error",       FT_UINT32, BASE_DEC,  VALS(error_values), 0x0, "", HFILL} },
	  { &hf_other,        { "Other",           "4c.other",       FT_STRING, BASE_NONE, NULL,               0x0, "", HFILL} }
	};

	static gint *ett[] = {
		&ett_4c
	};

	static ei_register_info ei[] = {
          { &ei_4c_type_unknown, 	{ "4c.type_unknown",	PI_MALFORMED, PI_ERROR, "Type is unknown", 	EXPFILL }},
	  { &ei_4c_invalid_padding, 	{ "4c.invalid_padding",	PI_MALFORMED, PI_ERROR, "Invalid padding size", EXPFILL }}
        };
	

	proto_4c = proto_register_protocol("Four Connect", "4C", "4c");

	proto_register_field_array(proto_4c, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_4c = expert_register_protocol(proto_4c);
	expert_register_field_array(expert_4c, ei, array_length(ei));
	four_c_module = prefs_register_protocol(proto_4c, NULL);
	prefs_register_bool_preference(four_c_module, 
	                               "desegment_4c_messages",
	                               "Desegment all 4C messages spanning multiple TCP segments",
	                               "Whether the 4C dissector should desegment all messages spanning multiple TCP segments",
	                               &four_c_desegment);
	//sub_handle_4c = create_dissector_handle(dissect_4c_sub,	proto_4c);
}

void
proto_reg_handoff_4c(void)
{
	static dissector_handle_t four_c_sctp_handle;
	static dissector_handle_t four_c_tcp_handle;
	static dissector_handle_t four_c_udp_handle;
	static guint32            current_ppid;
	
	
	four_c_sctp_handle = create_dissector_handle(dissect_4c_sctp, proto_4c);
	four_c_tcp_handle  = new_create_dissector_handle(dissect_4c_tcp,  proto_4c);
	four_c_udp_handle  = create_dissector_handle(dissect_4c_udp,  proto_4c);
	sub_handle_4c = four_c_tcp_handle;
	current_ppid = new_4c_ppid;
	dissector_add_uint("sctp.ppi", current_ppid, four_c_sctp_handle);
	dissector_add_uint("sctp.port", SCTP_PORT_4C, four_c_sctp_handle);
	dissector_add_uint("tcp.port",  TCP_PORT_4C,  four_c_tcp_handle);
	dissector_add_uint("udp.port",  UDP_PORT_4C,  four_c_udp_handle);
	//heur_dissector_add( "sctp", dissect_4c_heur, "4C over SCTP", "4c_sctp", proto_4c, HEURISTIC_ENABLE);
}

