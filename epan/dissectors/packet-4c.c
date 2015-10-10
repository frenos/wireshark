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

#include "epan/packet.h"
#include "epan/proto.h"
#include "packet-tcp.h"
#include "prefs.h"

#define NETWORK_BYTE_ORDER FALSE
#define SCTP_PORT_4C       55555
#define TCP_PORT_4C        55555
#define UDP_PORT_4C        55555

static int proto_4c        = -1;

static int hf_type         = -1;
static int hf_length       = -1;
static int hf_value        = -1;
static int hf_value_seq    = -1;
static int hf_value_col    = -1;
static int hf_peer_address = -1;
static int hf_name_length  = -1;
static int hf_pw_length    = -1;
static int hf_name         = -1;
static int hf_pw           = -1;
static int hf_start        = -1;

static gint ett_4c         = -1;

static gboolean four_c_desegment = TRUE;

#define TYPE_LENGTH         2
#define LENGTH_LENGTH       2
#define HEADER_LENGTH       (TYPE_LENGTH + LENGTH_LENGTH)
#define SEQNO_LENGTH	    4
#define COLUMN_LENGTH	    4
#define IPV4_ADDRESS_LENGTH 4
#define NAMELENGTH_LENGTH	2
#define PWLENGTH_LENGTH	    2
#define START_LENGTH        4

#define NAME_LENGTH        20
#define PW_LENGTH          20

#define HEADER_OFFSET      0
#define TYPE_OFFSET        HEADER_OFFSET
#define LENGTH_OFFSET      (TYPE_OFFSET + TYPE_LENGTH)
#define VALUE_OFFSET       (LENGTH_OFFSET + LENGTH_LENGTH)
#define SEQNO_OFFSET	   VALUE_OFFSET
#define COLUMN_OFFSET	   (VALUE_OFFSET + SEQNO_LENGTH)
#define NAMELENGTH_OFFSET  VALUE_OFFSET
#define	PWLENGTH_OFFSET	   (NAMELENGTH_OFFSET + NAMELENGTH_LENGTH)
#define NAME_OFFSET		   (PWLENGTH_OFFSET + PWLENGTH_LENGTH)

#define ADDRESS_OFFSET     (VALUE_OFFSET + START_LENGTH)

#define REGISTRATION_REQUEST_TYPE 0x1
#define REGISTRATION_ACK_TYPE     0x2
#define REGISTRATION_NACK_TYPE    0x3
#define HEARTBEAT_REQUEST_TYPE    0x4
#define HEARTBEAT_ACK_TYPE        0x5
#define PEER_INFO_TYPE            0x6
#define ERROR_CAUSE_TYPE          0x7
#define SET_COLUMN_TYPE           0x8
#define SET_COLUMN_ACK_TYPE       0x9
#define SERVER_ANNOUNCE_TYPE      0xa

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

#define ADD_PADDING(x) ((((x) + 3) >> 2) << 2)

/*
static void
dissect_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *four_c_tree)
{
	guint16 type;
	guint16 value_length;
	int namelen, pwlen, offset;
	//ultra workaround :D
	pinfo = pinfo;
	type  = tvb_get_ntohs(message_tvb, TYPE_OFFSET);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(type, type_values, "reserved"));
		col_set_fence(pinfo->cinfo, COL_INFO);
	}
	if (four_c_tree) 
	{
		value_length = tvb_get_ntohs(message_tvb, LENGTH_OFFSET) - HEADER_LENGTH;
		proto_tree_add_item(four_c_tree, hf_type,   message_tvb, TYPE_OFFSET,   TYPE_LENGTH,   NETWORK_BYTE_ORDER);
		proto_tree_add_item(four_c_tree, hf_length, message_tvb, LENGTH_OFFSET, LENGTH_LENGTH, NETWORK_BYTE_ORDER);

		if (value_length > 0) {
			switch (type) {
			case REGISTRATION_REQUEST_TYPE:
				proto_tree_add_item(four_c_tree, hf_name_length, message_tvb, NAMELENGTH_OFFSET, NAMELENGTH_LENGTH, NETWORK_BYTE_ORDER);
				proto_tree_add_item(four_c_tree, hf_pw_length,   message_tvb, PWLENGTH_OFFSET,   PWLENGTH_LENGTH,   NETWORK_BYTE_ORDER);
				namelen=tvb_get_ntohs(message_tvb, NAMELENGTH_OFFSET);
				proto_tree_add_item(four_c_tree, hf_name, message_tvb, NAME_OFFSET, namelen,FALSE);
				pwlen=tvb_get_ntohs(message_tvb, PWLENGTH_OFFSET);
				offset=ADD_PADDING(namelen);
				proto_tree_add_item(four_c_tree, hf_pw, message_tvb, NAME_OFFSET+offset, pwlen,FALSE);
				break;
			case SET_COLUMN_TYPE:
				proto_tree_add_item(four_c_tree, hf_value_seq, message_tvb, SEQNO_OFFSET, SEQNO_LENGTH,NETWORK_BYTE_ORDER);
				proto_tree_add_item(four_c_tree, hf_value_col, message_tvb, COLUMN_OFFSET, COLUMN_LENGTH,NETWORK_BYTE_ORDER);
				break;
			case SET_COLUMN_ACK_TYPE:
				proto_tree_add_item(four_c_tree, hf_value_seq, message_tvb, SEQNO_OFFSET, SEQNO_LENGTH, NETWORK_BYTE_ORDER);
				break;
			case PEER_INFO_TYPE:
				proto_tree_add_item(four_c_tree, hf_peer_address, message_tvb, ADDRESS_OFFSET, IPV4_ADDRESS_LENGTH,	NETWORK_BYTE_ORDER);
				break;
			default:
				proto_tree_add_item(four_c_tree, hf_value, message_tvb, VALUE_OFFSET, value_length, NETWORK_BYTE_ORDER);
			}
		}
	}
}*/
/*
static void
dissect_4c_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *four_c_item;
	proto_tree *four_c_tree;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "4C");
	 
	if (tree) {
		four_c_item = proto_tree_add_item(tree, proto_4c, tvb, 0, -1, FALSE);
		four_c_tree = proto_item_add_subtree(four_c_item, ett_4c);
	} else {
		four_c_item = NULL;
		four_c_tree = NULL;
	}
	dissect_message(tvb, pinfo, four_c_tree);
}*/

/*static void
dissect_4c_sctp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_4c_common(tvb, pinfo, tree);
}

static guint
get_4c_pdu_len(tvbuff_t *tvb, int offset)
{
	return ADD_PADDING(tvb_get_ntohs(tvb, offset + TYPE_LENGTH));
}

static void
dissect_4c_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_4c_common(tvb, pinfo, tree);
}

static void
dissect_4c_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, four_c_desegment, HEADER_LENGTH, get_4c_pdu_len, dissect_4c_tcp_pdu);
}

static void
dissect_4c_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_4c_common(tvb, pinfo, tree);
}*/

void
proto_register_4c(void)
{
	static hf_register_info hf[] = 
	{ { &hf_type,         { "Message type",    "4c.type",        FT_UINT16, BASE_HEX,  VALS(type_values),  0x0, "", HFILL} },
	  { &hf_length,       { "Message length",  "4c.length",      FT_UINT16, BASE_DEC,  NULL,               0x0, "", HFILL} },
	  { &hf_value,        { "Message value",   "4c.value",       FT_BYTES,  BASE_NONE, NULL,               0x0, "", HFILL} },
	  { &hf_value_seq,    { "Sequence number", "4c.seqno",       FT_UINT32, BASE_DEC,  NULL,               0x0, "", HFILL} },
	  { &hf_value_col,    { "Column number",   "4c.col",         FT_UINT32, BASE_DEC,  NULL,               0x0, "", HFILL} },
	  { &hf_name_length,  { "Username length", "4c.namelength",  FT_UINT32, BASE_DEC,  NULL,               0x0, "", HFILL} },
	  { &hf_pw_length,    { "Password length", "4c.pwlength",    FT_UINT32, BASE_DEC,  NULL,               0x0, "", HFILL} },
	  { &hf_start,        { "Player",          "4c.start",       FT_UINT32, BASE_DEC,  NULL,               0x0, "", HFILL} },
	  { &hf_peer_address, { "Peer address",    "4c.peeraddress", FT_IPv4,   BASE_NONE, NULL,               0x0, "", HFILL} },
	  { &hf_name,         { "User Name",       "4c.username",    FT_STRING, BASE_NONE, NULL,               0x0, "", HFILL} },
	  { &hf_pw,           { "User Password",   "4c.password",    FT_STRING, BASE_NONE, NULL,               0x0, "", HFILL} }
	};

	static gint *ett[] = {
	&ett_4c,
	};

	module_t *four_c_module;

	proto_4c = proto_register_protocol("Four Connect", "4C", "4c");

	proto_register_field_array(proto_4c, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	four_c_module = prefs_register_protocol(proto_4c, NULL);
	prefs_register_bool_preference(four_c_module, 
	                               "desegment_4c_messages",
	                               "Desegment all 4C messages spanning multiple TCP segments",
	                               "Whether the 4C dissector should desegment all messages spanning multiple TCP segments",
	                               &four_c_desegment);
}

void
proto_reg_handoff_4c(void)
{
	//dissector_handle_t four_c_sctp_handle;
	//dissector_handle_t four_c_tcp_handle;
	//dissector_handle_t four_c_udp_handle;

	//four_c_sctp_handle = create_dissector_handle(dissect_4c_sctp, proto_4c);
	//four_c_tcp_handle  = create_dissector_handle(dissect_4c_tcp,  proto_4c);
	//four_c_udp_handle  = create_dissector_handle(dissect_4c_udp,  proto_4c);

	//dissector_add("sctp.port", SCTP_PORT_4C, four_c_sctp_handle);
	//dissector_add("tcp.port",  TCP_PORT_4C,  four_c_tcp_handle);
	//dissector_add("udp.port",  UDP_PORT_4C,  four_c_udp_handle);
}

