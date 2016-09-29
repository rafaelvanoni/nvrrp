/*
 * This file is part of the nvrrp project (https://launchpad.net/nvrrp/)
 *
 * Copyright (C) 2016   Pluribus Networks
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <time.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <bsd/string.h>
#include <ctype.h>

#define	VRRP_CONF_DIR		"/etc/nvrrp"
#define	VRRP_LOG_FILE		"/var/log/nvrrp.log"
#define	VRRP_LOG_FILE_PREV	"/var/log/nvrrp.log.prev"
#define	VRRP_UNIX_SOCKET	"/tmp/nvrrp.unix.socket"

#define	IFNAME_LEN		(16)
#define	IP_STRING_LEN		(16)
#define	MAC_ADDR_LEN		(6)
#define	MAC_STRING_LEN		(18)
#define	MAX_NUM_VRRP_INTF	(256)
#define	MAX_FNAME_LEN		(64)
#define	IP_BUF_LEN		(64)

#define	VRRP_LOG_MAXSZ		(1 << 23)	/* 8Mb in bytes */
#define	VRRP_NFDS		(MAX_NUM_VRRP_INTF * 5)
#define	VRRP_CTRL_MAXCONN	(32)

#define	NANOSEC			(1000000000ll)	/* nanosecs in a sec */
#define	CENTISEC		(10000000ll)	/* nanosecs in a centisec */
#define	MILLISEC		(1000000ll)	/* nanosecs in a millisec */
#define	MICROSEC		(1000ll)	/* nanosecs in a microsec */

/*
 * These are here to pacify cstyle checks..
 */
/* CSTYLED */
typedef u_short			ushort_t;
/* CSTYLED */
typedef u_char			uchar_t;

typedef enum {
	B_FALSE			= 0,
	B_TRUE			= 1
} boolean_t;

typedef unsigned int		intf_index_t;
typedef uint8_t			vrid_t;		/* [1..255] */
typedef uint8_t			prio_t;		/* [1..254], 0 and 255 reserv */
typedef	uint8_t			adv_int_t;
typedef int			socket_t;

#define	VRRP_MCAST_ADDRv4	"224.0.0.18"
#define	VRRP_MCAST_HEXv4	(0xe0000012)
#define	VRRP_MAC_ADDRv4		"00:00:5E:00:01:%02x"
#define	VRRP_IP_VERSION		(4)

#define	VRRP_TTL		(255)
#define	VRRP_PROTOCOL		(112)

/*
 * VRRPv2 and v3 only defines one packet type, '1' for 'advertisement'.
 */
typedef enum {
	VRRP_PKT_ADVERT		= 1
} vrrp_pkt_type_t;

/*
 * Priority value for the VRRP router that owns the IP addr(s) associated
 * with a given vrid.
 */
#define	VRRP_PRIO_OWNER		(255)

/*
 * Default priority for VRRP routers backing up a virtual router.
 */
#define	VRRP_PRIO_DEFAULT	(100)

/*
 * Special priority to indicate that the current master has gone south and to
 * trigger the election of a backup router w/o waiting for the master to return.
 */
#define	VRRP_PRIO_ZERO		(0)

/*
 * Authentication types per RFC 3768. We don't currently support any, or only
 * support type 0.
 */
typedef enum {
	VRRP_AUTH_TYPE0		= 0,
	VRRP_AUTH_TYPE1		= 1,
	VRRP_AUTH_TYPE2		= 2
} vrrp_auth_type_t;

/*
 * Default advertisement interval in nanosseconds.
 */
#define	VRRP_ADV_INT_DEFAULT	(NANOSEC)
#define	VRRP_ADV_INT_MIN	(NANOSEC)
#define	VRRP_ADV_INT_MAX	(NANOSEC * 10)

typedef struct {
	uint8_t			vpkt_type_vers;
	vrid_t			vpkt_vrid;
	prio_t			vpkt_priority;
	uint8_t			vpkt_addr_count;
	uint8_t			vpkt_auth_type;
	adv_int_t		vpkt_adv_interval;
	uint16_t		vpkt_csum;
} vrrp_pkt_t;

/*
 * For simplicity, this macro indicates the size of the VRRP packet structure
 * with a single virtual address and no authentication data.
 */
#define	VRRP_PKT_LEN		(sizeof (vrrp_pkt_t) + sizeof (struct in_addr))

/*
 * Pseudo headers for IPv4 and IPv6 used in checksum calculations.
 */
typedef struct {
	uint32_t		vps4_src;
	uint32_t		vps4_dst;
	uint8_t			vps4_zero;	/* always zero */
	uint8_t			vps4_protocol;	/* VRRP_PROTOCOL */
	uint16_t		vps4_len;	/* VRRP payload len */
} vrrp_pseudo_v4hdr_t;

typedef struct timespec		vrrp_time_t;

typedef enum {
	VRRP_VERSION_2		= 2,
	VRRP_VERSION_3		= 3
} vrrp_version_t;

typedef enum {
	VRRP_INITIAL		= 1,	/* wait for startup event */
	VRRP_SLAVE		= 2,	/* monitor state of master router */
	VRRP_MASTER		= 3,	/* function as the forwarding router */
	VRRP_SHUTDOWN		= 4	/* exiting.. */
} vrrp_state_t;

/*
 * Indicates whether a impl structure is free, being used or should be
 * deleted (and its configuration undone).
 */
typedef enum {
	IMPL_FREE		= 1,	/* or unused, available */
	IMPL_INUSE		= 2,	/* in use and loaded */
	IMPL_EXIT		= 3 	/* session is being terminated */
} impl_state_t;

/*
 * Indicates any differences between two impl structures.
 */
typedef enum {
	IMPL_CMP_PRIM		= 1,	/* different vi_primary interface */
	IMPL_CMP_VIP		= 2,	/* different vi_vip interface */
	IMPL_CMP_VRID		= 3,	/* different vrid */
	IMPL_CMP_VRRP		= 4,	/* different VRRP setting(s) */
	IMPL_CMP_SAME		= 5	/* no differences */
} impl_cmp_t;

/*
 * Return values for vrrp_find_and_lock().
 */
typedef enum {
	IMPL_FIND_NONE		= 1,	/* didn't find a matching impl */
	IMPL_FIND_INVAL		= 2,	/* primary or vip already in use */
	IMPL_FIND_LOCKED	= 3	/* found and returned a locked impl */
} impl_find_t;

/*
 * Interface specification and implementation fields.
 */
typedef struct {
	char			intf_name[IFNAME_LEN];
	char			intf_addr_str[IP_STRING_LEN];
	struct in_addr		intf_addr;
	struct in_addr		intf_netmask;
	char			intf_mac_addr[MAC_ADDR_LEN];
	char			intf_mac_str[MAC_STRING_LEN];
	intf_index_t		intf_index;
	socket_t		intf_mgmt;
	socket_t		intf_mcast;
} intf_t;

/*
 * Internal representation of a VRRP interface with all the data required for
 * its implementation.
 */
typedef struct {
	pthread_rwlock_t	vi_rwlock;
	pthread_t		vi_thread;
	impl_state_t		vi_impl_state;
	char			vi_file[MAX_FNAME_LEN];
	intf_t			vi_primary;
	intf_t			vi_vip;
	vrrp_version_t		vi_version;
	vrrp_state_t		vi_state;
	vrid_t			vi_vrid;
	prio_t			vi_priority;
	int64_t			vi_adv_interval;
	boolean_t		vi_allow_preemption;
	/*
	 * Current master's advertisement interval in nanoseconds. Used in
	 * slave mode to calculate vi_master_down_interval and vi_skew_time.
	 * Initialized to vi_adv_interval.
	 */
	int64_t			vi_master_adv_interval;
	/*
	 * Interval in nanoseconds for backup to declare master as down.
	 *   (( 3 * vi_master_adv_interval ) + vi_skew_time )
	 */
	int64_t			vi_master_down_interval;
	/*
	 * Time to skew vi_master_down_interval in nanoseconds.
	 *   ((( 256 - vis_priority ) * vi_master_adv_interval ) / 256 )
	 */
	int64_t			vi_skew_time;

	vrrp_time_t		vi_timer_adv;
	vrrp_time_t		vi_timer_mdown;

	uint16_t		vi_iphdr_id;

	uint64_t		vi_counter_s2m;
	uint64_t		vi_counter_m2s;
	uint64_t		vi_counter_s2i;
	uint64_t		vi_counter_m2i;
	uint64_t		vi_counter_recvd;
	uint64_t		vi_counter_sent;
	uint64_t		vi_counter_err;
} vrrp_impl_t;

/*
 * Commands that can be issued to the daemon.
 */
typedef enum {
	CTRL_RELOAD		= 1,
	CTRL_SHOW		= 2,
	CTRL_SUMMARY		= 3,
	CTRL_VIP_STATE		= 4,
	CTRL_QUIT		= 5,
	CTRL_CLEAR_COUNTERS	= 6
} ctrl_msg_t;

/*
 * Message structure for daemon/client communication.
 */
typedef struct {
	ctrl_msg_t		vcm_msg;
	char			vcm_buf[512];
} vrrp_ctrl_msg_t;

/*
 * This structure is half declared in <linux/if_arp.h> but with the ethernet
 * portion ifdef'ed out. We need it for the gratuitous ARP packet.
 */
typedef struct {
	uint16_t	ar_hrd;			/* format of hardware addr */
	uint16_t	ar_pro;			/* format of protocol addr */
	uchar_t		ar_hln;			/* length of hardware addr */
	uchar_t		ar_pln;			/* length of protocol addr */
	uint16_t	ar_op;			/* ARP opcode (command) */
	/*
	 * Ethernet looks like this : This bit is variable sized however...
	 */
	uchar_t		ar_sha[ETH_ALEN];	/* sender hardware addr */
	uchar_t		ar_sip[4];		/* sender IP addr */
	uchar_t		ar_tha[ETH_ALEN];	/* target hardware addr */
	uchar_t		ar_tip[4];		/* target IP addr */
} arphdr_t;

/*
 * Determines whether vrrp_setsockopt() should check a string or a binary value.
 */
typedef enum {
	VSC_STRING	= 1,
	VSC_BIN		= 2
} vrrp_setso_cmp_t;

/*
 * Log levels.
 */
typedef enum {
	LOG_ERR		= 0x1,
	LOG_INFO	= 0x2,
	LOG_DAEMON	= 0x4
} log_level_t;
