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

#include "nvrrp.h"

static char *vrrp_usage_str = "usage: nvrrp "
	"[ -r | -s | -S | -v [vip] | -q | -c | -V | -l [level] | -h ]\n"
	"   -r          reload configuration\n"
	"   -s          show complete state\n"
	"   -S          show summary of current sessions\n"
	"   -v [vip]    show the state of a given vip interface\n"
	"   -q          quit the nvrrp daemon\n"
	"   -c          clear state counters\n"
	"   -V          show the current version\n"
	"   -l [level]  change the log level (1 or 2)\n"
	"   -h          show this help message";

static pthread_rwlock_t		vrrp_list_rwlock;
static vrrp_session_t		vrrp_session_array[MAX_NUM_VRRP_INTF];
static boolean_t		vrrp_daemon = B_FALSE;
static volatile boolean_t	vrrp_shutdown = B_FALSE;
static socket_t			vrrp_unix_socket = 0;
static socket_t			vrrp_garp_socket = 0;
static uint16_t			vrrp_inuse_cnt = 0;

static pthread_mutex_t		vrrp_log_mutex;
static log_level_t		vrrp_log_level = LOG_INFO;
static FILE			*vrrp_log_fp = NULL;

void
vrrp_log(log_level_t, const char *, ...)
    __attribute__((format(printf, 2, 3)));

void
vrrp_quit(const char *, ...)
    __attribute__((format(printf, 1, 2)));

/*
 * These rwlock wrappers are inlined so that assert failures point to the caller
 * rather than these leaf routines.
 */
static inline void
vrrp_rwlock_rdlock(pthread_rwlock_t *lock)
{
	int ret = pthread_rwlock_rdlock(lock);
	assert(ret == 0);
}

static inline void
vrrp_rwlock_wrlock(pthread_rwlock_t *lock)
{
	int ret = pthread_rwlock_wrlock(lock);
	assert(ret == 0);
}

static inline void
vrrp_rwlock_unlock(pthread_rwlock_t *lock)
{
	int ret = pthread_rwlock_unlock(lock);
	assert(ret == 0);
}

/*
 * Log to stdout if in 'client' mode or if the log file hasn't been opened yet.
 * When in daemon mode, log to the log file itself.
 */
void
vrrp_log(log_level_t level, const char *arg_fmt, ...)
{
	va_list		args;
	FILE		*stream;
	time_t		tval;
	struct tm	tm;
	char		time_buf[32];

	pthread_mutex_lock(&vrrp_log_mutex);

	if (!(vrrp_log_level & level)) {
		pthread_mutex_unlock(&vrrp_log_mutex);
		return;
	}

	if (!vrrp_daemon) {
		stream = stdout;
	} else {
		if (vrrp_log_fp == NULL &&
		    (vrrp_log_fp = fopen(VRRP_LOG_FILE, "a+")) == NULL) {
			perror("failed to open log");
			pthread_mutex_unlock(&vrrp_log_mutex);
			return;
		}

		if (ftello(vrrp_log_fp) > VRRP_LOG_MAXSZ) {
			(void) fclose(vrrp_log_fp);
			vrrp_log_fp = NULL;

			if (rename(VRRP_LOG_FILE, VRRP_LOG_FILE_PREV) != 0) {
				perror("failed to move log");
				pthread_mutex_unlock(&vrrp_log_mutex);
				return;
			}

			if ((vrrp_log_fp = fopen(VRRP_LOG_FILE,
			    "a+")) == NULL) {
				perror("failed to open log");
				pthread_mutex_unlock(&vrrp_log_mutex);
				return;
			}
		}

		stream = vrrp_log_fp;

		tzset();
		(void) time(&tval);

		if (localtime_r(&tval, &tm) != NULL &&
		    strftime(time_buf, sizeof (time_buf), "%x %X", &tm) != 0) {
			(void) fprintf(stream, "[%d %s] ", (int)getpid(),
			    time_buf);
		} else {
			(void) fprintf(stream, "[%d] ", (int)getpid());
		}

		switch (level) {
		case LOG_ERR:
			(void) fprintf(stream, "ERROR : ");
			break;
		case LOG_INFO:
			(void) fprintf(stream, "INFO : ");
			break;
		}
	}

	va_start(args, arg_fmt);
	(void) vfprintf(stream, arg_fmt, args);
	(void) vfprintf(stream, "\n", args);
	va_end(args);

	(void) fflush(stream);

	pthread_mutex_unlock(&vrrp_log_mutex);
}

char *
vrrp_state_str(vrrp_state_t state)
{
	switch (state) {
	case VRRP_INITIAL:
		return ("initial");
	case VRRP_SLAVE:
		return ("slave");
	case VRRP_MASTER:
		return ("master");
	case VRRP_SHUTDOWN:
		return ("shutdown");
	}
	return ("invalid state");
}

void
vrrp_intf_teardown(intf_t *intf)
{
	assert(intf != NULL);

	if (intf->intf_mgmt != -1) {
		(void) close(intf->intf_mgmt);
		intf->intf_mgmt = -1;
	}

	if (intf->intf_mcast != -1) {
		(void) close(intf->intf_mcast);
		intf->intf_mcast = -1;
	}

	(void) memset(intf, 0, sizeof (*intf));
}

void
vrrp_quit(const char *fmt, ...)
{
	va_list		args;
	char		buf[512];
	vrrp_session_t	*session;
	struct timespec	ts = { 0 };
	int64_t		start = NANOSEC/2, inc = NANOSEC/10, max = NANOSEC;
	int		iter = 30, ii, n, ret;

	assert(max > start);
	assert(start > inc);

	va_start(args, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, args);
	vrrp_log(LOG_INFO, "%s", buf);
	va_end(args);

	if (vrrp_daemon) {
		vrrp_shutdown = B_TRUE;
		ts.tv_nsec = start;

		do {
			vrrp_rwlock_rdlock(&vrrp_list_rwlock);

			if ((n = vrrp_inuse_cnt) == 0) {
				vrrp_rwlock_unlock(&vrrp_list_rwlock);
				break;
			}

			vrrp_rwlock_unlock(&vrrp_list_rwlock);
			vrrp_log(LOG_INFO, "waiting for %d instances", n);

			(void) nanosleep(&ts, NULL);

			if ((ts.tv_nsec += inc) >= max) {
				ts.tv_nsec = start;
				iter--;
			}

		} while (n != 0 && iter != 0);

		/*
		 * We haven't seen this yet, but it is possible that a session
		 * thread will get stuck in the kernel/driver and not shut
		 * down as we'd like.
		 */
		if (n != 0) {
			vrrp_log(LOG_ERR, "%d session(s) did not shutdown", n);

		} else {
			for (ii = 0; ii < MAX_NUM_VRRP_INTF; ii++) {
				session = &vrrp_session_array[ii];

				/*
				 * The following must be a result of shutting
				 * down each session thread.
				 */
				assert(session->vs_state == VRRP_SHUTDOWN ||
				    session->vs_session_state == SS_FREE);
				assert(session->vs_primary.intf_name[0] ==
				    '\0');
				assert(session->vs_vip.intf_name[0] == '\0');
				assert(session->vs_primary.intf_mgmt == -1);
				assert(session->vs_vip.intf_mgmt == -1);
				assert(session->vs_primary.intf_mcast == -1);
				assert(session->vs_vip.intf_mcast == -1);

				(void) pthread_rwlock_destroy(
				    &session->vs_rwlock);
			}

			if (vrrp_log_fp != NULL) {
				(void) fclose(vrrp_log_fp);
			}

			ret = pthread_mutex_destroy(&vrrp_log_mutex);
			assert(ret == 0);

			ret = pthread_rwlock_destroy(&vrrp_list_rwlock);
			assert(ret == 0);

			ret = close(vrrp_garp_socket);
			assert(ret == 0);

			ret = close(vrrp_unix_socket);
			assert(ret == 0);

			ret = unlink(VRRP_UNIX_SOCKET);
			assert(ret == 0);
		}
	}

	exit(EXIT_SUCCESS);
}

/*
 * Return the sum of the current and given time.
 */
static inline vrrp_time_t
vrrp_time_add(int64_t val)
{
	vrrp_time_t	curr;
	uint64_t	nsec;
	int		ret;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &curr);
	assert(ret == 0);

	nsec = (uint64_t)curr.tv_nsec + (uint64_t)val;

	if (nsec >= NANOSEC) {
		curr.tv_sec += nsec / NANOSEC;
		curr.tv_nsec = nsec % NANOSEC;
	} else {
		curr.tv_nsec = nsec;
	}

	return (curr);
}

/*
 * Return the difference between the current and the given time, or zero if the
 * latter has expired.
 */
static inline vrrp_time_t
vrrp_time_diff(vrrp_time_t ts)
{
	vrrp_time_t	curr;
	int		ret;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &curr);
	assert(ret == 0);

	if (curr.tv_sec > ts.tv_sec ||
	    (curr.tv_sec == ts.tv_sec && curr.tv_nsec >= ts.tv_nsec)) {
		return ((vrrp_time_t) {0, 0});
	}

	curr.tv_sec = ts.tv_sec - curr.tv_sec;
	assert(curr.tv_sec >= 0);

	if (curr.tv_nsec >= ts.tv_nsec) {
		curr.tv_nsec -= ts.tv_nsec;
	} else {
		curr.tv_nsec = NANOSEC - ts.tv_nsec;
	}

	return (curr);
}

static inline boolean_t
vrrp_time_elapsed(vrrp_time_t ts)
{
	vrrp_time_t	curr;
	int		ret;

	if (ts.tv_sec == 0 && ts.tv_nsec == 0) {
		return (B_FALSE);
	}

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &curr);
	assert(ret == 0);

	if (curr.tv_sec > ts.tv_sec) {
		return (B_TRUE);
	}

	if (curr.tv_sec == ts.tv_sec && curr.tv_nsec >= ts.tv_nsec) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Copy 'src' to 'dest', setting the VRRP state to initial and the session
 * state to SS_INUSE but leaving the lock alone.
 */
void
vrrp_session_inuse(vrrp_session_t *dest, vrrp_session_t *src)
{
	assert(dest != NULL);
	assert(src != NULL);

	(void) memcpy(dest->vs_file, src->vs_file, sizeof (dest->vs_file));
	(void) memcpy(&dest->vs_primary, &src->vs_primary,
	    sizeof (dest->vs_primary));
	(void) memcpy(&dest->vs_vip, &src->vs_vip, sizeof (dest->vs_vip));
	dest->vs_version = src->vs_version;
	dest->vs_vrid = src->vs_vrid;
	dest->vs_priority = src->vs_priority;
	dest->vs_adv_interval = src->vs_adv_interval;
	dest->vs_allow_preemption = src->vs_allow_preemption;
	dest->vs_master_adv_interval = src->vs_master_adv_interval;
	dest->vs_master_down_interval = src->vs_master_down_interval;
	dest->vs_skew_time = src->vs_skew_time;
	dest->vs_timer_adv = src->vs_timer_adv;
	dest->vs_timer_mdown = src->vs_timer_mdown;
	dest->vs_iphdr_id = src->vs_iphdr_id;
	dest->vs_counter_s2m = src->vs_counter_s2m;
	dest->vs_counter_m2s = src->vs_counter_m2s;
	dest->vs_counter_s2i = src->vs_counter_s2i;
	dest->vs_counter_m2i = src->vs_counter_m2i;
	dest->vs_counter_recvd = src->vs_counter_recvd;
	dest->vs_counter_sent = src->vs_counter_sent;
	dest->vs_counter_err = src->vs_counter_err;

	dest->vs_state = VRRP_INITIAL;
	dest->vs_session_state = SS_INUSE;
}

/*
 * Zero out the given session structure and mark it as free, but leave its
 * mutex alone (it's already been initialized).
 */
void
vrrp_session_clear(vrrp_session_t *session)
{
	assert(session != NULL);

	session->vs_thread = 0;
	session->vs_session_state = SS_FREE;
	(void) memset(session->vs_file, 0, sizeof (session->vs_file));
	(void) memset(&session->vs_primary, 0, sizeof (session->vs_primary));
	session->vs_primary.intf_mgmt = -1;
	session->vs_primary.intf_mcast = -1;
	(void) memset(&session->vs_vip, 0, sizeof (session->vs_vip));
	session->vs_vip.intf_mgmt = -1;
	session->vs_vip.intf_mcast = -1;
	session->vs_version = 0;
	session->vs_state = 0;
	session->vs_vrid = 0;
	session->vs_priority = 0;
	session->vs_adv_interval = 0;
	session->vs_allow_preemption = B_TRUE;
	session->vs_master_adv_interval = 0;
	session->vs_master_down_interval = 0;
	session->vs_skew_time = 0;
	session->vs_timer_adv = (vrrp_time_t) {0, 0};
	session->vs_timer_mdown = (vrrp_time_t) {0, 0};
	session->vs_iphdr_id = 0;
	session->vs_counter_s2m = 0;
	session->vs_counter_m2s = 0;
	session->vs_counter_s2i = 0;
	session->vs_counter_m2i = 0;
	session->vs_counter_recvd = 0;
	session->vs_counter_sent = 0;
	session->vs_counter_err = 0;
}

/*
 * Compares two session structures, returning zero if they're the same, minus
 * one if any of the interfaces have changed or one if only something in the
 * VRRP configuration changed. Note that this is called before the
 * implementation specific fields of either interface are populated.
 */
session_cmp_t
vrrp_session_cmp(vrrp_session_t *a, vrrp_session_t *b)
{
	intf_t		*ap, *av, *bp, *bv;

	assert(a != NULL);
	assert(b != NULL);
	assert(memcmp(a->vs_file, b->vs_file, sizeof (a->vs_file)) == 0);
	assert(a->vs_version == b->vs_version);

	ap = &a->vs_primary;
	bp = &b->vs_primary;

	if (strcmp(ap->intf_name, bp->intf_name) != 0) {
		return (SC_PRIM);
	}

	av = &a->vs_vip;
	bv = &b->vs_vip;

	if (strcmp(av->intf_name, bv->intf_name) != 0 ||
	    strcmp(av->intf_addr_str, bv->intf_addr_str) != 0) {
		return (SC_VIP);
	}

	if (a->vs_vrid != b->vs_vrid) {
		return (SC_VRID);
	}

	if (a->vs_priority != b->vs_priority ||
	    a->vs_adv_interval != b->vs_adv_interval ||
	    a->vs_allow_preemption != b->vs_allow_preemption) {
		return (SC_VRRP);
	}

	return (SC_SAME);
}

void
vrrp_show_session(vrrp_session_t *session)
{
	char	prim_addr[IP_STRING_LEN], vip_addr[IP_STRING_LEN];
	char	prim_nmask[IP_STRING_LEN], vip_nmask[IP_STRING_LEN];
	int	pad = 18;

	assert(session != NULL);

	if (inet_ntop(AF_INET, &session->vs_primary.intf_addr,
	    prim_addr, sizeof (prim_addr)) == NULL) {
		vrrp_log(LOG_ERR, "failed to convert primary address to string"
		    " on %s", session->vs_file);
		return;
	}

	if (inet_ntop(AF_INET, &session->vs_primary.intf_netmask,
	    prim_nmask, sizeof (prim_nmask)) == NULL) {
		vrrp_log(LOG_ERR, "failed to convert primary netmask to string"
		    " on %s", session->vs_file);
		return;
	}

	if (inet_ntop(AF_INET, &session->vs_vip.intf_addr,
	    vip_addr, sizeof (vip_addr)) == NULL) {
		vrrp_log(LOG_ERR, "failed to convert vip address to string"
		    " on %s", session->vs_file);
		return;
	}

	if (inet_ntop(AF_INET, &session->vs_vip.intf_netmask,
	    vip_nmask, sizeof (vip_nmask)) == NULL) {
		vrrp_log(LOG_ERR, "failed to convert vip netmask to string"
		    " on %s", session->vs_file);
		return;
	}

	vrrp_log(LOG_INFO,
	    "%*s %s\n"		/* filename */
	    "%*s %s\n" 		/* primary intf */
	    "%*s %s\n" 		/* primary IP */
	    "%*s %s\n" 		/* primary addr */
	    "%*s %s\n" 		/* primary netmask */
	    "%*s %s\n" 		/* primary MAC */
	    "%*s %u\n" 		/* primary idx */
	    "%*s %s\n" 		/* vip intf */
	    "%*s %s\n" 		/* vip IP */
	    "%*s %s\n" 		/* vip addr */
	    "%*s %s\n" 		/* vip netmask */
	    "%*s %s\n" 		/* vip MAC */
	    "%*s %u\n" 		/* vip idx */
	    "%*s %u\n" 		/* vrid */
	    "%*s %u\n" 		/* priority */
	    "%*s %ld\n"		/* adv interval */
	    "%*s %ld\n"		/* master adv int */
	    "%*s %ld\n"		/* master down int */
	    "%*s %ld\n"		/* skew time */
	    "%*s %ld %ld\n"	/* timer adv */
	    "%*s %ld %ld\n"	/* timer mdown */
	    "%*s %u\n"		/* iphdr id */
	    "%*s %s\n" 		/* version */
	    "%*s %s\n" 		/* state */
	    "%*s %s\n"		/* allow preempt */
	    "%*s %lu\n"		/* slave to master transitions */
	    "%*s %lu\n"		/* master to slave transitions */
	    "%*s %lu\n"		/* slave to initial transitions */
	    "%*s %lu\n"		/* master to initial transitions */
	    "%*s %lu\n"		/* number of received advertisements */
	    "%*s %lu\n"		/* number of advertisements sent */
	    "%*s %lu\n",	/* number of send errors */
	    pad, "filename", session->vs_file,
	    pad, "primary intf", session->vs_primary.intf_name,
	    pad, "primary IP", session->vs_primary.intf_addr_str,
	    pad, "primary addr", prim_addr,
	    pad, "primary netmask", prim_nmask,
	    pad, "primary MAC", session->vs_primary.intf_mac_str,
	    pad, "primary idx", session->vs_primary.intf_index,
	    pad, "vip intf", session->vs_vip.intf_name,
	    pad, "vip IP", session->vs_vip.intf_addr_str,
	    pad, "vip addr", vip_addr,
	    pad, "vip netmask", vip_nmask,
	    pad, "vip MAC", session->vs_vip.intf_mac_str,
	    pad, "vip idx", session->vs_vip.intf_index,
	    pad, "vrid", session->vs_vrid,
	    pad, "priority", session->vs_priority,
	    pad, "adv interval", session->vs_adv_interval,
	    pad, "master adv int", session->vs_master_adv_interval,
	    pad, "master down int", session->vs_master_down_interval,
	    pad, "skew time", session->vs_skew_time,
	    pad, "timer adv", session->vs_timer_adv.tv_sec,
	    session->vs_timer_adv.tv_nsec,
	    pad, "timer mdown", session->vs_timer_mdown.tv_sec,
	    session->vs_timer_mdown.tv_nsec,
	    pad, "iphdr id", session->vs_iphdr_id,
	    pad, "version", session->vs_version == VRRP_VERSION_2 ? "2" : "3",
	    pad, "state", vrrp_state_str(session->vs_state),
	    pad, "allow preempt", session->vs_allow_preemption ? "yes" : "no",
	    pad, "slave to master", session->vs_counter_s2m,
	    pad, "master to slave", session->vs_counter_m2s,
	    pad, "slave to initial", session->vs_counter_s2i,
	    pad, "master to initial", session->vs_counter_m2i,
	    pad, "adverts recvd", session->vs_counter_recvd,
	    pad, "adverts sent", session->vs_counter_sent,
	    pad, "send errors", session->vs_counter_err);
}

void
vrrp_show_pkt(vrrp_pkt_t *vpkt, struct in_addr src_addr)
{
	int	pad = 18;

	assert(vpkt != NULL);

	vrrp_log(LOG_INFO,
	    "%*s %u\n" /* type */
	    "%*s %u\n" /* version */
	    "%*s %u\n" /* vrid */
	    "%*s %u\n" /* priority */
	    "%*s %u\n" /* addr count */
	    "%*s %u\n" /* auth type */
	    "%*s %lld\n" /* adv interval */
	    "%*s %x\n" /* csum */
	    "%*s %s", /* sender */
	    pad, "type", vpkt->vpkt_type_vers & 0xf,
	    pad, "version", vpkt->vpkt_type_vers >> 4,
	    pad, "vrid", vpkt->vpkt_vrid,
	    pad, "priority", vpkt->vpkt_priority,
	    pad, "addr count", vpkt->vpkt_addr_count,
	    pad, "auth type", vpkt->vpkt_auth_type,
	    pad, "adv interval", vpkt->vpkt_adv_interval * CENTISEC,
	    pad, "csum", vpkt->vpkt_csum,
	    pad, "src", inet_ntoa(src_addr));
}

/*
 * Return the first empty intf_session with its rwlock held.
 */
vrrp_session_t *
vrrp_alloc(void)
{
	vrrp_session_t	*session;
	int		ii;

	vrrp_rwlock_wrlock(&vrrp_list_rwlock);

	for (ii = 0; ii < MAX_NUM_VRRP_INTF; ii++) {
		session = &vrrp_session_array[ii];
		vrrp_rwlock_wrlock(&session->vs_rwlock);

		if (session->vs_session_state == SS_FREE) {
			break;
		}
		vrrp_rwlock_unlock(&session->vs_rwlock);
	}

	vrrp_rwlock_unlock(&vrrp_list_rwlock);

	if (ii == MAX_NUM_VRRP_INTF) {
		session = NULL;
	}

	return (session);
}

/*
 * Return the current state of the given VRRP interface or zero (an invalid
 * state) if one isn't found.
 */
vrrp_state_t
vrrp_get_state(char *vip)
{
	vrrp_session_t	*session;
	vrrp_state_t	state;
	int		ii;

	assert(vip != NULL);

	vrrp_rwlock_rdlock(&vrrp_list_rwlock);

	for (ii = 0; ii < MAX_NUM_VRRP_INTF; ii++) {
		session = &vrrp_session_array[ii];
		vrrp_rwlock_rdlock(&session->vs_rwlock);

		if (strncmp(session->vs_vip.intf_name, vip,
		    sizeof (session->vs_vip.intf_name)) == 0) {
			state = session->vs_state;
			vrrp_rwlock_unlock(&session->vs_rwlock);
			vrrp_rwlock_unlock(&vrrp_list_rwlock);
			return (state);
		}

		vrrp_rwlock_unlock(&session->vs_rwlock);
	}

	vrrp_rwlock_unlock(&vrrp_list_rwlock);

	return (0);
}

/*
 * Clear all the counters.
 */
void
vrrp_clear_counters(void)
{
	vrrp_session_t	*session;
	int		ii;

	vrrp_rwlock_rdlock(&vrrp_list_rwlock);

	for (ii = 0; ii < MAX_NUM_VRRP_INTF; ii++) {
		session = &vrrp_session_array[ii];
		vrrp_rwlock_rdlock(&session->vs_rwlock);

		if (session->vs_session_state != SS_FREE) {
			session->vs_counter_s2m = 0;
			session->vs_counter_m2s = 0;
			session->vs_counter_s2i = 0;
			session->vs_counter_m2i = 0;
			session->vs_counter_recvd = 0;
			session->vs_counter_sent = 0;
			session->vs_counter_err = 0;
		}

		vrrp_rwlock_unlock(&session->vs_rwlock);
	}

	vrrp_rwlock_unlock(&vrrp_list_rwlock);
}

session_find_t
vrrp_find_and_lock(char *filename, char *primary, char *vip,
    vrrp_session_t **ret_session)
{
	vrrp_session_t	*session;
	int		ii, ret;

	assert(filename != NULL);
	assert(primary != NULL);
	assert(vip != NULL);

	/*
	 * First try to find an session with the given filename.
	 */
	vrrp_rwlock_rdlock(&vrrp_list_rwlock);

	for (ii = 0; ii < MAX_NUM_VRRP_INTF; ii++) {
		session = &vrrp_session_array[ii];
		vrrp_rwlock_rdlock(&session->vs_rwlock);

		if (session->vs_session_state != SS_FREE) {
			if (strcasecmp(session->vs_file, filename) == 0) {
				break;
			}
		}

		vrrp_rwlock_unlock(&session->vs_rwlock);
		session = NULL;
	}

	if (session != NULL) {
		pthread_rwlock_unlock(&vrrp_list_rwlock);
		*ret_session = session;

		return (SF_LOCKED);
	}

	ret = SF_NONE;

	/*
	 * Didn't find one. Take a moment to check if we're trying to use either
	 * primary or VRRP interfaces that are already in use.
	 */
	for (ii = 0; ii < MAX_NUM_VRRP_INTF; ii++) {
		session = &vrrp_session_array[ii];
		vrrp_rwlock_rdlock(&session->vs_rwlock);

		if (session->vs_session_state != SS_FREE) {
			if (strcasecmp(session->vs_primary.intf_name,
			    primary) == 0) {
				vrrp_rwlock_unlock(&session->vs_rwlock);
				ret = SF_INVAL;
				break;
			}
			if (strcasecmp(session->vs_vip.intf_name, vip) == 0) {
				vrrp_rwlock_unlock(&session->vs_rwlock);
				ret = SF_INVAL;
				break;
			}
		}

		vrrp_rwlock_unlock(&session->vs_rwlock);
		session = NULL;
	}

	vrrp_rwlock_unlock(&vrrp_list_rwlock);

	return (ret);
}

int
vrrp_strtoul(char *buf, uint64_t *ret)
{
	char		*ptr, *end;
	uint64_t	val;

	assert(buf != NULL);
	assert(buf[0] != '\0');

	if (*(ptr = &buf[strlen(buf) - 1]) == '\n') {
		*ptr = '0';
	}

	errno = 0;
	val = (uint64_t)strtoul(buf, &end, 10);

	if (end == buf || *end != '\0') {
		return (EINVAL);

	} else if (val == ULONG_MAX && errno == ERANGE) {
		return (ERANGE);
	}

	*ret = (int)val;

	return (0);
}

ushort_t
in_csum(ushort_t *addr, int len, int csum, int *acc)
{
	register int		nleft = len;
	const ushort_t		*w = addr;
	register ushort_t	answer;
	register int		sum = csum;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= sizeof (*w);
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		sum += htons(*(uchar_t *)w << 8);
	}
	if (acc) {
		*acc = sum;
	}
	/*
	 * Add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

int
vrrp_setsockopt(int sock, int level, int opt, void *arg, void *chk,
    socklen_t len, vrrp_setso_cmp_t cmp)
{
	socklen_t	ret_len = len;
	struct timeval	*tv;

	if (setsockopt(sock, level, opt, arg, len) < 0) {
		vrrp_log(LOG_ERR, "failed to setsockopt (%s)", strerror(errno));
		return (-1);
	}

	if (getsockopt(sock, level, opt, chk, &ret_len) < 0) {
		vrrp_log(LOG_ERR, "failed to getsockopt (%s)", strerror(errno));
		return (-1);
	}

	switch (cmp) {
	case VSC_STRING:
		if (strlen((char *)arg) + 1 != ret_len) {
			vrrp_log(LOG_ERR, "setopt and getopt len (%d, %d)",
			    (int)strlen((char *)arg), ret_len);
			return (-2);
		}

		if (strcmp(arg, chk) != 0) {
			vrrp_log(LOG_ERR, "setopt and getopt differ");
			return (-3);
		}
		break;

	case VSC_BIN:
		if (len != ret_len) {
			vrrp_log(LOG_ERR, "setopt and getopt len (%d, %d)",
			    len, ret_len);
			return (-2);
		}

		if (memcmp(arg, chk, len) != 0) {
			/*
			 * There's some amount of jitter for SO_RCVTIMEO calls
			 * so we just check that the returned timespec isn't
			 * zero.
			 */
			if (opt == SO_RCVTIMEO) {
				tv = (struct timeval *)chk;

				if (tv->tv_sec != 0 || tv->tv_usec != 0) {
					break;
				}
			}
			vrrp_log(LOG_ERR, "setsockopt and getsockopt differ");
			return (-3);
		}
		break;
	}

	return (0);
}

boolean_t
vrrp_intf_is_up(intf_t *intf)
{
	const short	fl = (IFF_UP | IFF_RUNNING);
	struct ifreq	ifr = {{{ 0 }}};

	(void) strlcpy(ifr.ifr_name, intf->intf_name, sizeof (ifr.ifr_name));

	if (ioctl(intf->intf_mgmt, SIOCGIFFLAGS, &ifr) != 0) {
		vrrp_log(LOG_ERR, "failed to get flags for %s (%s)",
		    ifr.ifr_name, strerror(errno));
		return (B_FALSE);
	}

	return ((ifr.ifr_flags & fl) == fl);
}

int
vrrp_intf_down(intf_t *intf)
{
	struct ifreq	ifr = {{{ 0 }}};

	(void) strlcpy(ifr.ifr_name, intf->intf_name, sizeof (ifr.ifr_name));

	if (ioctl(intf->intf_mgmt, SIOCGIFFLAGS, &ifr) != 0) {
		vrrp_log(LOG_ERR, "failed to get flags for %s (%s)",
		    ifr.ifr_name, strerror(errno));
		return (EIO);

	} else if ((ifr.ifr_flags & (IFF_UP | IFF_RUNNING)) != 0) {
		ifr.ifr_flags = ifr.ifr_flags & ~(IFF_UP | IFF_RUNNING);

		if (ioctl(intf->intf_mgmt, SIOCSIFFLAGS, &ifr) != 0) {
			vrrp_log(LOG_ERR, "failed to set intf %s down (%s)",
			    ifr.ifr_name, strerror(errno));
			return (EIO);
		}
	}

	return (0);
}

/*
 * Set the interface's address (if not set already) then bring it up (if not
 * already).
 */
int
vrrp_intf_up(intf_t *intf)
{
	struct ifreq		ifr = {{{ 0 }}};
	int			flags = (IFF_UP | IFF_RUNNING);
	struct in_addr		*sa;

	(void) strlcpy(ifr.ifr_name, intf->intf_name, sizeof (ifr.ifr_name));

	if (ioctl(intf->intf_mgmt, SIOCGIFADDR, &ifr) != 0 &&
	    errno != EADDRNOTAVAIL) {
		vrrp_log(LOG_ERR, "failed to get addr for %s (%s)",
		    ifr.ifr_name, strerror(errno));
		return (EIO);

	} else {
		sa = &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

		if (sa->s_addr != intf->intf_addr.s_addr) {
			ifr.ifr_addr.sa_family = AF_INET;
			sa->s_addr = intf->intf_addr.s_addr;

			if (ioctl(intf->intf_mgmt, SIOCSIFADDR, &ifr) != 0) {
				vrrp_log(LOG_ERR,
				    "failed to set addr on %s (%s)",
				    ifr.ifr_name, strerror(errno));
				return (EIO);
			}

			sa->s_addr = intf->intf_netmask.s_addr;

			if (ioctl(intf->intf_mgmt, SIOCSIFNETMASK, &ifr) != 0) {
				vrrp_log(LOG_ERR,
				    "failed to set netmask on %s (%s)",
				    ifr.ifr_name, strerror(errno));
				return (EIO);
			}
		}
	}

	if (ioctl(intf->intf_mgmt, SIOCGIFFLAGS, &ifr) != 0) {
		vrrp_log(LOG_ERR, "failed to get mgmt flags for %s (%s)",
		    ifr.ifr_name, strerror(errno));
		return (EIO);

	} else if ((ifr.ifr_flags & flags) != flags) {
		ifr.ifr_flags = ifr.ifr_flags | flags;

		if (ioctl(intf->intf_mgmt, SIOCSIFFLAGS, &ifr) != 0) {
			vrrp_log(LOG_ERR, "failed to set intf %s up (%s)",
			    ifr.ifr_name, strerror(errno));
			return (EIO);
		}
	}

	return (0);
}

int
vrrp_intf_setup_vip(intf_t *vip)
{
	struct ip_mreqn	mr = {{ 0 }}, mr_ret;
	int		ret, so_val, so_ret;
	char		buf[IFNAME_LEN];

	if ((ret = vrrp_intf_up(vip)) != 0) {
		return (ret);
	}

	if (vrrp_setsockopt(vip->intf_mcast, SOL_SOCKET, SO_BINDTODEVICE,
	    (void *)vip->intf_name, &buf, sizeof (vip->intf_name),
	    VSC_STRING) < 0) {
		vrrp_log(LOG_ERR, "failed to bind mcast socket on %s",
		    vip->intf_name);
		return (EIO);
	}

	mr.imr_ifindex = vip->intf_index;

	if (vrrp_setsockopt(vip->intf_mcast, IPPROTO_IP, IP_MULTICAST_IF,
	    &mr, &mr_ret, sizeof (mr.imr_ifindex), VSC_BIN) < 0) {
		vrrp_log(LOG_ERR, "failed to set multicast if on %s",
		    vip->intf_name);
		return (EIO);
	}

	so_val = 1;

	if (vrrp_setsockopt(vip->intf_mcast, IPPROTO_IP, IP_HDRINCL, &so_val,
	    (void *)&so_ret, sizeof (so_val), VSC_BIN) < 0) {
		vrrp_log(LOG_ERR, "failed to set header incl on %s",
		    vip->intf_name);
		return (EIO);
	}

	so_val = 0;

	if (vrrp_setsockopt(vip->intf_mcast, IPPROTO_IP, IP_MULTICAST_ALL,
	    &so_val, &so_ret, sizeof (so_val), VSC_BIN) < 0) {
		vrrp_log(LOG_ERR, "failed to turn mcast all off on %s",
		    vip->intf_name);
		return (EIO);
	}

	if (vrrp_setsockopt(vip->intf_mcast, IPPROTO_IP, IP_MULTICAST_LOOP,
	    &so_val, &so_ret, sizeof (so_val), VSC_BIN) < 0) {
		vrrp_log(LOG_ERR, "failed to turn mcast loop off on %s",
		    vip->intf_name);
		return (EIO);
	}

	return (0);
}

int
vrrp_bcast_garp(vrrp_session_t *session)
{
	char			buf[sizeof (arphdr_t) + ETH_HLEN] = { 0 };
	struct sockaddr_ll	dest = { 0 };
	struct ether_header	*ehdr;
	arphdr_t		*arphdr;
	char			*mac_addr = session->vs_vip.intf_mac_addr;
	struct in_addr		vip_addr = session->vs_vip.intf_addr;

	/*
	 * Assert that our intf_mac_addr is the expected length according to
	 * the cryptic ETH_ALEN macro.
	 */
	assert(MAC_ADDR_LEN == ETH_ALEN);
	assert(vrrp_garp_socket != -1);

	dest.sll_family = AF_PACKET;
	dest.sll_ifindex = session->vs_vip.intf_index;
	(void) memcpy(&dest.sll_addr, mac_addr, sizeof (dest.sll_addr));
	dest.sll_halen = MAC_ADDR_LEN;

	ehdr = (struct ether_header *)buf;
	ehdr->ether_type = htons(ETHERTYPE_ARP);
	(void) memset(ehdr->ether_dhost, 0xff, ETH_ALEN);
	(void) memcpy(ehdr->ether_shost, mac_addr, ETH_ALEN);

	arphdr = (arphdr_t *)((char *)buf + sizeof (*ehdr));
	arphdr->ar_hrd = htons(ARPHRD_ETHER);
	arphdr->ar_pro = htons(ETHERTYPE_IP);
	arphdr->ar_hln = ETH_ALEN;
	arphdr->ar_pln = 4;
	arphdr->ar_op = htons(ARPOP_REQUEST);

	(void) memcpy(arphdr->ar_sha, mac_addr, ETH_ALEN);
	(void) memcpy(arphdr->ar_sip, &vip_addr, sizeof (struct in_addr));
	(void) memset(arphdr->ar_tha, 0xff, ETH_ALEN);
	(void) memcpy(arphdr->ar_tip, &vip_addr, sizeof (struct in_addr));

	if (sendto(vrrp_garp_socket, &buf, sizeof (buf), 0,
	    (struct sockaddr *)&dest, sizeof (dest)) < 0) {
		vrrp_log(LOG_ERR, "failed to send GARP on %s (%s)",
		    session->vs_file, strerror(errno));
		return (EIO);
	}

	return (0);
}

int
vrrp_adv_send(vrrp_session_t *session, prio_t prio)
{
	char			buf[IP_BUF_LEN] = { 0 };
	struct sockaddr_in	src = { 0 }, dest = { 0 };
	struct iovec		iovec = { 0 };
	struct msghdr		msghdr = { 0 };
	struct iphdr		*iphdr;
	vrrp_pkt_t		*vpkt;
	vrrp_pseudo_v4hdr_t	ph = { 0 };
	int			acc = 0;
	struct in_addr		*ipa;
	int			ret;

	assert((sizeof (*iphdr) + VRRP_PKT_LEN) < sizeof (buf));

	/*
	 * Set the destination to the VRRP mcast address and the source to the
	 * primary interface's addr.
	 */
	ret = inet_pton(AF_INET, VRRP_MCAST_ADDRv4, &dest.sin_addr);
	assert(ret == 1);
	dest.sin_family = AF_INET;

	src.sin_addr.s_addr = session->vs_primary.intf_addr.s_addr;
	src.sin_family = AF_INET;

	/*
	 * The msg payload points to the iovector which is really just a buffer.
	 */
	iovec.iov_base = buf;
	iovec.iov_len = sizeof (*iphdr) + VRRP_PKT_LEN;

	msghdr.msg_iov = &iovec;
	msghdr.msg_iovlen = 1;
	msghdr.msg_name = &dest;
	msghdr.msg_namelen = sizeof (dest);

	/*
	 * Fill in the ip header (top) portion of the buffer.
	 */
	iphdr = (struct iphdr *)buf;
	iphdr->ihl = sizeof (*iphdr) >> 2;
	iphdr->version = VRRP_IP_VERSION;
	iphdr->tos = 0;
	iphdr->tot_len = htons(sizeof (*iphdr) + VRRP_PKT_LEN);
	iphdr->id = htons(session->vs_iphdr_id++);
	iphdr->frag_off = 0;
	iphdr->ttl = VRRP_TTL;
	iphdr->protocol = VRRP_PROTOCOL;
	iphdr->saddr = src.sin_addr.s_addr;
	iphdr->daddr = dest.sin_addr.s_addr;
	iphdr->check = in_csum((ushort_t *)iphdr, iphdr->ihl << 2, 0, NULL);

	/*
	 * ..followed by the VRRP packet
	 */
	vpkt = (vrrp_pkt_t *)((char *)iphdr + sizeof (*iphdr));
	vpkt->vpkt_type_vers = (VRRP_VERSION_3 << 4) | VRRP_PKT_ADVERT;
	vpkt->vpkt_vrid = session->vs_vrid;
	vpkt->vpkt_priority = prio;
	vpkt->vpkt_addr_count = 1;
	vpkt->vpkt_adv_interval = session->vs_adv_interval / CENTISEC;
	vpkt->vpkt_csum = 0;

	/*
	 * ..with its single VIP address.
	 */
	ipa = (struct in_addr *)((char *)vpkt + sizeof (*vpkt));
	*ipa = session->vs_vip.intf_addr;

	/*
	 * Now compute the checksum.
	 */
	ph.vps4_src = src.sin_addr.s_addr;
	ph.vps4_dst = htonl(VRRP_MCAST_HEXv4);
	ph.vps4_zero = 0;
	ph.vps4_protocol = VRRP_PROTOCOL;
	ph.vps4_len = htons(VRRP_PKT_LEN);
	acc = 0;

	(void) in_csum((ushort_t *)&ph, sizeof (ph), 0, &acc);
	vpkt->vpkt_csum = in_csum((ushort_t *)vpkt, VRRP_PKT_LEN, acc, NULL);

	if (sendmsg(session->vs_vip.intf_mcast, &msghdr, MSG_DONTROUTE) == -1) {
		ret = errno;
		vrrp_log(LOG_ERR, "failed to send adv on %s (%s)",
		    session->vs_vip.intf_name, strerror(ret));

		vrrp_rwlock_wrlock(&session->vs_rwlock);
		session->vs_counter_err++;
		vrrp_rwlock_unlock(&session->vs_rwlock);

		return (ret);
	}

	vrrp_rwlock_wrlock(&session->vs_rwlock);
	session->vs_counter_sent++;
	vrrp_rwlock_unlock(&session->vs_rwlock);

	return (0);
}

vrrp_pkt_t *
vrrp_adv_recv(vrrp_session_t *session, vrrp_time_t to, struct sockaddr_in *src,
    char *buf, int buf_len)
{
	vrrp_time_t		ts;
	struct timeval		tv, tv_ret;
	struct iovec		iovec;
	struct msghdr		msghdr;
	struct iphdr		*iphdr;
	ssize_t			len;
	vrrp_pkt_t		*vpkt;
	vrrp_pseudo_v4hdr_t	ph  = { 0 };
	int			acc;
	struct in_addr		*ipa;

	assert((sizeof (*iphdr) + VRRP_PKT_LEN) < buf_len);

	iovec.iov_base = buf;
	iovec.iov_len = buf_len;

	msghdr.msg_name = src;
	msghdr.msg_namelen = sizeof (src);
	msghdr.msg_iov = &iovec;
	msghdr.msg_iovlen = 1;

	ts = vrrp_time_diff(to);
	tv.tv_sec = ts.tv_sec;
	tv.tv_usec = ts.tv_nsec / MICROSEC;

	if (tv.tv_sec != 0 || tv.tv_usec != 0) {
		if (vrrp_setsockopt(session->vs_primary.intf_mcast, SOL_SOCKET,
		    SO_RCVTIMEO, &tv, &tv_ret, sizeof (tv), VSC_BIN) < 0) {
			vrrp_log(LOG_ERR, "failed to set timeout on %s",
			    session->vs_file);
			return (NULL);
		}
	} else {
		return (NULL);
	}

	if ((len = recvmsg(session->vs_primary.intf_mcast, &msghdr, 0)) == -1) {
		if (errno == EAGAIN) {
			/* timed out */
			return (NULL);
		}
		vrrp_log(LOG_ERR, "failed to receive on %s (%s)",
		    session->vs_file, strerror(errno));
		return (NULL);
	}

	/*
	 * Drop advertisements sent from our own VRRP interface.
	 */
	if (src->sin_addr.s_addr == session->vs_primary.intf_addr.s_addr) {
		return (NULL);
	}

	/*
	 * Verify the packet.
	 */
	iphdr = (struct iphdr *)msghdr.msg_iov->iov_base;
	vpkt = (vrrp_pkt_t *)((char *)iphdr + (iphdr->ihl << 2));

	if (len < (sizeof (struct iphdr) + VRRP_PKT_LEN)) {
		vrrp_log(LOG_ERR, "incorrect pkt size on %s", session->vs_file);
		return (NULL);

	} else if (iphdr->version != VRRP_IP_VERSION) {
		vrrp_log(LOG_ERR, "incorrect addr family on %s",
		    session->vs_file);
		return (NULL);

	} else if (iphdr->protocol != VRRP_PROTOCOL) {
		vrrp_log(LOG_ERR, "incorrect pkt protocol on %s",
		    session->vs_file);
		return (NULL);

	} else if (iphdr->ttl != VRRP_TTL) {
		vrrp_log(LOG_ERR, "incorrect TTL (%d)", iphdr->ttl);
		return (NULL);

	} else if ((vpkt->vpkt_type_vers >> 4) != VRRP_VERSION_3) {
		vrrp_log(LOG_ERR, "incorrect VRRP version on %s",
		    session->vs_file);
		return (NULL);

	} else if ((vpkt->vpkt_type_vers & 0xf) != VRRP_PKT_ADVERT) {
		vrrp_log(LOG_ERR, "incorrect pkt type on %s",
		    session->vs_file);
		return (NULL);

	} else if (vpkt->vpkt_vrid != session->vs_vrid) {
		vrrp_log(LOG_ERR, "incorrect vrid on %s (%u, %u)",
		    session->vs_file, vpkt->vpkt_vrid, session->vs_vrid);
		return (NULL);

	} else if (vpkt->vpkt_auth_type != VRRP_AUTH_TYPE0) {
		vrrp_log(LOG_ERR, "incorrect pkt auth on %s (%d)",
		    session->vs_file, vpkt->vpkt_auth_type);
		return (NULL);

	} else if (vpkt->vpkt_addr_count != 1) {
		vrrp_log(LOG_ERR, "incorrect addr count on %s",
		    session->vs_file);
		return (NULL);
	}

	ipa = (struct in_addr *)((char *)vpkt + sizeof (*vpkt));

	if (session->vs_vip.intf_addr.s_addr != ipa->s_addr) {
		vrrp_log(LOG_ERR, "wrong vip on %s (%s, %s)", session->vs_file,
		    inet_ntoa(session->vs_vip.intf_addr),
		    inet_ntoa(*ipa));
		return (NULL);
	}

	ph.vps4_src = iphdr->saddr;
	ph.vps4_dst = htonl(VRRP_MCAST_HEXv4);
	ph.vps4_zero = 0;
	ph.vps4_protocol = VRRP_PROTOCOL;
	ph.vps4_len = htons(VRRP_PKT_LEN);
	acc = 0;

	(void) in_csum((ushort_t *)&ph, sizeof (ph), 0, &acc);

	if (in_csum((ushort_t *)vpkt, VRRP_PKT_LEN, acc, NULL) != 0) {
		vrrp_log(LOG_ERR, "bad chksum on %s %s", session->vs_file,
		    inet_ntoa(*(struct in_addr *)ipa));
		return (NULL);
	}

	vrrp_rwlock_wrlock(&session->vs_rwlock);
	session->vs_counter_recvd++;
	vrrp_rwlock_unlock(&session->vs_rwlock);

	return (vpkt);
}

/*
 * Note that vs_state can only be changed by the session thread itself, so the
 * locking around it is really only here for when displaying the session or
 * querying the state.
 */
int
vrrp_state_set(vrrp_session_t *session, vrrp_state_t new_state)
{
	vrrp_state_t	old_state;
	int		ret = 0;

	assert(new_state > 0);

	vrrp_rwlock_wrlock(&session->vs_rwlock);
	assert(session->vs_state != new_state);

	old_state = session->vs_state;
	session->vs_state = new_state;

	if (old_state == VRRP_MASTER) {
		if (new_state == VRRP_SLAVE) {
			session->vs_counter_m2s++;
		} else if (new_state == VRRP_INITIAL) {
			session->vs_counter_m2i++;
		}
	} else if (old_state == VRRP_SLAVE) {
		if (new_state == VRRP_MASTER) {
			session->vs_counter_s2m++;
		} else if (new_state == VRRP_INITIAL) {
			session->vs_counter_s2i++;
		}
	}

	vrrp_rwlock_unlock(&session->vs_rwlock);

	vrrp_log(LOG_ERR, "%s -> %s : %s",
	    vrrp_state_str(old_state), vrrp_state_str(new_state),
	    session->vs_file);

	switch (session->vs_state) {
	case VRRP_INITIAL:
		/*
		 * Under normal circumstances we shouldn't go back to initial
		 * state after the session is started, but it can happen when
		 * a primary interface goes down. Under that scenario, we'll
		 * restart the session and keep falling back into initial state
		 * until the primary is back up. The appropriate timer (adv or
		 * mdown) works as the 'polling' interval for the interface
		 * state.
		 */
		break;

	case VRRP_SLAVE:
		ret = vrrp_intf_down(&session->vs_vip);
		break;

	case VRRP_SHUTDOWN:
		(void) vrrp_intf_down(&session->vs_vip);
		vrrp_intf_teardown(&session->vs_vip);
		vrrp_intf_teardown(&session->vs_primary);

		session->vs_timer_adv = (vrrp_time_t) {0, 0};
		session->vs_timer_mdown = (vrrp_time_t) {0, 0};
		break;

	case VRRP_MASTER:
		ret = vrrp_intf_setup_vip(&session->vs_vip);
		break;

	default:
		vrrp_quit("invalid state %u", new_state);
		ret = EINVAL;
	}

	return (ret);
}

int
vrrp_state_initial(vrrp_session_t *session)
{
	int 	ret;

	if (session->vs_priority == VRRP_PRIO_OWNER) {
		if ((ret = vrrp_intf_setup_vip(&session->vs_vip)) != 0) {
			return (ret);
		}

		/*
		 * We ignore errors in this case because the initial state is
		 * the fallback state for such errors. If they persist, we'll
		 * handle them accordingly once we're in master state.
		 */
		(void) vrrp_adv_send(session, session->vs_priority);

		(void) vrrp_bcast_garp(session);

		session->vs_timer_adv = vrrp_time_add(session->vs_adv_interval);

		if ((ret = vrrp_state_set(session, VRRP_MASTER)) != 0) {
			vrrp_log(LOG_ERR, "failed to set master state on %s",
			    session->vs_file);
			return (ret);
		}

	} else {
		session->vs_master_adv_interval = session->vs_adv_interval;

		assert(session->vs_master_down_interval != 0);

		session->vs_timer_mdown =
		    vrrp_time_add(session->vs_master_down_interval);

		if ((ret = vrrp_state_set(session, VRRP_SLAVE)) != 0) {
			vrrp_log(LOG_ERR, "failed to set slave state on %s",
			    session->vs_file);
			return (ret);
		}
	}

	return (0);
}

/*
 * Note that the formulas for calculating the skew time and the master down
 * interval come straight from the VRRPv3 RFC, and as with most of this file
 * are kept as verbatim as possible for maintainability and readability.
 */
int
vrrp_state_slave(vrrp_session_t *session)
{
	char			buf[IP_BUF_LEN] = { 0 };
	vrrp_pkt_t		*vpkt;
	struct sockaddr_in	src;
	int			ret;

	if (vrrp_shutdown || session->vs_session_state == SS_EXIT) {
		if ((ret = vrrp_state_set(session, VRRP_SHUTDOWN)) != 0) {
			vrrp_log(LOG_ERR, "failed to set shutdown state on %s",
			    session->vs_file);
			return (ret);
		}

		return (0);
	}

	vpkt = vrrp_adv_recv(session, session->vs_timer_mdown, &src, buf,
	    sizeof (buf));

	/*
	 * Switch to master if the master down timer has expired, but first
	 * check if the primary interface is up. If it's not, fall back to
	 * initial state.
	 */
	if (vrrp_time_elapsed(session->vs_timer_mdown)) {
		if (!vrrp_intf_is_up(&session->vs_primary)) {
			vrrp_log(LOG_INFO, "primary is down on %s, moving from "
			    "slave to initial state", session->vs_file);

			if ((ret = vrrp_state_set(session,
			    VRRP_INITIAL)) != 0) {
				vrrp_log(LOG_ERR, "unable to set initial state"
				    " on %s", session->vs_file);
				return (ret);
			}

			return (0);
		}

		if ((ret = vrrp_intf_setup_vip(&session->vs_vip)) != 0) {
			return (ret);
		}

		if ((ret = vrrp_adv_send(session, session->vs_priority)) != 0) {
			vrrp_log(LOG_INFO, "failed to send advert on %s, moving"
			    " from slave to initial state", session->vs_file);

			if ((ret = vrrp_state_set(session,
			    VRRP_INITIAL)) != 0) {
				vrrp_log(LOG_ERR, "unable to set initial state"
				    " on %s", session->vs_file);
				return (ret);
			}

			return (0);
		}

		if ((ret = vrrp_bcast_garp(session)) != 0) {
			return (ret);
		}

		session->vs_timer_adv = vrrp_time_add(session->vs_adv_interval);
		session->vs_timer_mdown = (vrrp_time_t) {0, 0};

		if ((ret = vrrp_state_set(session, VRRP_MASTER)) != 0) {
			vrrp_log(LOG_ERR, "failed to set master state on %s",
			    session->vs_file);
			return (ret);
		}

		return (0);
	}

	if (vpkt != NULL && (vpkt->vpkt_type_vers & 0xf) == VRRP_PKT_ADVERT) {
		if (vpkt->vpkt_priority == VRRP_PRIO_ZERO) {
			session->vs_timer_mdown =
			    vrrp_time_add(session->vs_skew_time);

		} else if (!session->vs_allow_preemption ||
		    vpkt->vpkt_priority >= session->vs_priority) {

			session->vs_master_adv_interval =
			    vpkt->vpkt_adv_interval * CENTISEC;

			session->vs_master_down_interval =
			    ((3 * session->vs_master_adv_interval) +
			    session->vs_skew_time);

			session->vs_timer_mdown =
			    vrrp_time_add(session->vs_master_down_interval);
		} else {
			/* ignore the advertisement */
		}
	}

	return (0);
}

int
vrrp_state_master(vrrp_session_t *session)
{
	char			buf[IP_BUF_LEN] = { 0 };
	vrrp_pkt_t		*vpkt;
	struct sockaddr_in	src;
	int			ret;

	if (vrrp_shutdown || session->vs_session_state == SS_EXIT) {
		if ((ret = vrrp_adv_send(session, VRRP_PRIO_ZERO)) != 0) {
			return (ret);
		}

		if ((ret = vrrp_state_set(session, VRRP_SHUTDOWN)) != 0) {
			vrrp_log(LOG_ERR, "failed to set shutdown state on %s",
			    session->vs_file);
			return (ret);
		}

		return (0);
	}

	vpkt = vrrp_adv_recv(session, session->vs_timer_adv, &src, buf,
	    sizeof (buf));

	if (vrrp_time_elapsed(session->vs_timer_adv)) {
		if (!vrrp_intf_is_up(&session->vs_primary)) {
			vrrp_log(LOG_INFO, "primary is down on %s, moving from"
			    " master to initial state", session->vs_file);

			if ((ret = vrrp_state_set(session,
			    VRRP_INITIAL)) != 0) {
				vrrp_log(LOG_ERR, "unable to set initial state"
				    " on %s", session->vs_file);
				return (ret);
			}

			return (0);
		}

		if ((ret = vrrp_adv_send(session, session->vs_priority)) != 0) {
			vrrp_log(LOG_INFO, "failed to send advert on %s, "
			    "moving from master to initial state",
			    session->vs_file);

			if ((ret = vrrp_state_set(session,
			    VRRP_INITIAL)) != 0) {
				vrrp_log(LOG_ERR, "unable to set initial state"
				    " on %s", session->vs_file);
				return (ret);
			}

			return (0);
		}

		session->vs_timer_adv = vrrp_time_add(session->vs_adv_interval);
	}

	if (vpkt != NULL && (vpkt->vpkt_type_vers & 0xf) == VRRP_PKT_ADVERT) {
		if (vpkt->vpkt_priority == VRRP_PRIO_ZERO) {
			if ((ret = vrrp_adv_send(session,
			    session->vs_priority)) != 0) {
				vrrp_log(LOG_INFO, "failed to send advert on "
				    "%s (recvd prio zero), moving from master "
				    "to initial state", session->vs_file);

				if ((ret = vrrp_state_set(session,
				    VRRP_INITIAL)) != 0) {
					vrrp_log(LOG_ERR, "unable to set "
					    "initial state on %s",
					    session->vs_file);
					return (ret);
				}

				return (0);
			}

			session->vs_timer_adv =
			    vrrp_time_add(session->vs_adv_interval);

		} else if (vpkt->vpkt_priority > session->vs_priority ||
		    (vpkt->vpkt_priority == session->vs_priority &&
		    src.sin_addr.s_addr >
		    session->vs_primary.intf_addr.s_addr)) {

			session->vs_master_adv_interval =
			    vpkt->vpkt_adv_interval * CENTISEC;

			session->vs_skew_time = (((256 - session->vs_priority) *
			    session->vs_master_adv_interval) / 256);

			session->vs_master_down_interval =
			    ((3 * session->vs_adv_interval) +
			    session->vs_skew_time);

			session->vs_timer_mdown =
			    vrrp_time_add(session->vs_master_down_interval);
			session->vs_timer_adv = (vrrp_time_t) {0, 0};

			if ((ret = vrrp_state_set(session, VRRP_SLAVE)) != 0) {
				vrrp_log(LOG_ERR, "failed to set slave state "
				    "on %s", session->vs_file);
				return (ret);
			}
		} else {
			/* ignore the advertisement */
		}
	}

	return (0);
}

void *
vrrp_state_thread(void *arg)
{
	vrrp_session_t	*session = (vrrp_session_t *)arg;
	int		ret = 0;

	vrrp_rwlock_wrlock(&vrrp_list_rwlock);
	vrrp_inuse_cnt++;
	vrrp_rwlock_unlock(&vrrp_list_rwlock);

	for (;;) {
		switch (session->vs_state) {
		case VRRP_INITIAL:
			ret = vrrp_state_initial(session);
			break;

		case VRRP_SLAVE:
			ret = vrrp_state_slave(session);
			break;

		case VRRP_MASTER:
			ret = vrrp_state_master(session);
			break;

		case VRRP_SHUTDOWN:
			ret = -1;
			break;
		}

		if (ret != 0) {
			vrrp_rwlock_rdlock(&session->vs_rwlock);

			if (session->vs_state != VRRP_SHUTDOWN) {
				vrrp_rwlock_unlock(&session->vs_rwlock);
				(void) vrrp_state_set(session, VRRP_SHUTDOWN);
			} else {
				vrrp_rwlock_unlock(&session->vs_rwlock);
			}

			break;
		}
	}

	vrrp_log(LOG_INFO, "shutting down %s", session->vs_file);

	vrrp_rwlock_wrlock(&session->vs_rwlock);
	assert(session->vs_state == VRRP_SHUTDOWN);
	vrrp_session_clear(session);
	vrrp_rwlock_unlock(&session->vs_rwlock);

	vrrp_rwlock_wrlock(&vrrp_list_rwlock);
	vrrp_inuse_cnt--;
	vrrp_rwlock_unlock(&vrrp_list_rwlock);

	return (NULL);
}

/*
 * Both primary and vip interfaces need their fields populated and both
 * need an open, raw socket on the VRRP protocol.
 */
int
vrrp_intf_setup_common(intf_t *intf)
{
	struct ifreq	ifr = {{{ 0 }}};

	if ((intf->intf_mgmt = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		vrrp_log(LOG_ERR, "failed to open management socket on %s (%s)",
		    intf->intf_name, strerror(errno));
		return (EIO);
	}

	(void) strlcpy(ifr.ifr_name, intf->intf_name, sizeof (ifr.ifr_name));

	if (ioctl(intf->intf_mgmt, SIOCGIFINDEX, &ifr) != 0) {
		vrrp_log(LOG_ERR, "failed to get interface index for %s (%s)",
		    ifr.ifr_name, strerror(errno));
		goto out1;
	}

	intf->intf_index = ifr.ifr_ifindex;

	if (ioctl(intf->intf_mgmt, SIOCGIFFLAGS, &ifr) != 0) {
		vrrp_log(LOG_ERR, "failed to get interface flags for %s (%s)",
		    ifr.ifr_name, strerror(errno));
		goto out1;
	}

	if (!(ifr.ifr_flags & (IFF_UP | IFF_RUNNING))) {
		vrrp_log(LOG_ERR, "interface %s is down", ifr.ifr_name);
	}

	if (ioctl(intf->intf_mgmt, SIOCGIFHWADDR, &ifr) != 0) {
		vrrp_log(LOG_ERR, "failed to get MAC addres for %s (%s)",
		    ifr.ifr_name, strerror(errno));
		goto out1;
	}

	(void) memcpy(&intf->intf_mac_addr, &ifr.ifr_hwaddr.sa_data,
	    sizeof (intf->intf_mac_addr));

	(void) snprintf(intf->intf_mac_str, sizeof (intf->intf_mac_str),
	    "%02x:%02x:%02x:%02x:%02x:%02x",
	    (unsigned char)intf->intf_mac_addr[0],
	    (unsigned char)intf->intf_mac_addr[1],
	    (unsigned char)intf->intf_mac_addr[2],
	    (unsigned char)intf->intf_mac_addr[3],
	    (unsigned char)intf->intf_mac_addr[4],
	    (unsigned char)intf->intf_mac_addr[5]);

	if ((intf->intf_mcast = socket(AF_INET, SOCK_RAW,
	    VRRP_PROTOCOL)) < 0) {
		vrrp_log(LOG_ERR, "failed to create raw vrrp socket on %s (%s)",
		    intf->intf_name, strerror(errno));
		goto out1;
	}

	return (0);
out1:
	(void) close(intf->intf_mgmt);
	return (EIO);
}

/*
 * The primary interface joins the VRRP multicast group. We'll receive
 * advertisements there.
 */
int
vrrp_intf_setup_prim(intf_t *prim)
{
	struct ifreq		ifr = {{{ 0 }}};
	struct ip_mreqn		mr = {{ 0 }};
	struct sockaddr_in	*sa;
	char			buf[IFNAME_LEN];
	int			ret, so_val, so_ret;

	(void) strlcpy(ifr.ifr_name, prim->intf_name, sizeof (ifr.ifr_name));

	/*
	 * The primary address isn't specified in the configuration file, we
	 * query from the system.
	 */
	if (ioctl(prim->intf_mgmt, SIOCGIFADDR, &ifr) != 0 &&
	    errno != EADDRNOTAVAIL) {
		vrrp_log(LOG_ERR, "failed to get address for %s (%s)",
		    ifr.ifr_name, strerror(errno));
		return (EIO);
	} else {
		sa = (struct sockaddr_in *)&ifr.ifr_addr;

		if (inet_ntop(AF_INET, &sa->sin_addr, prim->intf_addr_str,
		    sizeof (prim->intf_addr_str)) == NULL) {
			vrrp_log(LOG_ERR, "failed to convert addr on %s (%s)",
			    ifr.ifr_name, strerror(errno));
			return (EIO);
		}

		prim->intf_addr.s_addr = sa->sin_addr.s_addr;
	}

	if (ioctl(prim->intf_mgmt, SIOCGIFNETMASK, &ifr) != 0 &&
	    errno != EADDRNOTAVAIL) {
		vrrp_log(LOG_ERR, "failed to get address for %s (%s)",
		    ifr.ifr_name, strerror(errno));
		return (EIO);
	} else {
		prim->intf_netmask =
		    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	}

	/*
	 * Bring primary up only if it is admin up.
	 */
	if (ioctl(prim->intf_mgmt, SIOCGIFFLAGS, &ifr) != 0) {
		vrrp_log(LOG_ERR, "failed to get flags for %s (%s)",
		    ifr.ifr_name, strerror(errno));
		return (B_FALSE);
	}
	if (ifr.ifr_flags & IFF_UP) {
		if ((ret = vrrp_intf_up(prim)) != 0) {
			return (ret);
		}
	}

	so_val = 0;

	if (vrrp_setsockopt(prim->intf_mcast, SOL_SOCKET, SO_BINDTODEVICE,
	    (void *)prim->intf_name, &buf, sizeof (prim->intf_name),
	    VSC_STRING) < 0) {
		vrrp_log(LOG_ERR, "failed to bind mcast socket on %s",
		    prim->intf_name);
		return (EIO);
	}

	if (vrrp_setsockopt(prim->intf_mcast, IPPROTO_IP, IP_MULTICAST_ALL,
	    &so_val, &so_ret, sizeof (so_val), VSC_BIN) < 0) {
		vrrp_log(LOG_ERR, "failed to turn mcast all off on %s",
		    prim->intf_name);
		return (EIO);
	}

	if (vrrp_setsockopt(prim->intf_mcast, IPPROTO_IP, IP_MULTICAST_LOOP,
	    &so_val, &so_ret, sizeof (so_val), VSC_BIN) < 0) {
		vrrp_log(LOG_ERR, "failed to turn mcast loop off on %s",
		    prim->intf_name);
		return (EIO);
	}

	mr.imr_ifindex = prim->intf_index;
	mr.imr_address = prim->intf_addr;

	if (inet_pton(AF_INET, VRRP_MCAST_ADDRv4, &mr.imr_multiaddr) != 1) {
		vrrp_log(LOG_ERR, "failed to convert VRRP mcast string (%s)",
		    strerror(errno));
		return (EIO);
	}

	if (setsockopt(prim->intf_mcast, IPPROTO_IP, IP_ADD_MEMBERSHIP,
	    &mr, sizeof (mr)) < 0) {
		vrrp_log(LOG_ERR, "failed to join VRRP mcast group on %s (%s)",
		    prim->intf_name, strerror(errno));
		return (EIO);
	}

	return (0);
}

/*
 * Read the config files in VRRP_CONF_DIR verifying and allocating session's
 * from the vrrp_session_array table. Returns the number of allocated and/or
 * deleted sessions through the respective arguments.
 */
int
vrrp_config_load(int *ret_alloced, int *ret_deleted)
{
	DIR			*dir;
	struct dirent		de, *res;
	FILE			*fp;
	char			buf[64], *field, *val, *end, *sep = " \t\n";
	char			fname[MAX_FNAME_LEN], *slash;
	char			*rpt = "repeated entry %s on %s";
	vrrp_session_t		cfg, *session;
	intf_t			*prim, *vip;
	boolean_t		err;
	uint64_t		tmp;
	int			ii, nmask, ret, alloced, deleted;

	alloced = 0;
	deleted = 0;

	/*
	 * First check if any of the existing sessions have had their config
	 * file deleted, indicating that they should be removed.
	 */
	vrrp_rwlock_wrlock(&vrrp_list_rwlock);

	for (ii = 0; ii < MAX_NUM_VRRP_INTF; ii++) {
		session = &vrrp_session_array[ii];

		if (session->vs_session_state != SS_FREE) {
			assert(session->vs_file[0] != '\0');
			if (access(session->vs_file, F_OK) != 0) {
				session->vs_session_state = SS_EXIT;
				deleted++;
			}
		}
	}

	vrrp_rwlock_unlock(&vrrp_list_rwlock);

	if ((dir = opendir(VRRP_CONF_DIR)) == NULL) {
		vrrp_log(LOG_ERR, "failed to open %s (%s)", VRRP_CONF_DIR,
		    strerror(errno));
		return (EIO);
	}

	for (;;) {
		if (readdir_r(dir, &de, &res) != 0) {
			vrrp_log(LOG_ERR, "error reading %s (%s)",
			    VRRP_CONF_DIR, strerror(errno));
			(void) closedir(dir);
			return (EIO);
		}

		/*
		 * End of directory is indicated by return NULL in res.
		 */
		if (res == NULL) {
			break;
		}

		/*
		 * Skip non regular files.
		 */
		if (de.d_type != DT_REG) {
			continue;
		}

		(void) snprintf(fname, sizeof (fname), "%s/%s", VRRP_CONF_DIR,
		    de.d_name);

		if ((fp = fopen(fname, "r")) == NULL) {
			vrrp_log(LOG_ERR, "failed to open %s (%s)", fname,
			    strerror(errno));
			continue;
		}

		vrrp_session_clear(&cfg);
		prim = &cfg.vs_primary;
		vip = &cfg.vs_vip;

		err = B_FALSE;
		tmp = 0;

		(void) strlcpy(cfg.vs_file, fname, sizeof (cfg.vs_file));

		while (fgets(buf, sizeof (buf), fp) != NULL) {
			if (buf[0] == '\0' || buf[0] == '#') {
				continue;
			}

			if ((field = strtok_r(buf, sep, &end)) == NULL) {
				continue;
			}

			if ((val = strtok_r(NULL, sep, &end)) == NULL) {
				continue;
			}

			if (field[0] == '\0' || val[0] == '\0') {
				vrrp_log(LOG_ERR, "empty field and/or val");
				err = B_TRUE;
				break;
			}

			if (strcmp(field, "primary_intf") == 0) {
				if (prim->intf_name[0] != '\0') {
					vrrp_log(LOG_ERR, rpt, field, fname);
					err = B_TRUE;
					break;
				}

				(void) strlcpy(prim->intf_name, val,
				    sizeof (prim->intf_name));

			} else if (strcmp(field, "vrrp_intf") == 0) {
				if (vip->intf_name[0] != '\0') {
					vrrp_log(LOG_ERR, rpt, field, fname);
					err = B_TRUE;
					break;
				}

				(void) strlcpy(vip->intf_name, val,
				    sizeof (vip->intf_name));

			} else if (strcmp(field, "vip") == 0) {
				if (vip->intf_addr_str[0] != '\0') {
					vrrp_log(LOG_ERR, rpt, field, fname);
					err = B_TRUE;
					break;
				}

				if ((slash = strchr(val, '/')) == NULL) {
					vrrp_log(LOG_ERR, "VIP address missing "
					    "netmask on %s", fname);
					err = B_TRUE;
					break;
				}

				(void) strlcpy(vip->intf_addr_str, val,
				    sizeof (vip->intf_addr_str));

				*slash = '\0';

				if (inet_aton(val, &vip->intf_addr) != 1) {
					vrrp_log(LOG_ERR, "failed to convert "
					    "VIP on %s", fname);
					err = B_TRUE;
					break;
				}

				if (vrrp_strtoul(++slash, &tmp) != 0) {
					vrrp_log(LOG_ERR, "failed to convert "
					    "netmask on %s", fname);
					err = B_TRUE;
					break;
				}

				/*
				 * Convert the netmask to a struct in_addr.
				 */
				nmask = 0;
				for (ii = 0; ii < tmp; ii++) {
					nmask |= 1 << (31 - ii);
				}

				vip->intf_netmask.s_addr = htonl(nmask);

			} else if (strcmp(field, "vrid") == 0) {
				if (cfg.vs_vrid != 0) {
					vrrp_log(LOG_ERR, rpt, field, fname);
					err = B_TRUE;
					break;
				}

				if (vrrp_strtoul(val, &tmp) != 0) {
					vrrp_log(LOG_ERR, "failed to convert "
					    "vrid on %s", fname);
					err = B_TRUE;
					break;
				} else if (tmp < 1 || tmp >= 255) {
					vrrp_log(LOG_ERR,
					    "illegal vrid on %s", fname);
					err = B_TRUE;
					break;
				} else {
					cfg.vs_vrid = (vrid_t)tmp;
				}

			} else if (strcmp(field, "priority") == 0) {
				if (cfg.vs_priority != 0) {
					vrrp_log(LOG_ERR, rpt, field, fname);
					err = B_TRUE;
					break;
				}

				if (vrrp_strtoul(val, &tmp) != 0) {
					vrrp_log(LOG_ERR, "failed to convert "
					    " priority on %s", fname);
					err = B_TRUE;
					break;

				} else if (tmp <= 0 || tmp >= VRRP_PRIO_OWNER) {
					vrrp_log(LOG_ERR,
					    "illegal priority %lu on %s",
					    tmp, fname);
					err = B_TRUE;
					break;

				} else {
					cfg.vs_priority = (prio_t)tmp;
				}

			} else if (strcmp(field, "advert_int") == 0) {
				if (cfg.vs_adv_interval != 0) {
					vrrp_log(LOG_ERR, rpt, field, fname);
					err = B_TRUE;
					break;
				}

				if (vrrp_strtoul(val, &tmp) != 0) {
					vrrp_log(LOG_ERR, "failed to convert "
					    "advertisement interval on %s",
					    fname);
					err = B_TRUE;
					break;
				}


				tmp *= MILLISEC;

				if (tmp < VRRP_ADV_INT_MIN ||
				    tmp > VRRP_ADV_INT_MAX) {
					vrrp_log(LOG_ERR, "illegal "
					    "advertisement interval %lu on %s",
					    tmp, fname);
					err = B_TRUE;
					break;
				}

				/*
				 * The RFC states that timers are all in
				 * centiseconds, the config file uses
				 * milliseconds and we use nanoseconds
				 * internally.
				 */
				cfg.vs_adv_interval = tmp;
				cfg.vs_master_adv_interval =
				    cfg.vs_adv_interval;
				cfg.vs_skew_time = (((256 - cfg.vs_priority) *
				    cfg.vs_master_adv_interval) / 256);
				cfg.vs_master_down_interval =
				    ((3 * cfg.vs_master_adv_interval) +
				    cfg.vs_skew_time);

			} else if (strcmp(field, "version") == 0) {
				if (cfg.vs_version != 0) {
					vrrp_log(LOG_ERR, rpt, field, fname);
					err = B_TRUE;
					break;
				}

				if (strcmp(val, "3") == 0) {
					cfg.vs_version = VRRP_VERSION_3;
				} else {
					vrrp_log(LOG_ERR,
					    "invalid version %s on %s",
					    val, fname);
					err = B_TRUE;
					break;
				}

			} else if (strcmp(field, "allow_preemption") == 0) {
				if (cfg.vs_allow_preemption != 0) {
					vrrp_log(LOG_ERR, rpt, field, fname);
					err = B_TRUE;
					break;
				}

				if (strcmp(val, "yes") == 0) {
					cfg.vs_allow_preemption = B_TRUE;
				} else if (strcmp(val, "no") == 0) {
					cfg.vs_allow_preemption = B_FALSE;
				} else {
					vrrp_log(LOG_ERR,
					    "invalid value '%s' on %s",
					    val, fname);
					err = B_TRUE;
					break;
				}
			} else {
				vrrp_log(LOG_ERR, "invalid field '%s' on %s",
				    field, fname);
				err = B_TRUE;
				break;
			}
		}

		(void) fclose(fp);

		if (err) {
			break;
		}

		/*
		 * Check that the required fields were parsed.
		 */
		if (prim->intf_name[0] == '\0' || vip->intf_name[0] == '\0' ||
		    vip->intf_addr_str[0] == '\0' || cfg.vs_vrid == 0 ||
		    cfg.vs_priority == 0 || cfg.vs_adv_interval == 0) {
			vrrp_log(LOG_ERR, "incomplete config on %s",
			    cfg.vs_file);
			break;
		}

		/*
		 * See if we've already loaded this config before.
		 */
		session = NULL;

		ret = vrrp_find_and_lock(cfg.vs_file, prim->intf_name,
		    vip->intf_name, &session);

		switch (ret) {
		case SF_LOCKED:
			/*
			 * Check if the session we found hasn't changed, has
			 * changed and can be updated or has changed and needs
			 * to be replaced.
			 */
			switch (vrrp_session_cmp(session, &cfg)) {
			case SC_SAME:
				vrrp_log(LOG_INFO, "config %s hasn't changed",
				    cfg.vs_file);
				break;

			case SC_VRRP:
				vrrp_log(LOG_INFO, "updating VRRP config on %s",
				    cfg.vs_file);
				session->vs_vrid = cfg.vs_vrid;
				session->vs_priority = cfg.vs_priority;
				session->vs_allow_preemption =
				    cfg.vs_allow_preemption;
				break;

			case SC_PRIM:
			case SC_VIP:
			case SC_VRID:
				/*
				 * Mark the existing config for exit and
				 * continue to allocate a new one.
				 */
				vrrp_log(LOG_INFO, "replacing config on %s",
				    cfg.vs_file);
				cfg.vs_session_state = SS_EXIT;
				break;
			}

			vrrp_rwlock_unlock(&session->vs_rwlock);
			continue;

		case SF_INVAL:
			vrrp_log(LOG_ERR, "invalid config %s", cfg.vs_file);
			continue;

		case SF_NONE:
			/* continue to allocate a new config */
			break;
		}

		if ((session = vrrp_alloc()) == NULL) {
			vrrp_log(LOG_INFO, "all available sessions are busy");
			continue;
		}

		if (vrrp_intf_setup_common(vip) == 0) {
			(void) snprintf(buf, sizeof (buf),
			    VRRP_MAC_ADDRv4, cfg.vs_vrid);

			if (strncasecmp(vip->intf_mac_str, buf,
			    sizeof (vip->intf_mac_str)) != 0) {
				vrrp_log(LOG_INFO, "invalid MAC addr on %s",
				    vip->intf_name);
				vrrp_intf_teardown(vip);

			} else if (vrrp_intf_setup_common(prim) != 0 ||
			    vrrp_intf_setup_prim(prim) != 0) {
				vrrp_intf_teardown(vip);
				vrrp_intf_teardown(prim);

			} else {
				/*
				 * Alright, new config is valid. Copy it to
				 * the newly allocated one and start its thread.
				 */
				vrrp_session_inuse(session, &cfg);
			}
		}

		vrrp_rwlock_unlock(&session->vs_rwlock);

		/*
		 * If all went well, the session should be in use and we
		 * can create its state thread.
		 */
		if (session->vs_session_state == SS_INUSE) {
			if (pthread_create(&session->vs_thread, NULL,
			    vrrp_state_thread, (void *)session) != 0) {
				vrrp_log(LOG_INFO, "failed to create session "
				    "for %s (%s)", session->vs_file,
				    strerror(errno));

				vrrp_intf_teardown(vip);
				vrrp_intf_teardown(prim);
				vrrp_session_clear(session);
			} else {
				alloced++;
			}
		}
	}

	(void) closedir(dir);

	*ret_alloced = alloced;
	*ret_deleted = deleted;

	return (0);
}

/*
 * Send a message to the daemon through a UNIX socket and waits for the
 * reply. This is called when one of the options is passed to the command line
 * and to check if the daemon is already running.
 */
int
vrrp_ctrl_send(vrrp_ctrl_msg_t *ctrl_msg)
{
	struct sockaddr_un	addr = { 0 };
	int			send_socket, ret = 0;
	ctrl_msg_t		msg_type;
	vrrp_session_t		session;

	/*
	 * First we send the command to the daemon..
	 */
	if ((send_socket = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		vrrp_log(LOG_ERR, "failed to open UNIX socket (%s)",
		    strerror(errno));
		return (EIO);
	}

	addr.sun_family = AF_UNIX;
	(void) strlcpy(addr.sun_path, VRRP_UNIX_SOCKET, sizeof (addr.sun_path));

	msg_type = ctrl_msg->vcm_msg;
	ret = 0;

	if (connect(send_socket, (struct sockaddr *)&addr,
	    sizeof (addr)) == -1) {
		vrrp_log(LOG_ERR, "failed to connect to UNIX socket (%s)",
		    strerror(errno));
		(void) close(send_socket);
		return (EIO);
	}

	if (write(send_socket, ctrl_msg, sizeof (*ctrl_msg)) < 0) {
		vrrp_log(LOG_ERR, "failed to send message to daemon (%s)",
		    strerror(errno));
		(void) close(send_socket);
		return (EIO);
	}

	/*
	 * ..then wait for a reply according to the type of command.
	 */
	switch (msg_type) {
	case CTRL_RELOAD:
	case CTRL_SUMMARY:
	case CTRL_VIP_STATE:
	case CTRL_CLEAR_COUNTERS:
	case CTRL_LOG_LEVEL:
		if (read(send_socket, ctrl_msg, sizeof (*ctrl_msg)) !=
		    sizeof (*ctrl_msg)) {
			vrrp_log(LOG_ERR, "failed to get reply");
			ret = EIO;
		} else {
			vrrp_log(LOG_INFO, "%s", ctrl_msg->vcm_buf);
		}
		break;

	case CTRL_SHOW:
		for (;;) {
			if (read(send_socket, ctrl_msg, sizeof (*ctrl_msg)) !=
			    sizeof (*ctrl_msg)) {
				break;
			}

			(void) memcpy((void *)&session,
			    (void *)ctrl_msg->vcm_buf, sizeof (session));

			if (session.vs_file[0] == '\0') {
				break;
			}

			vrrp_show_session(&session);
		}

		break;

	case CTRL_QUIT:
		/*
		 * The daemon closes the UNIX socket in the process of quitting
		 * and we only get an interrupt in the read(2) call below, so
		 * just wait for it.
		 */
		if (read(send_socket, ctrl_msg, sizeof (*ctrl_msg)) !=
		    sizeof (*ctrl_msg)) {
			ret = EXIT_SUCCESS;
		}
		break;

	case CTRL_VERSION:
		break;

	default:
		(void) strlcpy(ctrl_msg->vcm_buf, "invalid command",
		    sizeof (ctrl_msg->vcm_buf));
		ret = 0;
		break;
	}

	(void) close(send_socket);

	return (ret);
}

/*
 * Send each configured vrrp_session_t to the client using the given socket and
 * vrrp_ctrl_msg structure. We send one at a time to ssessionify things.
 */
int
vrrp_send_session(socket_t conn_socket, vrrp_ctrl_msg_t *ctrl_msg)
{
	vrrp_session_t	*session;
	int		ii, ret = 0;

	assert(sizeof (ctrl_msg->vcm_buf) > sizeof (*session));
	vrrp_rwlock_rdlock(&vrrp_list_rwlock);

	for (ii = 0; ii < MAX_NUM_VRRP_INTF; ii++) {
		session = &vrrp_session_array[ii];
		(void) memset(ctrl_msg, 0, sizeof (*ctrl_msg));

		vrrp_rwlock_rdlock(&session->vs_rwlock);

		if (session->vs_session_state != SS_FREE) {
			(void) memcpy(ctrl_msg->vcm_buf, session,
			    sizeof (*session));
			vrrp_rwlock_unlock(&session->vs_rwlock);
		} else {
			vrrp_rwlock_unlock(&session->vs_rwlock);
			continue;
		}

		if (write(conn_socket, ctrl_msg,
		    sizeof (*ctrl_msg)) == -1) {
			vrrp_log(LOG_INFO, "server failed to show (%s)",
			    strerror(errno));
			ret = EIO;
			break;
		}
	}

	vrrp_rwlock_unlock(&vrrp_list_rwlock);

	/*
	 * Zero the ctrl_msg on our way out so the client interprets a blank
	 * structure as the end of the transimission.
	 */
	(void) memset(ctrl_msg, 0, sizeof (*ctrl_msg));

	return (ret);
}

/*
 * Walk the current config and generate a summary.
 */
void
vrrp_summary(vrrp_ctrl_msg_t *ctrl_msg)
{
	vrrp_session_t	*session;
	int		ii, ninitial = 0, nslave = 0, nmaster = 0;

	assert(sizeof (ctrl_msg->vcm_buf) > sizeof (*session));
	vrrp_rwlock_rdlock(&vrrp_list_rwlock);

	for (ii = 0; ii < MAX_NUM_VRRP_INTF; ii++) {
		session = &vrrp_session_array[ii];
		vrrp_rwlock_rdlock(&session->vs_rwlock);

		if (session->vs_session_state == SS_FREE) {
			vrrp_rwlock_unlock(&session->vs_rwlock);
			continue;
		}

		switch (session->vs_state) {
		case VRRP_INITIAL:
			ninitial++;
			break;
		case VRRP_SLAVE:
			nslave++;
			break;
		case VRRP_MASTER:
			nmaster++;
			break;
		default:
			break;
		}

		vrrp_rwlock_unlock(&session->vs_rwlock);
	}

	vrrp_rwlock_unlock(&vrrp_list_rwlock);

	(void) snprintf(ctrl_msg->vcm_buf, sizeof (ctrl_msg->vcm_buf),
	    "%d initial session(s)\n"
	    "%d slave session(s)\n"
	    "%d master session(s)",
	    ninitial, nslave, nmaster);
}

void *
vrrp_ctrl_handler(void *arg)
{
	int			n, conn_socket = (intptr_t)arg;
	int			alloced, deleted;
	uint64_t		val;
	vrrp_ctrl_msg_t		ctrl_msg;

	for (;;) {
		if (read(conn_socket, &ctrl_msg, sizeof (ctrl_msg)) !=
		    sizeof (ctrl_msg)) {
			break;
		}

		switch (ctrl_msg.vcm_msg) {
		case CTRL_RELOAD:
			if (vrrp_config_load(&alloced, &deleted) != 0) {
				(void) strlcpy(ctrl_msg.vcm_buf,
				    "error loading configuration",
				    sizeof (ctrl_msg.vcm_buf));

			} else if (alloced != 0 || deleted != 0) {
				(void) snprintf(ctrl_msg.vcm_buf,
				    sizeof (ctrl_msg.vcm_buf),
				    "%d session(s) loaded\n"
				    "%d session(s) deleted",
				    alloced, deleted);
				vrrp_log(LOG_INFO,
				    "reload: %d alloced, %d deleted",
				    alloced, deleted);
			} else {
				(void) snprintf(ctrl_msg.vcm_buf,
				    sizeof (ctrl_msg.vcm_buf),
				    "no changes to configuration");
			}
			break;

		case CTRL_SHOW:
			if (vrrp_send_session(conn_socket, &ctrl_msg) != 0) {
				(void) strlcpy(ctrl_msg.vcm_buf,
				    "error showing configuration",
				    sizeof (ctrl_msg.vcm_buf));
			} else {
				(void) strlcpy(ctrl_msg.vcm_buf,
				    "show completed",
				    sizeof (ctrl_msg.vcm_buf));
			}
			break;

		case CTRL_SUMMARY:
			vrrp_summary(&ctrl_msg);
			break;

		case CTRL_VIP_STATE:
			if ((n = vrrp_get_state(ctrl_msg.vcm_buf)) != 0) {
				(void) strlcpy(ctrl_msg.vcm_buf,
				    vrrp_state_str(n),
				    sizeof (ctrl_msg.vcm_buf));
			} else {
				(void) strlcpy(ctrl_msg.vcm_buf,
				    "invalid interface",
				    sizeof (ctrl_msg.vcm_buf));
			}
			break;

		case CTRL_CLEAR_COUNTERS:
			vrrp_clear_counters();
			(void) strlcpy(ctrl_msg.vcm_buf, "counters cleared",
			    sizeof (ctrl_msg.vcm_buf));
			break;

		case CTRL_LOG_LEVEL:
			if (vrrp_strtoul(ctrl_msg.vcm_buf, &val) != 0) {
				(void) strlcpy(ctrl_msg.vcm_buf,
				    "failed to convert new log level",
				    sizeof (ctrl_msg.vcm_buf));
				break;
			}

			if (val != LOG_INFO && val != LOG_ERR) {
				(void) strlcpy(ctrl_msg.vcm_buf,
				    "invalid log level specified",
				    sizeof (ctrl_msg.vcm_buf));
				break;
			}

			pthread_mutex_lock(&vrrp_log_mutex);
			vrrp_log_level = (log_level_t)val;
			pthread_mutex_unlock(&vrrp_log_mutex);

			vrrp_log(LOG_INFO, "log level set to %d",
			    vrrp_log_level);
			(void) strlcpy(ctrl_msg.vcm_buf, "log level modified",
			    sizeof (ctrl_msg.vcm_buf));
			break;

		case CTRL_QUIT:
			/*
			 * Let the process termination close conn_socket
			 * so that the 'client' waits on a read until
			 * that happens. This is a slightly abrupt way
			 * of making the quit command seem like a
			 * synchronous call as far as the 'client' is
			 * concerned.
			 */
			vrrp_quit("quitting");
			break;

		case CTRL_VERSION:
			break;

		default:
			break;
		}

		if (write(conn_socket, &ctrl_msg, sizeof (ctrl_msg)) < 0) {
			vrrp_log(LOG_INFO, "server failed to reply");
			break;
		}
	}

	(void) close(conn_socket);
	return (NULL);
}

/*
 * Listener thread. Essentially a server thread that waits for commands
 * to reload, show the configuration, or to have the daemon exit.
 */
int
vrrp_ctrl_listener(void)
{
	int			conn_socket, max, ret;
	struct sockaddr_un	addr = { 0 };
	pthread_attr_t		attr;
	pthread_t		tid;
	fd_set			fds;

	if ((vrrp_unix_socket = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		vrrp_quit("failed to open UNIX socket (%s)", strerror(errno));
	}

	unlink(VRRP_UNIX_SOCKET);
	addr.sun_family = AF_UNIX;
	(void) strlcpy(addr.sun_path, VRRP_UNIX_SOCKET, sizeof (addr.sun_path));

	if (bind(vrrp_unix_socket, (struct sockaddr *)&addr,
	    sizeof (addr)) != 0) {
		vrrp_quit("failed to bind to UNIX socket (%s)",
		    strerror(errno));
	}

	ret = pthread_attr_init(&attr);
	assert(ret == 0);

	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	assert(ret == 0);

	if (listen(vrrp_unix_socket, 10) != 0) {
		vrrp_quit("server failed to listen (%s)", strerror(errno));
	}

	for (;;) {
		FD_ZERO(&fds);
		FD_SET(vrrp_unix_socket, &fds);
		max = vrrp_unix_socket;

		if (select(max + 1, &fds, NULL, NULL, NULL) == -1) {
			if (errno == EINTR) {
				continue;
			}
			vrrp_quit("failed to select on UNIX socket");
		}

		if (!FD_ISSET(vrrp_unix_socket, &fds)) {
			continue;
		}

		if ((conn_socket = accept(vrrp_unix_socket, NULL,
		    NULL)) == -1) {
			vrrp_quit("failed to accept on UNIX socket (%s)",
			    strerror(errno));
		}

		if (pthread_create(&tid, &attr, vrrp_ctrl_handler,
		    (void *)(intptr_t)conn_socket) != 0) {
			vrrp_log(LOG_ERR, "failed to handle client request");
			close(conn_socket);
		}
	}

	ret = pthread_attr_destroy(&attr);
	assert(ret == 0);

	return (0);
}

int
vrrp_init(void)
{
	pthread_mutexattr_t	mattr;
	pthread_rwlockattr_t	rwattr;
	vrrp_session_t		*session;
	struct sigaction	sig = {{ 0 }};
	int			ii, ret, alloced, deleted;

	/*
	 * Ignore SIGPIPE in case a client is terminated while the daemon is
	 * communicating with it.
	 */
	sig.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sig, NULL) != 0) {
		vrrp_quit("failed to ignore SIGPIPE");
	}

	/*
	 * Init the log mutex and open the log file.
	 */
	ret = pthread_mutexattr_init(&mattr);
	assert(ret == 0);
	ret = pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_ERRORCHECK);
	assert(ret == 0);
	ret = pthread_mutex_init(&vrrp_log_mutex, &mattr);
	assert(ret == 0);

	vrrp_log(LOG_INFO, "starting");

	if ((vrrp_garp_socket = socket(PF_PACKET, SOCK_RAW,
	    htons(ETH_P_RARP))) < 0) {
		vrrp_log(LOG_ERR, "failed to open GARP socket (%s)",
		    strerror(errno));
		return (EIO);
	}

	/*
	 * Init the rw lock for vrrp_list_rwlock.
	 */
	ret = pthread_rwlockattr_init(&rwattr);
	assert(ret == 0);
	ret = pthread_rwlock_init(&vrrp_list_rwlock, &rwattr);
	assert(ret == 0);

	vrrp_rwlock_wrlock(&vrrp_list_rwlock);

	/*
	 * Initialize all the session mutexes and mark them as free. These locks
	 * will only be destroyed when quiting.
	 */
	for (ii = 0; ii < MAX_NUM_VRRP_INTF; ii++) {
		session = &vrrp_session_array[ii];

		vrrp_session_clear(session);

		if (pthread_rwlock_init(&session->vs_rwlock, &rwattr) != 0) {
			vrrp_quit("failed to init rwlock %d (%s)", ii,
			    strerror(errno));
		}
	}

	vrrp_rwlock_unlock(&vrrp_list_rwlock);

	/*
	 * Load and setup all config files.
	 */
	if (vrrp_config_load(&alloced, &deleted) != 0) {
		vrrp_log(LOG_INFO, "failed to load config file(s)");
	} else {
		vrrp_log(LOG_INFO, "%d session(s) loaded, "
		    "%d session(s) deleted", alloced, deleted);
	}

	return (vrrp_ctrl_listener());
}

boolean_t
vrrp_is_running(void)
{
	struct sockaddr_un	addr = { 0 };
	int			sock;

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		vrrp_log(LOG_ERR, "failed to open UNIX socket (%s)",
		    strerror(errno));
		return (B_FALSE);
	}

	addr.sun_family = AF_UNIX;
	(void) strlcpy(addr.sun_path, VRRP_UNIX_SOCKET, sizeof (addr.sun_path));

	if (connect(sock, (struct sockaddr *)&addr, sizeof (addr)) == -1) {
		close(sock);
		return (B_FALSE);
	}

	(void) close(sock);

	return (B_TRUE);
}

int
main(int argc, char **argv)
{
	vrrp_ctrl_msg_t	ctrl_msg = { 0 };
	struct rlimit	rl = {VRRP_NFDS, VRRP_NFDS};
	char		ch;
	pid_t		pid;
	boolean_t	running;

	/*
	 * Invoking nvrrp(1) without any options will start the daemon load
	 * any existing configuration. But first we need to check if its
	 * already running.
	 */
	running = vrrp_is_running();

	if (argc > 1) {
		while ((ch = getopt(argc, argv, "rsSv:l:qchV")) != -1) {
			switch (ch) {
			case 'r':
				ctrl_msg.vcm_msg = CTRL_RELOAD;
				break;

			case 's':
				ctrl_msg.vcm_msg = CTRL_SHOW;
				break;

			case 'S':
				ctrl_msg.vcm_msg = CTRL_SUMMARY;
				break;

			case 'v':
				if (optarg != NULL && optarg[0] != '\0') {
					ctrl_msg.vcm_msg = CTRL_VIP_STATE;
					(void) snprintf(ctrl_msg.vcm_buf,
					    sizeof (ctrl_msg.vcm_buf), "%s",
					    optarg);
				}
				break;

			case 'l':
				if (optarg != NULL && optarg[0] != '\0') {
					ctrl_msg.vcm_msg = CTRL_LOG_LEVEL;
					(void) snprintf(ctrl_msg.vcm_buf,
					    sizeof (ctrl_msg.vcm_buf), "%s",
					    optarg);
				}
				break;

			case 'q':
				ctrl_msg.vcm_msg = CTRL_QUIT;
				break;

			case 'c':
				ctrl_msg.vcm_msg = CTRL_CLEAR_COUNTERS;
				break;

			case 'V':
				vrrp_log(LOG_INFO, "nvrrp version %d.%d :: "
				    "http://launchpad.net/nvrrp", VERSION_MAJOR,
				    VERSION_MINOR);
				return (EXIT_SUCCESS);

			case '?':
			case 'h':
			default:
				vrrp_quit("%s", vrrp_usage_str);
			}
		}

		if (ctrl_msg.vcm_msg == 0) {
			vrrp_quit("%s", vrrp_usage_str);
		} else if (!running) {
			vrrp_quit("daemon isn't running");
		}

		return (vrrp_ctrl_send(&ctrl_msg));
	}

	if (running) {
		vrrp_log(LOG_INFO, "daemon is already running");
		return (EXIT_SUCCESS);
	}

	if (getuid() != 0) {
		vrrp_quit("daemon must be started by the root user");
	}

	/*
	 * Daemonize and go into vrrp_init(), which will join on the
	 * the server thread.
	 */
	if ((pid = fork()) < 0) {
		vrrp_quit("failed to fork(2)");
	} else {
		if (pid > 0) {
			exit(EXIT_SUCCESS);
		}
	}

	umask(0);

	if (setsid() < 0) {
		vrrp_quit("failed to create a new session id");
	}

	if ((chdir("/")) < 0) {
		vrrp_quit("failed to move to root directory");
	}

	/*
	 * Don't close STDERR in case we need it before the log file's open.
	 */
	(void) close(STDIN_FILENO);
	(void) close(STDOUT_FILENO);

	if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
		vrrp_quit("failed to set RLIMIT_NOFILE");
	}

	vrrp_daemon = B_TRUE;
	vrrp_log_level = (LOG_ERR | LOG_INFO);

	return (vrrp_init());
}
