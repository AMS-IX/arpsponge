#!/bin/sh
###############################################################################
# @(#) $Id$
###############################################################################
#
# Start-up script for the arpsponge program.
#
###############################################################################

PATH=/sbin:/bin:/usr/bin:@BINDIR@

PROG=arpsponge
SPONGE_VAR=@SPONGE_VAR@
SPONGE_OPTIONS="@SPONGE_OPTIONS@"

# Program defaults
export DUMMY_MODE INIT_MODE SPONGE_NETWORK LEARNING
export QUEUE_DEPTH RATE PENDING SWEEP GRATUITOUS AGE

# Defaults for all sponges.
if test -f /etc/default/${PROG}/defaults ; then
	. /etc/default/${PROG}/defaults
fi

eval_bool() {
	var=$1
	case $var in
		[1-9]*|0[1-9]*|y|yes|true|on|Y|YES|TRUE|ON)
			true
			return;;
		*)
			false
			return;;
	esac
}

start_sponge() {
	file=$1
	export file
	(
		DEVICE=$(basename $file)
		unset NETWORK
		. $file
		opts=''
		eval_bool ${DUMMY_MODE}     && opts="$opts --dummy"
		eval_bool ${SPONGE_NETWORK} && opts="$opts --sponge-network"
		eval_bool ${GRATUITOUS}     && opts="$opts --gratuitous"
		[ -n "${INIT_MODE}" ]       && opts="$opts --init=${INIT_MODE}"
		[ -n "${LEARNING}" ]        && opts="$opts --learning=${LEARNING}"
		[ -n "${QUEUE_DEPTH}" ]     && opts="$opts --queuedepth=${QUEUE_DEPTH}"
		[ -n "${RATE}" ]            && opts="$opts --queuedepth=${RATE}"
		[ -n "${PENDING}" ]         && opts="$opts --pending=${PENDING}"
		[ -n "${SWEEP}" ]           && opts="$opts --sweep=${SWEEP}"
		[ -n "${AGE}" ]             && opts="$opts --age=${AGE}"

		if [ ! -n "${DEVICE}" ]
		then
			echo "** arpsponge init error: $file: no device specified">&2
			exit 1
		fi
		if [ ! -n "${NETWORK}" ]
		then
			echo "** arpsponge init error: $file ($DEVICE): no network specified">&2
			exit 1
		fi

		notify="${SPONGE_VAR}/${DEVICE}/notify"
		status="${SPONGE_VAR}/${DEVICE}/status"
		pidfile="${SPONGE_VAR}/${DEVICE}/pid"

		if eval_bool $SPONGE_DEBUG
		then
			echo @BINDIR@/${PROG} ${opts} --daemon="${pidfile}" \
					--notify="${notify}" --statusfile="${status}" \
					${NETWORK} dev "${DEVICE}"
		else
			mkdir -p "${SPONGE_VAR}/${DEVICE}"

			# Create notification FIFO...
			[ -p "${notify}" ] || /usr/bin/mkfifo --mode=644 "${notify}"

			printf "  %-10s " "${DEVICE}"

			@BINDIR@/${PROG} ${opts} --daemon="${pidfile}" \
				--notify="${notify}" --statusfile="${status}" \
				${NETWORK} dev "${DEVICE}" 2>/dev/null
		
			[ $? -eq 0 ] && echo "[Ok]" || echo "[FAILED]"
		fi
	)
}

start() {
	SPONGES=`/bin/ls -1 /etc/default/${PROG}/eth* 2>/dev/null`
	if [ -n "${SPONGES}" ]
	then
		echo "Starting ${PROG}(s):"
		for file in ${SPONGES}
		do
			start_sponge ${file}
		done
	fi
}

stop() {
	echo "Stopping ${PROG}(s):"
	pidfiles=`ls ${SPONGE_VAR}/*/pid 2>/dev/null`
	for pf in ${pidfiles}
	do
		pid=$(cat ${pf})
		iface=$(basename $(dirname ${pf}))
		printf "  interface=%-10s pid=%-6s " ${iface} ${pid}
		kill -TERM ${pid}
		sleep 1
		if ps -p ${pid} > /dev/null 2>&1
		then
			kill -KILL ${pid}
			echo KILLED
		else
			echo terminated
		fi
		/bin/rm -f ${SPONGE_VAR}/${iface}/notify
	done
}

status() {
	if [ "X$1" = "Xre-init" ]
	then
		echo "Saving state:"
	else
		echo "Dumping status:"
	fi
	pidfiles=`ls ${SPONGE_VAR}/*/pid 2>/dev/null`
	for pf in ${pidfiles}
	do
		pid=$(cat ${pf})
		iface=$(basename $(dirname ${pf}))
		printf "  interface=%-10s pid=%-6s " ${iface} ${pid}
		kill -USR1 ${pid} 2>/dev/null && echo "[Ok]" || echo "[FAILED]"
	done
}

case "$1" in
	start)
		start
		;;
	restart|reload|force-reload)
		status re-init
		stop
		start re-init
		;;
	status)
		status
		;;
	stop)
		stop
		;;
	*)
		echo "Usage: $0 {start|stop|restart|reload|force-reload}"
		exit 1
		;;
esac

exit 0
