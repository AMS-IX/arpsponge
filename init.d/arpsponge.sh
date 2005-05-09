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

if test -f /etc/default/${PROG}/defaults ; then
	. /etc/default/${PROG}/defaults
fi

start() {
	[ "X$1" = "Xre-init" ] && re_init=true || re_init=false

	SPONGES=`/bin/ls -1 /etc/default/${PROG}/eth* 2>/dev/null`
	if [ -n "${SPONGES}" ]
	then
		echo "Starting ${PROG}(s):"
		for file in ${SPONGES}
		do
			if=$(basename "${file}")
			mkdir -p "${SPONGE_VAR}/${if}"
			notify="${SPONGE_VAR}/${if}/notify"
			status="${SPONGE_VAR}/${if}/status"
			pidfile="${SPONGE_VAR}/${if}/pid"

			# Create notification FIFO...
			[ -p "${notify}" ] || /usr/bin/mkfifo --mode=644 "${notify}"

			printf "  %-10s " "${if}"

			if ${re_init} && [ -f ${status} ]
			then
				init_arg="--re-init=${status}"
			else
				init_arg=''
			fi
			@BINDIR@/${PROG} ${SPONGE_OPTIONS} --daemon="${pidfile}" \
				--notify="${notify}" --statusfile="${status}" \
				${init_arg} \
				$(/bin/cat "/etc/default/${PROG}/${if}") \
				dev "${if}" 2>/dev/null \
					&& echo "[Ok]" || echo "[FAILED]"
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
