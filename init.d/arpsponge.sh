#!/bin/bash
### BEGIN INIT INFO
# Provides:          arpsponge
# Required-Start:    $network
# Required-Stop:     $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Starts the arpsponge daemon
### END INIT INFO

###############################################################################
# @(#) $Id$
###############################################################################
#
# Start-up script for the arpsponge program.
#
###############################################################################

BINDIR=@BINDIR@
#BINDIR=../bin
PATH=/sbin:/bin:/usr/bin:${BINDIR}

PROG=arpsponge
SPONGE_VAR=@SPONGE_VAR@

# Program defaults
export  AGE \
        DUMMY_MODE \
        FLOOD_PROTECTION \
        GRATUITOUS \
        INIT_MODE \
        LEARNING \
        PENDING \
        PROBERATE \
        QUEUE_DEPTH \
        RATE \
        SPONGE_NETWORK \
        ARP_UPDATE_METHOD \
        SWEEP \
        SWEEP_SKIP_ALIVE

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

fatal() {
    echo "** arpsponge init error:" $@ >&2
    exit 1
}

start_sponge() {
    mode="$1"
    file="$2"
    export file
    export mode
    (
        DEVICE=$(basename $file)
        unset NETWORK
        . $file

        [ -n "${DEVICE}" ]  || fatal "$file: no device specified"
        [ -n "${NETWORK}" ] || fatal "$file ($DEVICE): no network specified"

        rundir="${SPONGE_VAR}/${DEVICE}"
        pidfile="${rundir}/pid"

        opts="--daemon --rundir=${rundir} --pidfile=${pidfile}"

        eval_bool ${SPONGE_NETWORK} && opts="$opts --sponge-network"
        eval_bool ${GRATUITOUS}     && opts="$opts --gratuitous"
        eval_bool ${DUMMY_MODE}     && opts="$opts --dummy"
        eval_bool ${SWEEP_SKIP_ALIVE} && opts="$opts --sweep-skip-alive"

        [ -n "${INIT_MODE}" ]       && opts="$opts --init=${INIT_MODE}"
        [ -n "${LEARNING}" ]        && opts="$opts --learning=${LEARNING}"
        [ -n "${QUEUE_DEPTH}" ]     && opts="$opts --queuedepth=${QUEUE_DEPTH}"
        [ -n "${RATE}" ]            && opts="$opts --rate=${RATE}"
        [ -n "${PENDING}" ]         && opts="$opts --pending=${PENDING}"
        [ -n "${SWEEP}" ]           && opts="$opts --sweep=${SWEEP}"
        [ -n "${PROBERATE}" ]       && opts="$opts --proberate=${PROBERATE}"
        [ -n "${AGE}" ]             && opts="$opts --age=${AGE}"

        if [ -n "${ARP_UPDATE_METHOD}" ]; then
            opts="$opts --arp-update-method=${ARP_UPDATE_METHOD}"
        fi

		if [ -n "${FLOOD_PROTECTION}" ]; then
            opts="$opts --flood-protection=${FLOOD_PROTECTION}"
        fi

        if eval_bool $SPONGE_DEBUG
        then
            echo "** DEBUG MODE:"
            echo "** command line:"
            echo "----"
            echo ${BINDIR}/${PROG} ${opts} ${NETWORK} dev "${DEVICE}"
            echo "----"
            echo "** DEBUG MODE: not executing"
            return 0
        fi

        mkdir -p "${SPONGE_VAR}/${DEVICE}"

        printf "  %-10s " "${DEVICE}"

        ${BINDIR}/${PROG} ${opts} ${NETWORK} dev "${DEVICE}" 2>/dev/null
    
        [ $? -eq 0 ] && echo "[Ok]" || echo "[FAILED]"

        if [ "$mode" = "re-init" ] && [ -f "${rundir}/status" ]
        then
            ${BINDIR}/asctl -c load status "${rundir}/status"
        fi
    )
}

start() {
    SPONGES=$(find "/etc/default/${PROG}" \
                -maxdepth 1 -type f -name 'eth*' 2>/dev/null)
    if [ -n "${SPONGES}" ]
    then
        echo "Starting ${PROG}(s):"
        for file in ${SPONGES}
        do
            start_sponge "$1" ${file}
        done
    fi
}

stop() {
    echo "Stopping ${PROG}(s):"
    local pid
    local cruft
    for pf in ${SPONGE_VAR}/*/pid
    do
        if [ -f "$pf" ]
        then
            read pid cruft <"${pf}"
            iface=$(basename $(dirname "${pf}"))
            printf "  interface=%-10s pid=%-6s " "${iface}" "${pid}"
            # Don't use kill -0. The point is to check whether the process
            # exists, not whether we can send it a signal.
            if ps -p "${pid}" > /dev/null 2>&1
            then
                kill -TERM "${pid}"
                sleep 1
                if ps -p "${pid}" > /dev/null 2>&1
                then
                    kill -KILL "${pid}"
                    echo KILLED
                else
                    echo terminated
                fi
            else
                echo already dead
                /bin/rm -f "${pf}"
            fi
        fi
    done
}

status() {
    local pid
    local cruft
    local pidfiles
    local pf
    local retval=0

    if [ "X$1" = "Xre-init" ]
    then
        echo "Saving state:"
    else
        echo "Dumping status:"
    fi

    pidfiles=$(find ${SPONGE_VAR} -mindepth 2 -maxdepth 2 \
                -type f -name pid 2>/dev/null)
    for pf in $pidfiles
    do
        if [ -f "$pf" ]
        then
            read pid cruft <"${pf}"
            iface=$(basename $(dirname "${pf}"))
            printf "  interface=%-10s pid=%-6s " "${iface}" "${pid}"
            if kill -USR1 "${pid}" 2>/dev/null
            then
                sleep 1
                echo "[Ok]"
            else
                retval=1
                echo "[FAILED]"
            fi
        fi
    done
    return $retval
}

case "$1" in
    debug)
        SPONGE_DEBUG=true
        start
        ;;
    start)
        start
        ;;
    restart)
        status re-init
        stop
        start
        ;;
    reload|force-reload)
        status re-init
        stop
        start re-init
        ;;
    status)
        status
        ;;
    stop)
        status re-init
        stop
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|reload|force-reload}"
        exit 1
        ;;
esac

exit 0
