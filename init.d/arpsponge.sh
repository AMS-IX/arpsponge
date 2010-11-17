#!/bin/sh
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
SPONGE_OPTIONS="@SPONGE_OPTIONS@"

# Program defaults
export  AGE \
        DUMMY_MODE \
        FLOOD_PROTECTION \
        GRATUITOUS \
        INIT_MODE \
        LEARNING \
        NOTIFY \
        PENDING \
        PROBERATE \
        QUEUE_DEPTH \
        RATE \
        SPONGE_NETWORK \
        SWEEP

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
    file=$1
    export file
    (
        DEVICE=$(basename $file)
        unset NETWORK
        . $file

        notify="${SPONGE_VAR}/${DEVICE}/notify"
        status="${SPONGE_VAR}/${DEVICE}/status"
        pidfile="${SPONGE_VAR}/${DEVICE}/pid"

        opts="--statusfile='${status}'"
        eval_bool ${NOTIFY}         && opts="$opts --notify ${notify}"
        eval_bool ${SPONGE_NETWORK} && opts="$opts --sponge-network"
        eval_bool ${GRATUITOUS}     && opts="$opts --gratuitous"
        [ -n "${INIT_MODE}" ]       && opts="$opts --init=${INIT_MODE}"
        [ -n "${LEARNING}" ]        && opts="$opts --learning=${LEARNING}"
        [ -n "${QUEUE_DEPTH}" ]     && opts="$opts --queuedepth=${QUEUE_DEPTH}"
        [ -n "${RATE}" ]            && opts="$opts --rate=${RATE}"
        [ -n "${PENDING}" ]         && opts="$opts --pending=${PENDING}"
        [ -n "${SWEEP}" ]           && opts="$opts --sweep=${SWEEP}"
        [ -n "${PROBERATE}" ]       && opts="$opts --proberate=${PROBERATE}"
        [ -n "${AGE}" ]             && opts="$opts --age=${AGE}"
		if [ -n "${FLOOD_PROTECTION}" ]; then
            opts="$opts --flood-protection=${FLOOD_PROTECTION}"
        fi

        # DUMMY_MODE and --daemon are mutually exclusive
        # so make DUMMY_MODE imply SPONGE_DEBUG
        if eval_bool ${DUMMY_MODE}; then
            opts="$opts --dummy"
            SPONGE_DEBUG=true
        else
            opts="$opts --daemon='${pidfile}'"
        fi

        if [ ! -n "${DEVICE}" ]
        then
            fatal "$file: no device specified"
        fi
        if [ ! -n "${NETWORK}" ]
        then
            fatal "$file ($DEVICE): no network specified"
        fi

        if eval_bool $SPONGE_DEBUG
        then
            echo "** DEBUG MODE:"
            echo "** command line:"
            echo "----"
            echo ${BINDIR}/${PROG} ${opts} ${NETWORK} dev "${DEVICE}"
            echo "----"
            echo "** DEBUG MODE: not executing"
            exit 0
        fi

        mkdir -p "${SPONGE_VAR}/${DEVICE}"

        if eval_bool ${NOTIFY}
        then
            # Create notification FIFO...
            if [ ! -p "${notify}" ]; then
                if ! /usr/bin/mkfifo --mode=644 "${notify}"; then
                    fatal "cannot create ${notify} fifo"
                fi
            fi
        fi

        printf "  %-10s " "${DEVICE}"

        ${BINDIR}/${PROG} ${opts} ${NETWORK} dev "${DEVICE}" 2>/dev/null
    
        [ $? -eq 0 ] && echo "[Ok]" || echo "[FAILED]"
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
