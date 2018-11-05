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
        DISABLED \
        DUMMY_MODE \
        FLOOD_PROTECTION \
        GRATUITOUS \
        INIT_MODE \
        LEARNING \
        LOG_MASK \
        PENDING \
        PERMISSIONS \
        PROBERATE \
        QUEUE_DEPTH \
        RATE \
        SPONGE_NETWORK \
        ARP_UPDATE_METHOD \
        SWEEP_AT_START \
        SWEEP \
        SWEEP_SKIP_ALIVE

# Defaults for all sponges.
if test -f @ETC_DEFAULT@/${PROG}/defaults ; then
    . @ETC_DEFAULT@/${PROG}/defaults
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
        # Execute in a sub-shell, so settings in individual interface
        # files do not disturb the global (default) settings.
        DEVICE=$(basename $file)
        unset NETWORK
        . $file

        [ -n "${DEVICE}" ]  || fatal "$file: no device specified"

        if eval_bool "${DISABLED}"
        then
            printf "  %-10s (skipped)\n" "${DEVICE}"
            return
        fi

        [ -n "${NETWORK}" ] || fatal "$file ($DEVICE): no network specified"

        rundir="${SPONGE_VAR}/${DEVICE}"
        pidfile="${rundir}/pid"

        opts="--daemon --rundir=${rundir} --pidfile=${pidfile}"

        eval_bool ${SPONGE_NETWORK}   && opts="$opts --sponge-network"
        eval_bool ${GRATUITOUS}       && opts="$opts --gratuitous"
        eval_bool ${DUMMY_MODE}       && opts="$opts --dummy"
        eval_bool ${SWEEP_SKIP_ALIVE} && opts="$opts --sweep-skip-alive"
        eval_bool ${SWEEP_AT_START}   && opts="$opts --sweep-at-start"

        [ -n "${INIT_MODE}" ]       && opts="$opts --init=${INIT_MODE}"
        [ -n "${LEARNING}" ]        && opts="$opts --learning=${LEARNING}"
        [ -n "${QUEUE_DEPTH}" ]     && opts="$opts --queuedepth=${QUEUE_DEPTH}"
        [ -n "${RATE}" ]            && opts="$opts --rate=${RATE}"
        [ -n "${PENDING}" ]         && opts="$opts --pending=${PENDING}"
        [ -n "${SWEEP}" ]           && opts="$opts --sweep=${SWEEP}"
        [ -n "${PROBERATE}" ]       && opts="$opts --proberate=${PROBERATE}"
        [ -n "${AGE}" ]             && opts="$opts --age=${AGE}"
        [ -n "${LOGMASK}" ]         && opts="$opts --logmask=${LOGMASK}"
        [ -n "${PERMISSIONS}" ]     && opts="$opts --permissions=${PERMISSIONS}"

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
            ${BINDIR}/asctl --interface="${DEVICE}" -c load status "${rundir}/status"
        fi
    )
}


start() {
    SPONGES=$(find "@ETC_DEFAULT@/${PROG}" \
                -maxdepth 1 -type f -name 'eth*' 2>/dev/null)
    if [ -n "${SPONGES}" ]
    then
        echo "Starting ${PROG}(s):"
        for file in ${SPONGES}
        do
            start_sponge "$1" ${file}
        done
    fi
    return 0
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
    return 0
}


status() {
    local pid
    local cruft
    local pidfiles
    local pf
    local isroot=false
    local retval=0

    pidfiles=$(find ${SPONGE_VAR} -mindepth 2 -maxdepth 2 \
                -type f -name pid 2>/dev/null)

    if [ -n "$pidfiles" ]; then
        [ `id -u` = 0 ] && isroot=true

        if [ "X$1" = "Xre-init" ]; then
            echo "Saving state:"
        else
            echo "Arpsponge status:"
        fi

        for pf in $pidfiles
        do
            if [ -f "$pf" ]
            then
                read pid cruft <"${pf}"
                iface=$(basename $(dirname "${pf}"))
                printf "  interface=%-10s pid=%-6s " "${iface}" "${pid}"
                if ps -p "${pid}" > /dev/null 2>&1
                then
                    if $isroot
                    then
                        if kill -USR1 "${pid}" 2>/dev/null
                        then
                            sleep 1
                            echo "[Ok]"
                        else
                            retval=1
                            echo "[FAILED]"
                        fi
                    else
                        echo "[Ok]"
                    fi
                else 
                    retval=1
                    echo "[FAILED]"
                fi
            fi
        done
    else
        if [ "X$1" != "Xre-init" ]; then
            echo "  no arpsponge instance running"
        fi
        retval=1
    fi
    return $retval
}


do_help() {
    cat <<EOF

Usage: $0 {start|stop|restart|flush|reload|force-reload}

    start   - start daemon if not already running (reading state table)

    stop    - stop daemon (saving state table)

    restart, reload, force-reload
            - restart daemon (re-using state table)

    flush   - restart daemon, flushing state table

EOF
}


case "$1" in
    debug)
        SPONGE_DEBUG=true
        start
        ;;
    start)
        start re-init
        ;;
    restart)
        status re-init
        stop
        start re-init
        ;;
    reload|force-reload)
        status re-init
        stop
        start re-init
        ;;
    flush)
        stop
        start
        ;;
    status)
        status
        ;;
    stop)
        status re-init
        stop
        ;;
    help)
        do_help
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|flush|reload|force-reload}"
        exit 1
        ;;
esac

exit $?
