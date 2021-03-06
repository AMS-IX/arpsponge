#!/bin/sh
### BEGIN INIT INFO
# Provides:          @NAME@
# Required-Start:    $network
# Required-Stop:     $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: @NAME@ daemon
### END INIT INFO

#############################################################################
#############################################################################
#
# Start-up script for the arpsponge program.
#
#############################################################################

if [ -e /lib/lsb/init-functions ]; then
  . /lib/lsb/init-functions
fi

BINDIR=@BINDIR@
#BINDIR=../bin
PATH=/sbin:/bin:/usr/bin:${BINDIR}

PROG=@NAME@
SPONGE_VAR=@SPONGE_VAR@
ETC_DEFAULT=@ETC_DEFAULT@

# Program defaults
export  \
        AGE \
        ARP_UPDATE_METHOD \
        DISABLED \
        DUMMY_MODE \
        FLOOD_PROTECTION \
        GRATUITOUS \
        INIT_MODE \
        LEARNING \
        LOG_MASK \
        PASSIVE_MODE \
        PENDING \
        PERMISSIONS \
        PROBERATE \
        QUEUE_DEPTH \
        RATE \
        SPONGE_NETWORK \
        STATIC_MODE \
        SWEEP \
        SWEEP_AT_START \
        SWEEP_SKIP_ALIVE

Main() {
    # Defaults for all sponges.
    if [ -f "${ETC_DEFAULT}/${PROG}/defaults" ]; then
        . "${ETC_DEFAULT}/${PROG}/defaults"
        # Make sure the "defaults" file doesn't accidentally overwrite
        # our ETC_DEFAULT.
        ETC_DEFAULT=@ETC_DEFAULT@

        check_global_unset DEVICE NETWORK STATIC_STATE_FILE
    fi

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
}


start() {
    local config_dir="$ETC_DEFAULT/${PROG}"
    SPONGES=$(find_legacy_interface_configs "$config_dir")

    if [ -d "$config_dir/interfaces.d" ]; then
        # Allow interface configs to be put in "interfaces.d"
        # sub-directory, so the name can be anything, including
        # "defaults".
        if [ -n "$SPONGES" ]; then
            echo "${PROG}: WARNING: interface configurations" \
                "will be taken from $config_dir/interfaces.d"
            echo "${PROG}: WARNING: interface configurations" \
                "from $config_dir will be ignored: $SPONGES"
        fi
        config_dir="$config_dir/interfaces.d"
        SPONGES=$(find_interface_configs $config_dir)
    fi

    if [ -n "${SPONGES}" ]
    then
        echo "Starting ${PROG}(s):"
        for file in ${SPONGES}
        do
            start_sponge "$1" ${file}
        done
    else
        echo "${PROG}: WARNING: no interface configuration files found in" \
            "$config_dir -- no ${PROG}(s) started"
    fi
    return 0
}


stop() {
    echo "Stopping ${PROG}(s):"
    local pf
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
    local pidfiles

    pidfiles=$(find ${SPONGE_VAR} -mindepth 2 -maxdepth 2 \
                -type f -name pid 2>/dev/null)

    if [ ! -n "$pidfiles" ]; then
        if [ "X$1" != "Xre-init" ]; then
            echo "  no arpsponge instance running"
        fi
        return 1
    fi

    local isroot=false

    [ `id -u` = 0 ] && isroot=true

    if [ "X$1" = "Xre-init" ]; then
        echo "Saving state:"
    else
        echo "Arpsponge status:"
    fi

    local retval=0
    local pf
    local pid
    local cruft
    for pf in $pidfiles
    do
        if [ -f "$pf" ]
        then
            read pid cruft <"${pf}"
            rundir=$(dirname "${pf}")
            iface=$(basename "${rundir}")
            socket="${rundir}/control"
            status="${rundir}/status"
            printf "  interface=%-10s pid=%-6s " "${iface}" "${pid}"
            if ps -p "${pid}" > /dev/null 2>&1
            then
                if $isroot
                then
                    out=$(
                        ${BINDIR}/asctl \
                            --socket="${socket}" \
                            -c dump status "${status}" \
                        2>&1
                    )
                    if [ $? -eq 0 ]; then
                        echo "[Ok]"
                        [ -n "$out" ] && echo "  $out"
                    else
                        retval=1
                        echo "[FAILED]"
                        [ -n "$out" ] && echo "  $out"
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


# start_sponge MODE CONFIG_FILE
#
#   MODE        - either "re-init" or "".
#   CONFIG_FILE - location of the interface configuration file.
#
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
        unset STATIC_STATE_FILE
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

        opts=$(fix_opts_bool "$opts" --dummy "${DUMMY_MODE}")
        opts=$(fix_opts_bool "$opts" --passive "${PASSIVE_MODE}")
        opts=$(fix_opts_bool "$opts" --static "${STATIC_MODE}")
        opts=$(fix_opts_bool "$opts" --sponge-network "${SPONGE_NETWORK}")
        opts=$(fix_opts_bool "$opts" --gratuitous "${GRATUITOUS}")
        opts=$(fix_opts_bool "$opts" --sweep-skip-alive "${SWEEP_SKIP_ALIVE}")
        opts=$(fix_opts_bool "$opts" --sweep-at-start "${SWEEP_AT_START}")

        opts=$(fix_opts "$opts" --init "${INIT_MODE}")
        opts=$(fix_opts "$opts" --learning "${LEARNING}")
        opts=$(fix_opts "$opts" --queuedepth "${QUEUE_DEPTH}")
        opts=$(fix_opts "$opts" --rate "${RATE}")
        opts=$(fix_opts "$opts" --pending "${PENDING}")
        opts=$(fix_opts "$opts" --sweep "${SWEEP}")
        opts=$(fix_opts "$opts" --proberate "${PROBERATE}")
        opts=$(fix_opts "$opts" --age "${AGE}")
        opts=$(fix_opts "$opts" --logmask "${LOGMASK}")
        opts=$(fix_opts "$opts" --permissions "${PERMISSIONS}")
        opts=$(fix_opts "$opts" --arp-update-method "${ARP_UPDATE_METHOD}")
        opts=$(fix_opts "$opts" --flood-protection "${FLOOD_PROTECTION}")

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
            ${BINDIR}/asctl \
                --interface="${DEVICE}" \
                -c load status "${rundir}/status"
        fi

        if eval_bool "${STATIC_MODE}" && [ -n "${STATIC_STATE_FILE}" ]
        then
            ${BINDIR}/asctl \
                --interface="${DEVICE}" \
                -c load status --force "${STATIC_STATE_FILE}"
        fi
    )
}

# LIST=$(find_legacy_interface_configs DIR)
#
#   List legacy configuration files in DIR.
#
#   This is basically any regular file in DIR
#   that starts with `eth`
#
find_legacy_interface_configs() {
    local config_dir=$1
    find "$config_dir" \
        -maxdepth 1 \
        -type f \
        -name 'eth*' \
    | sort 2>/dev/null
}

# LIST=$(find_interface_configs DIR)
#
#   List configuration files in DIR.
#
#   This is basically any regular, non-hidden
#   file in DIR.
#
find_interface_configs() {
    local config_dir=$1
    find "$config_dir" \
        -maxdepth 1 \
        -type f \
        \! -name '.*' \
    | sort 2>/dev/null
}

# check_global_unset VAR1 VAR2 ...
#
#   Check if variables VAR1 ... have values set.
#   If so, issue a warning.
#
check_global_unset() {
    local val
    local varname
    for varname in "$@"; do
        eval val="\$$varname"
        if [ -n "$val" ]; then
            echo "${PROG}: WARNING: global $varname setting" \
                "will be ignored; specify in the interface-specific" \
                "configuration instead"
        fi
    done
}

# eval_bool $var && echo TRUE
#
#   Evaluate "$var" as a boolean expression.
#   $? status indicates true/false.
#
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


# fatal MSG ...
fatal() {
    echo "** arpsponge init error:" $@ >&2
    exit 1
}


# opts=$(fix_opts_bool "$opts" "$opt" "$val")
#
#   Add "$opt" to "$opts" if "$val" evaluates to true.
#
fix_opts_bool() {
    local opts="$1"
    local opt="$2"
    local val="$3"
    eval_bool "$val" && opts="$opts $opt"
    echo "$opts"
}


# opts=$(fix_opts "$opts" "$opt" "$val")
#
#   Add "$opt=$val" to "$opts" if "$val" has length > 0
#
fix_opts() {
    local opts="$1"
    local opt="$2"
    local val="$3"
    [ -n "$val" ] && opts="$opts $opt=$val"
    echo "$opts"
}

Main "$@"
exit $?
