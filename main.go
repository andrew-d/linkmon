package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	debug = flag.Bool("debug", false, "debug print netlink messages to stderr")

	addr = flag.Bool("address", true, "monitor address messages")
	link = flag.Bool("link", true, "monitor link messages")
)

func main() {
	log.SetOutput(os.Stderr)
	flag.Parse()

	sock, err := createNetlinkSocket()
	if err != nil {
		log.Fatal(err)
	}
	defer unix.Close(sock)

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}

	ifMap := make(map[int]net.Interface, len(interfaces))
	for _, iif := range interfaces {
		ifMap[iif.Index] = iif
	}

	ifByIndex := func(idx int) string {
		iif, ok := ifMap[idx]
		if !ok {
			return "unknown"
		}
		return iif.Name
	}

	msg := make([]byte, 1<<16)
	for {
		var err error
		var msgn int
		for {
			msgn, _, _, _, err = unix.Recvmsg(sock, msg[:], nil, 0)
			if err == nil || !retryError(err) {
				break
			}
		}
		if err != nil {
			log.Fatal("failed to receive netlink message: %v", err)
		}

		for remain := msg[:msgn]; len(remain) >= unix.SizeofNlMsghdr; {
			hdr := *(*unix.NlMsghdr)(unsafe.Pointer(&remain[0]))

			if int(hdr.Len) > len(remain) {
				break
			}
			switch hdr.Type {
			case unix.NLMSG_DONE:
				remain = nil

			case unix.RTM_NEWLINK, unix.RTM_DELLINK:
				info := *(*unix.IfInfomsg)(unsafe.Pointer(&remain[unix.SizeofNlMsghdr]))
				remain = remain[hdr.Len:]

				isUp := info.Flags&unix.IFF_UP != 0 && info.Flags&unix.IFF_LOWER_UP != 0
				switch {
				case hdr.Type == unix.RTM_NEWLINK && isUp:
					fmt.Printf("+ linkup %s %s\n", ifByIndex(int(info.Index)), families[info.Family])
				case hdr.Type == unix.RTM_NEWLINK && !isUp:
					fmt.Printf("- linkdown %s %s\n", ifByIndex(int(info.Index)), families[info.Family])
				case hdr.Type == unix.RTM_DELLINK:
					fmt.Printf("- link %s %s\n", ifByIndex(int(info.Index)), families[info.Family])
				}

				if *debug {
					var flags, change []string
					for val, ss := range linkFlags {
						if info.Flags&val != 0 {
							flags = append(flags, ss)
						}
						if info.Change&val != 0 {
							change = append(change, ss)
						}
					}
					log.Printf("%s: %+v flags=%+v change=%+v", msgNames[hdr.Type], info, flags, change)
				}

			case unix.RTM_NEWADDR, unix.RTM_DELADDR:
				info := *(*unix.IfAddrmsg)(unsafe.Pointer(&remain[unix.SizeofNlMsghdr]))
				remain = remain[hdr.Len:]

				if hdr.Type == unix.RTM_NEWADDR {
					fmt.Printf("+ addr %s %s\n", ifByIndex(int(info.Index)), families[info.Family])
				} else {
					fmt.Printf("- addr %s %s\n", ifByIndex(int(info.Index)), families[info.Family])
				}
				if *debug {
					log.Printf("%s: %+v", msgNames[hdr.Type], info)
				}

			default:
				remain = remain[hdr.Len:]
				if *debug {
					log.Printf("unknown message: %d", hdr.Type)
				}
			}
		}
	}
}

var msgNames = map[uint16]string{
	unix.RTM_NEWLINK: "RTM_NEWLINK",
	unix.RTM_DELLINK: "RTM_DELLINK",
	unix.RTM_DELADDR: "RTM_DELADDR",
	unix.RTM_NEWADDR: "RTM_NEWADDR",
}

var linkFlags = map[uint32]string{
	unix.IFF_UP:          "IFF_UP",
	unix.IFF_BROADCAST:   "IFF_BROADCAST",
	unix.IFF_DEBUG:       "IFF_DEBUG",
	unix.IFF_LOOPBACK:    "IFF_LOOPBACK",
	unix.IFF_POINTOPOINT: "IFF_POINTOPOINT",
	unix.IFF_RUNNING:     "IFF_RUNNING",
	unix.IFF_NOARP:       "IFF_NOARP",

	unix.IFF_PROMISC:    "IFF_PROMISC",
	unix.IFF_NOTRAILERS: "IFF_NOTRAILERS",
	unix.IFF_ALLMULTI:   "IFF_ALLMULTI",
	unix.IFF_MASTER:     "IFF_MASTER",
	unix.IFF_SLAVE:      "IFF_SLAVE",
	unix.IFF_MULTICAST:  "IFF_MULTICAST",
	unix.IFF_PORTSEL:    "IFF_PORTSEL",
	unix.IFF_AUTOMEDIA:  "IFF_AUTOMEDIA",
	unix.IFF_DYNAMIC:    "IFF_DYNAMIC",

	unix.IFF_LOWER_UP: "IFF_LOWER_UP",
	unix.IFF_DORMANT:  "IFF_DORMANT",
	unix.IFF_ECHO:     "IFF_ECHO",
}

var families = map[uint8]string{
	unix.AF_INET:  "AF_INET",
	unix.AF_INET6: "AF_INET6",
}

func createNetlinkSocket() (int, error) {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, err
	}
	if !*addr && !*link {
		return -1, fmt.Errorf("nothing to monitor")
	}

	var groups uint32
	if *addr {
		groups |= unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR
	}
	if *link {
		groups |= unix.RTMGRP_LINK
	}
	saddr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: groups,
	}
	err = unix.Bind(sock, saddr)
	if err != nil {
		return -1, err
	}
	return sock, nil
}

func retryError(err error) bool {
	return errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR)
}
