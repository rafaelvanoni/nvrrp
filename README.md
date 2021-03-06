### Introduction

nvrrp is an implementation of the Virtual Router Redundancy Protocol version 3 (VRRPv3) described in [RFC 5798](https://tools.ietf.org/html/rfc5798) originally developed at [Pluribus Networks](http://pluribusnetworks.com/). nvrrp is currently only built and tested on Linux based operating systems.

### Design Principles

nvrrp's design goals are stability, scalability, readability and maintainability. It must able to support thousands of sessions, with an easy to read and easy to maintain source. It also features straight forward logging and monitoring features, making it easy to deploy and support.

With those goals in mind, nvrrp was implemented through a daemon that manages one session thread per VRRP instance. Once running, it is possible to query the daemon's running state in a few different ways, as well as to request a reload of the configuration and to have it exit. All these operations are synchronous (i.e the command waits until the operation is complete) and output to the standard output. Logging is implemented with a simple rotating mechanism between two files.

### Work in Progress

The current version only supports IPv4 addresses and doesn't support sub-second advertisement intervals, but both of these limitations are being actively developed. It also doesn't support the 'accept_mode' option (secion 6.1 in the RFC).

### Acknowledgements

nvrrp was written from scratch but took a hint or two from existing/defunct vrrp implementations (namely the vrrpd and keepalived projects). We're grateful for those ideas and the people who implemented them.

### Requirements

nvrrp requires libc, libpthread, librt and libbsd.

### Configuration

nvrrp configuration files must be placed under the `/etc/nvrrp` directory, one file per VRRP session. Here's an example of such a file:
```C
    $ cat /etc/nvrrp/nvrrp.example
    #
    # example nvrrp instance
    #
    primary_intf eth1.2
    vrrp_intf eth2.2
    vip 2.2.2.1/16
    vrid 5
    priority 100
    advert_int 1000
```
All the fields are required. Note that the advert_int is specified in milliseconds.

nvrrp does not create any of the specified interfaces, it expects them to be present and the vrrp_intf to have a standard VRRP MAC address (00-00-5E-00-01-{VRID in hexadecimal}). Please consult the documentation of your Linux distribution on how to specify the appropriate MAC address for your VRRP interface(s).

There are a handful of Linux kernel tunables that must be applied either system wide or on a per interface basis to allow nvrrp to funtion correctly. These are mostly related to ARP and reverse path filtering. We recommend setting
```
    net.ipv4.conf.all.arp_ignore=1
    net.ipv4.conf.all.rp_filter=0
    net.ipv4.conf.default.rp_filter=0
    net.ipv4.icmp_errors_use_inbound_ifaddr=1
```
and for each interfaca (primary or virtual):
```
    net.ipv4.conf.eth0.arp_notify=1
    net.ipv4.conf.eth0.arp_announce=2
    net.ipv4.conf.eth0.rp_filter=2
```
Please consult your distribution's documentation before changing any tunables.

### Debugging

nvrrp offers a client that can be used to gather information from the current state. Here are the available options and example outputs:
```
    # nvrrp -h
    usage: nvrrp [ -r | -s | -S | -v [vip] | -q | -h ]
        -r         reload configuration
        -s         show complete state
        -S         show summary of current sessions
        -v [vip]   show the state of a given vip interface
        -q         quit the nvrrp daemon
        -h         show this help message

    # nvrrp -s
              filename /etc/nvrrp/vrrp5.2
          primary intf eth1.2
            primary IP 2.2.2.13
          primary addr 2.2.2.13
       primary netmask 255.255.0.0
           primary MAC 66:0e:94:99:c5:e0
           primary idx 1010
              vip intf eth2.2
                vip IP 2.2.2.1/16
              vip addr 2.2.2.1
           vip netmask 255.255.0.0
               vip MAC 00:00:5e:00:01:05
               vip idx 1012
                  vrid 5
              priority 100
          adv interval 1000000000
        master adv int 1000000000
       master down int 1000000000
             skew time 609375000
             timer adv 559146 397622489
           timer mdown 0 0
              iphdr id 564
               version 3
                 state master
         allow preempt yes
       slave to master 1
       master to slave 0
      slave to initial 0
     master to initial 0
         adverts recvd 0
          adverts sent 564
           send errors 0

    # nvrrp -S
    0 initial session(s)
    0 slave session(s)
    1 master session(s)

    # nvrrp -v eth2.2
    master
```
Note that the interval values above are in nanoseconds and the timers are in the "seconds nanosecons" format.

nvrrp logs to `/var/log/nvrrp.log`, rotated with `/var/log/nvrrp.log.prev`

Most runtime errors are recoverable and will cause the session thread to transition between different states, essentially starting over. This can result in a series of transitions until the error is corrected (a common case is when the primary interface goes down unexpectedly). Check the log file(s) for more detail.

In case an irrecoverable error happens, the session thread will exit.

### License

The nvrrp project is licensed under the GPLv2 license.

