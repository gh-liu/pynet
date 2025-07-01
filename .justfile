run:
    sudo python3 main.py

test:
    ping 192.168.9.1

test_tcp:
    nc 192.168.9.1 82

test_udp:
    nc -zuv 192.168.9.1 82
