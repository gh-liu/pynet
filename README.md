# pynet

> implement net stack for leanring purpose

## icmp check sum

starting with the ICMP Type, every two byte is a 16bit number,
if the total length is odd, the received data is padded with one byte of zeros,
add all the 16-bit numbers together,
if the result is greater than 16 bits, wrap around by adding the overflow (higher part) back into the lower 16 bits,
then bitwise NOT the result and limit it only 16bit.
