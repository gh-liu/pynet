import json
import socket


CRLF = b"\r\n"


def main():
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.bind(("127.0.0.1", 9999))
    sk.listen()
    (client_sk, addr) = sk.accept()
    # print(f"Rec conn from {addr}")
    data = client_sk.recv(1024)
    parse_request(data)
    resp_data = make_resp()
    client_sk.send(resp_data)
    client_sk.close()
    sk.close()


def parse_request(data):
    # print("Rec data: ", data)
    lines = data.split(sep=CRLF)
    # 1. start_line
    start_line = lines[0]
    parts = start_line.split(b" ")
    print("method: ", parts[0].decode("utf-8"))
    print("path: ", parts[1].decode("utf-8"))
    print("protocol: ", parts[2].decode("utf-8"))

    # 2. headers
    headers = {}
    idx = 1
    while idx < len(lines):
        parts = lines[idx].split(b":")
        if len(parts) < 2:
            break

        headers[parts[0].decode("utf-8").strip()] = parts[1].decode("utf-8").strip()
        idx = idx + 1
    print("headers:", headers)
    # 3. body
    # NOTE: why idx+1, two CRLF here
    body_lines = lines[idx + 1 :] if idx < len(lines) else []
    body = CRLF.join(body_lines)
    print("body:", body)
    cl = headers.get("Content-Length")
    if cl:
        print(cl)
    if headers.get("Content-Type") == "application/json":
        d = json.loads(body)
        print(d)


def make_resp() -> bytes:
    start_line = " ".join(
        [
            "HTTP/1.1",
            "200",
            "OK",
        ]
    )
    start_line_bytes = start_line.encode("utf-8")

    headers_lines_bytes = bytes()
    headers = {}
    headers["Content-Length"] = "16"
    headers["Content-Type"] = "application/json"
    for k, v in headers.items():
        headers_lines_bytes += k.encode("utf-8") + b": " + v.encode("utf-8") + CRLF
    headers_lines_bytes += CRLF

    data = {"yo": "hey"}
    data_bytes = json.dumps(data).encode("utf-8")

    return start_line_bytes + headers_lines_bytes + data_bytes


if __name__ == "__main__":
    main()
