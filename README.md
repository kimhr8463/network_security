# PCAP TCP/HTTP Packet Sniffer

libpcap으로 Ethernet/IPv4/TCP 패킷을 캡처하고 다음 정보를 출력하는
C 프로그램입니다.

- Ethernet 출발지/목적지 MAC 주소
- IPv4 출발지/목적지 주소
- TCP 출발지/목적지 포트
- IP/TCP 헤더 길이
- TCP 페이로드에 포함된 평문 HTTP 메시지

UDP와 IPv4가 아닌 Ethernet 프레임은 무시합니다. HTTPS는 암호화되어
있으므로 HTTP 메시지 본문을 평문으로 출력할 수 없습니다.

## 빌드

Ubuntu 24.04 기준:

```bash
sudo apt update
sudo apt install -y build-essential libpcap-dev
make
```

## 실행

사용 가능한 인터페이스 확인:

```bash
ip -br address
```

라이브 캡처:

```bash
sudo ./pcap_http_sniffer -i enp0s3
sudo ./pcap_http_sniffer -i enp0s3 -c 10
```

저장된 PCAP 재생:

```bash
./pcap_http_sniffer -r sample_http.pcap
```

HTTP 시험 트래픽 생성 예:

```bash
python3 -m http.server 8080
curl http://127.0.0.1:8080/
```

루프백 인터페이스의 데이터 링크 형식은 Ethernet이 아닐 수 있습니다.
이 프로그램은 과제 범위에 맞춰 `DLT_EN10MB` 형식만 처리하므로,
Ethernet 형식으로 저장된 PCAP 또는 Ethernet NIC를 사용해야 합니다.

## GitHub

참고 저장소: <https://github.com/pwnhyo/network_security_codes>

