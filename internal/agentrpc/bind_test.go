package agentrpc

import "testing"

// TestValidateListenAddrRejectsNonLAN은 R7 bind 거절 목록을 본다: wildcard(0.0.0.0·::)·빈 host·
// hostname·공개 IP를 전부 거절하고, private LAN·loopback literal IP만 통과시킨다.
func TestValidateListenAddrRejectsNonLAN(t *testing.T) {
	reject := []string{
		"0.0.0.0:9000",     // IPv4 wildcard
		"[::]:9000",        // IPv6 wildcard
		":9000",            // 빈 host = wildcard
		"deploy.host:9000", // hostname(literal IP 아님)
		"8.8.8.8:9000",     // 공개 IP(인터넷 노출)
		"10.0.0.5",         // 포트 없음
		"",                 // 빈 주소
	}
	for _, addr := range reject {
		if _, err := ValidateListenAddr(addr); err == nil {
			t.Errorf("%q는 거절돼야 한다(LAN bind 위반)", addr)
		}
	}

	accept := []string{
		"10.0.0.158:9000",   // 10/8 private
		"172.16.0.1:9000",   // 172.16/12 private
		"192.168.1.10:9000", // 192.168/16 private
		"127.0.0.1:9000",    // loopback(테스트·단일 호스트)
		"[fd00::1]:9000",    // fc00::/7 ULA private
	}
	for _, addr := range accept {
		if _, err := ValidateListenAddr(addr); err != nil {
			t.Errorf("%q는 통과해야 한다(private LAN·loopback): %v", addr, err)
		}
	}
}
