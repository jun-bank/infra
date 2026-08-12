package store

import (
	"encoding/json"
	"testing"
)

// 회귀(리뷰 P1 · 2026-08-12): deploy_history.detail은 JSON 컬럼이라 평문 문자열을 그대로
// 바인딩하면 MySQL이 INSERT 전체를 거부한다(하필 UNKNOWN 이력이 통째로 유실). detailJSON은
// 항상 유효 JSON을 만들어야 한다(비었으면 호출부가 NULL로 두므로 여기선 비지 않은 입력만).
func TestDetailJSONProducesValidJSON(t *testing.T) {
	cases := []string{
		`dispatch: compose up 실패`,
		`이미지 대조 실패 · green 정리(down)도 실패 — 원인="x" · down="y"`,
		`quotes " backslash \ newline
tab	end`,
		"unicode 한글 · émoji 😀",
	}
	for _, s := range cases {
		v := detailJSON(s)
		str, ok := v.(string)
		if !ok {
			t.Fatalf("detailJSON(%q) = %T, 문자열(JSON) 기대", s, v)
		}
		if !json.Valid([]byte(str)) {
			t.Fatalf("detailJSON(%q) = %q — 유효 JSON 아님(JSON 컬럼 INSERT 거부됨)", s, str)
		}
		// 왕복: JSON 문자열을 역직렬화하면 원본과 같아야 한다(손실 없음).
		var back string
		if err := json.Unmarshal([]byte(str), &back); err != nil {
			t.Fatalf("detailJSON(%q) 역직렬화 실패: %v", s, err)
		}
		if back != s {
			t.Fatalf("왕복 불일치: 원본 %q != 복원 %q", s, back)
		}
	}
}

// 리뷰 P3(수용된 동작): 비 UTF-8 바이트가 섞인 detail(실행기 원시 stdout/stderr)도 INSERT를
// 깨서는 안 된다 — json.Marshal이 U+FFFD로 치환해 유효 JSON을 만든다(바이트 무손실은 아니지만
// P1의 핵심인 INSERT 안전은 지킨다). 무손실 왕복은 이 입력에 요구하지 않는다(주석 계약).
func TestDetailJSONNonUTF8StaysValidJSON(t *testing.T) {
	bad := "dispatch: 실패\xff\xfe raw bytes"
	v := detailJSON(bad)
	str, ok := v.(string)
	if !ok {
		t.Fatalf("detailJSON(비UTF8) = %T, 문자열(JSON) 기대", v)
	}
	if !json.Valid([]byte(str)) {
		t.Fatalf("detailJSON(비UTF8) = %q — 유효 JSON 아님(INSERT 거부됨)", str)
	}
}
